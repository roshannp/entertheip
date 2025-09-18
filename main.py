"""
lightweight_apifuzzing parser

What it does
- Load an OpenAPI v3 spec (dict or file.
- Extract endpoints, methods, path/query/header params, and requestBody schema.
- Produce a simple example payload (json-friendly) from common JSON Schema types.
- Keep dependencies to stdlib + pyyaml (optional)

How to use
- From Python: import parse_openapi, then iterate endpoints and call example_payload(endpoint)
- CLI: `python lightweight_apifuzzer_parser.py --spec openapi.yaml --sample-requests out.jsonl`

Limitations
- Minimal $ref resolver that works for local refs only (#/components/...).
- Doesn't implement all JSON Schema keywords (oneOf/allOf/anyOf have simple heuristics).
- Intended as a small, easily extensible building block for a fuzzer.
"""
from __future__ import annotations
import json
import argparse
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple, Union
import re

try:
    import yaml
except Exception:
    yaml = None


@dataclass
class Parameter:
    name: str
    in_: str
    required: bool
    schema: Dict[str, Any]


@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: Optional[str]
    params: List[Parameter]
    request_body_schema: Optional[Dict[str, Any]]
    responses: Dict[str, Any]


# ----------------- spec loading / resolving -----------------

def load_spec(path_or_dict: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(path_or_dict, dict):
        return path_or_dict
    if isinstance(path_or_dict, str):
        if path_or_dict.strip().startswith("{"):
            return json.loads(path_or_dict)
        if yaml is None and path_or_dict.endswith(('.yml', '.yaml')):
            raise RuntimeError('pyyaml required to read YAML files; `pip install pyyaml`')
        with open(path_or_dict, 'r', encoding='utf-8') as f:
            txt = f.read()
        if path_or_dict.endswith(('.yml', '.yaml')):
            return yaml.safe_load(txt)
        return json.loads(txt)
    raise TypeError('spec must be a dict or path string')


def resolve_ref(spec: Dict[str, Any], ref: str) -> Any:
    # supports local refs like #/components/schemas/Pet
    if not ref.startswith('#/'):
        raise NotImplementedError('Only local refs supported in this lightweight parser')
    parts = ref.lstrip('#/').split('/')
    cur = spec
    for p in parts:
        if p not in cur:
            raise KeyError(f'ref path missing: {ref} (failed at {p})')
        cur = cur[p]
    return cur


# ----------------- schema -> example/template -----------------

PRIMITIVE_DEFAULTS = {
    'string': 'string',
    'integer': 0,
    'number': 0.0,
    'boolean': True,
}


def schema_to_example(schema: Dict[str, Any], spec: Dict[str, Any], depth=0) -> Any:
    """
    Convert a small subset of JSON Schema (as used by OpenAPI) into an example value.
    Heuristics only: arrays produce one example item; object properties use required fields first.
    """
    if depth > 6:
        return None

    if not schema:
        return None

    if '$ref' in schema:
        resolved = resolve_ref(spec, schema['$ref'])
        return schema_to_example(resolved, spec, depth + 1)

    typ = schema.get('type')
    if not typ:
        # try to infer
        if 'properties' in schema:
            typ = 'object'
        elif 'enum' in schema:
            typ = 'string'

    if 'enum' in schema:
        # return first enum value
        enum = schema.get('enum', [])
        if enum:
            return enum[0]

    if typ == 'object':
        props = schema.get('properties', {})
        required = set(schema.get('required', []))
        out = {}
        # include required fields first
        for name in list(required) + [n for n in props.keys() if n not in required]:
            if name not in props:
                continue
            out[name] = schema_to_example(props[name], spec, depth + 1)
        return out

    if typ == 'array':
        items = schema.get('items') or {}
        return [schema_to_example(items, spec, depth + 1)]

    if typ in PRIMITIVE_DEFAULTS:
        fmt = schema.get('format')
        if typ == 'string' and fmt == 'email':
            return 'user@example.com'
        if typ == 'string' and fmt == 'uuid':
            return '00000000-0000-0000-0000-000000000000'
        if 'example' in schema:
            return schema['example']
        if 'default' in schema:
            return schema['default']
        return PRIMITIVE_DEFAULTS[typ]

    # fallback: try oneOf/anyOf/allOf
    if 'oneOf' in schema:
        return schema_to_example(schema['oneOf'][0], spec, depth + 1)
    if 'anyOf' in schema:
        return schema_to_example(schema['anyOf'][0], spec, depth + 1)
    if 'allOf' in schema:
        # merge simply
        merged = {}
        for s in schema['allOf']:
            if '$ref' in s:
                s = resolve_ref(spec, s['$ref'])
            if 'properties' in s:
                merged.setdefault('properties', {}).update(s.get('properties', {}))
            if 'required' in s:
                merged.setdefault('required', []).extend(s.get('required', []))
        return schema_to_example(merged, spec, depth + 1)

    return None


# ----------------- parse OpenAPI -----------------

def extract_request_body_schema(request_body: Dict[str, Any], spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not request_body:
        return None
    # prefer application/json
    content = request_body.get('content', {})
    if 'application/json' in content:
        schema = content['application/json'].get('schema')
        if schema:
            return schema
    # pick first
    for ctype, obj in content.items():
        if 'schema' in obj:
            return obj['schema']
    return None


def parse_openapi(spec: Dict[str, Any]) -> List[Endpoint]:
    paths = spec.get('paths', {})
    endpoints: List[Endpoint] = []
    for path, path_item in paths.items():
        for method in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'):
            if method not in path_item:
                continue
            op = path_item[method]
            params_raw = []
            # parameters can be defined on path level and operation level
            params_agg = []
            if 'parameters' in path_item:
                params_agg.extend(path_item['parameters'] or [])
            if 'parameters' in op:
                params_agg.extend(op['parameters'] or [])
            for p in params_agg:
                if '$ref' in p:
                    p = resolve_ref(spec, p['$ref'])
                schema = p.get('schema', {})
                params_raw.append(Parameter(name=p['name'], in_=p['in'], required=p.get('required', False), schema=schema))

            rb_schema = None
            if 'requestBody' in op:
                rb_schema = extract_request_body_schema(op['requestBody'], spec)
                if rb_schema and '$ref' in rb_schema:
                    rb_schema = resolve_ref(spec, rb_schema['$ref'])

            responses = op.get('responses', {})
            endpoints.append(Endpoint(method=method.upper(), path=path, operation_id=op.get('operationId'), params=params_raw, request_body_schema=rb_schema, responses=responses))
    return endpoints


# ----------------- utility: render example request -----------------

def build_example_request(base_url: str, ep: Endpoint, spec: Dict[str, Any]) -> Dict[str, Any]:
    url = base_url.rstrip('/') + ep.path
    path_params = {p.name: schema_to_example(p.schema, spec) for p in ep.params if p.in_ == 'path'}
    # substitute path params
    for k, v in path_params.items():
        placeholder = '{' + k + '}'
        if placeholder in url:
            url = url.replace(placeholder, str(v))
        else:
            # some specs use :param style? just append
            pass

    query_params = {p.name: schema_to_example(p.schema, spec) for p in ep.params if p.in_ == 'query'}
    headers = {p.name: schema_to_example(p.schema, spec) for p in ep.params if p.in_ == 'header'}

    body = None
    if ep.request_body_schema:
        body = schema_to_example(ep.request_body_schema, spec)

    return {
        'method': ep.method,
        'url': url,
        'query': query_params,
        'headers': headers,
        'body': body,
    }


# ----------------- CLI -----------------

def main(argv: Optional[List[str]] = None):
    p = argparse.ArgumentParser(description='Lightweight OpenAPI parser for APIFuzzing')
    p.add_argument('--spec', required=True, help='OpenAPI spec file (json or yaml) or raw JSON string')
    p.add_argument('--base-url', default='http://localhost:8000', help='Base URL to render example requests')
    p.add_argument('--sample-requests', help='Write example requests as JSONL')
    p.add_argument('--dump-endpoints', help='Print parsed endpoints as JSON')
    args = p.parse_args(argv)

    spec = load_spec(args.spec)
    endpoints = parse_openapi(spec)

    if args.dump_endpoints:
        serial = [
            {
                'method': e.method,
                'path': e.path,
                'operation_id': e.operation_id,
                'params': [asdict(p) for p in e.params],
                'has_request_body': bool(e.request_body_schema),
            }
            for e in endpoints
        ]
        with open(args.dump_endpoints, 'w', encoding='utf-8') as f:
            json.dump(serial, f, indent=2)
        print('wrote', args.dump_endpoints)

    if args.sample_requests:
        with open(args.sample_requests, 'w', encoding='utf-8') as out:
            for e in endpoints:
                req = build_example_request(args.base_url, e, spec)
                out.write(json.dumps(req) + '\n')
        print('wrote', args.sample_requests)

    if not args.sample_requests and not args.dump_endpoints:
        # print a quick summary
        for e in endpoints:
            print(f"{e.method} {e.path}  body={'yes' if e.request_body_schema else 'no'} params={len(e.params)}")


if __name__ == '__main__':
    main()
