# pyfuzzer

## Light weight Python fuzzer

Lightweight OpenAPI parser that turns API specs into ready-to-use example requests. I kept it dependency-light and extensible, adding logic to resolve $refs and generate example payloads from JSON Schema. This gave testers a simple foundation for fuzzing APIs without heavy tooling.


python lightweight_apifuzzer_parser.py --spec openapi.yaml --sample-requests out.jsonl
Options:
--spec: path to JSON/YAML spec or raw JSON string.
--base-url: prefix for example request URLs.
--sample-requests: write generated requests to a JSONL file.
--dump-endpoints: write parsed endpoint metadata to JSON.
