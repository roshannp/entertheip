import socket
import argparse
from datetime import datetime
import subprocess

# Argument parsing for IP input
parser = argparse.ArgumentParser(description="Python Port Scanner with Gobuster integration")
parser.add_argument("target", help="Target IP address to scan")
args = parser.parse_args()
target = args.target

# Define port range
start_port = 1
end_port = 65535

# Path to the wordlist
wordlist = "/usr/share/wordlists/dirb/directory-list-2.3-small.txt"

# Lists to store open TCP and UDP ports and HTTP service ports
open_tcp_ports = []
open_udp_ports = []
http_ports = []

def print_banner():
    """Prints the start banner."""
    print("-" * 60)
    print(f"Starting scan on target: {target}")
    print("Scanning started at:", datetime.now())
    print("-" * 60)

def scan_tcp_ports():
    """Scans for open TCP ports and identifies potential HTTP services."""
    print("\nScanning for open TCP ports...")
    for port in range(start_port, end_port + 1):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(1)
        result = tcp_socket.connect_ex((target, port))
        if result == 0:
            open_tcp_ports.append(port)
            if port in [80, 8080, 443]:  # Common HTTP ports
                http_ports.append(port)
        tcp_socket.close()

def scan_udp_ports():
    """Scans for open UDP ports."""
    print("\nScanning for open UDP ports...")
    for port in range(start_port, end_port + 1):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(1)
        try:
            udp_socket.sendto(b"", (target, port))
            data, _ = udp_socket.recvfrom(1024)
            open_udp_ports.append(port)
        except socket.timeout:
            continue
        except Exception:
            pass
        udp_socket.close()

def display_results():
    """Displays scanning results for TCP, UDP, and HTTP ports."""
    print("-" * 60)
    print(f"Scanning completed at: {datetime.now()}")
    print("-" * 60)
    print("\nOpen TCP Ports:")
    print(", ".join(str(port) for port in open_tcp_ports) if open_tcp_ports else "No open TCP ports found.")
    
    print("\nOpen UDP Ports:")
    print(", ".join(str(port) for port in open_udp_ports) if open_udp_ports else "No open UDP ports found.")
    
    print("\nHTTP Services Detected on Ports:")
    print(", ".join(str(port) for port in http_ports) if http_ports else "No HTTP services detected.")
    print("-" * 60)

def run_gobuster(target_ip, port=None):
    """Runs Gobuster on the target IP or a specific port."""
    url = f"http://{target_ip}:{port}" if port else f"http://{target_ip}"
    print(f"\nRunning Gobuster on {url} with wordlist {wordlist}...")
    try:
        result = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist],
            capture_output=True,
            text=True,
            check=True
        )
        print("\nGobuster Results:")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Gobuster encountered an error:")
        print(e.output)
    except FileNotFoundError:
        print("Gobuster is not installed or could not be found. Please install Gobuster and try again.")

def main():
    """Main function to run all steps."""
    print_banner()
    
    # Run port scans
    scan_tcp_ports()
    scan_udp_ports()
    
    # Display results
    display_results()
    
    # Run Gobuster on the main IP
    run_gobuster(target)
    
    # Run Gobuster on detected HTTP service ports
    for port in http_ports:
        run_gobuster(target, port)

# Execute main function
if __name__ == "__main__":
    main()
