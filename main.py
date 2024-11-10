import socket
import argparse
import threading
from datetime import datetime
import subprocess

# Argument parsing for IP input, including the verbose flag
parser = argparse.ArgumentParser(description="Simple Python Port Scanner with Verbose Option")
parser.add_argument("target", help="Target IP address to scan")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
args = parser.parse_args()
target = args.target
verbose = args.verbose  # Store verbose flag

# Define port range to scan all the way up to 65535
start_port = 1
end_port = 65535  # Change this to 65535 to scan all possible ports

# Path to the wordlist for Gobuster
wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

# Lists to store open TCP ports and HTTP service ports
open_tcp_ports = []
http_ports = []

# Define number of threads to limit concurrency
max_threads = 50
thread_lock = threading.Lock()

def print_banner():
    """Prints the start banner."""
    print("-" * 60)
    print(f"Starting scan on target: {target}")
    print("Scanning started at:", datetime.now())
    print("-" * 60)
    if verbose:
        print("Verbose mode enabled: Detailed output will be shown.")

def scan_port(port):
    """Function to scan a single port."""
    try:
        # Create a socket object
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(1)  # Timeout for 1 second
        result = tcp_socket.connect_ex((target, port))
        
        # Check if the port is open
        if result == 0:
            with thread_lock:
                open_tcp_ports.append(port)
                if port in [80, 8080, 443]:  # Common HTTP ports
                    http_ports.append(port)
            if verbose:
                print(f"Port {port} is open.")  # Print open ports only in verbose mode
        tcp_socket.close()
    except socket.error as e:
        # Handle socket errors
        if verbose:
            print(f"Error scanning port {port}: {e}")

def scan_tcp_ports():
    """Scan TCP ports with threading."""
    print("\nScanning for open TCP ports...")
    
    # Create threads for scanning ports
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        thread.start()
        threads.append(thread)
        
        # Control number of threads running concurrently
        if len(threads) >= max_threads:
            for t in threads:
                t.join()  # Wait for threads to finish
            threads = []  # Reset threads list
    
    # Wait for any remaining threads
    for t in threads:
        t.join()

def display_results():
    """Display the scan results."""
    print("-" * 60)
    print(f"Scanning completed at: {datetime.now()}")
    print("-" * 60)
    
    print("\nOpen TCP Ports:")
    if open_tcp_ports:
        print(", ".join(str(port) for port in open_tcp_ports))
    else:
        print("No open TCP ports found.")
    
    print("\nHTTP Services Detected on Ports:")
    if http_ports:
        print(", ".join(str(port) for port in http_ports))
    else:
        print("No HTTP services detected.")
    print("-" * 60)

def run_gobuster(target_ip, port=80, wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"):
    """Run Gobuster on the target IP with a specified port."""
    # Ensure port is valid, if None is provided, default to 80
    if port is None:
        port = 80

    url = f"http://{target_ip}:{port}"
    print(f"\nRunning Gobuster on {url} with wordlist {wordlist}...")

    # Define the command arguments for Gobuster
    command = [
        "gobuster", "dir", 
        "-u", url, 
        "-w", wordlist, 
        "-t", "10",  # Set the number of threads to 10
        "-timeout", "30s"  # Corrected timeout flag to -timeout
    ]

    # Print the command to debug
    print(f"Executing command: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Print the results of Gobuster's scan
        print("\nGobuster Results:")
        if result.stdout:
            print(result.stdout)
        else:
            print("No output received. Possible network issues or no directories found.")
        
        if result.stderr:
            print("\nGobuster Errors (if any):")
            print(result.stderr)
    
    except subprocess.CalledProcessError as e:
        # Gobuster returned a non-zero exit status
        print("Gobuster encountered an error:")
        print(e.stderr)  # Error output from Gobuster
    
    except FileNotFoundError:
        # Gobuster binary not found
        print("Gobuster is not installed or could not be found. Please install Gobuster and try again.")
    
    except Exception as e:
        # Catch any other unforeseen errors
        print(f"An unexpected error occurred: {e}")

def main():
    """Main function to run all steps."""
    print_banner()
    
    # Run port scan
    scan_tcp_ports()
    
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
