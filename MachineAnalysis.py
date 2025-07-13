import subprocess
import re
import socket

def detect_os_by_ttl(ttl):
    ttl = int(ttl)
    if 120 <= ttl <= 128:
        return "Windows"
    elif 60 <= ttl <= 64:
        return "Linux/Unix/macOS"
    elif ttl >= 250:
        return "Solaris/AIX/Router Cisco"
    elif 30 <= ttl <= 60:
        return "IoT device or legacy system (for example, HP-UX)"
    else:
        return f"Error, could not determinate the system (TTL: {ttl})"


def extract_port_info(output):
    port_lines = []
    for line in output.split('\n'):
        if re.match(r'^\d+/tcp\s+open\s+\w+', line):
            port_lines.append(line)
    return '\n'.join(port_lines)

def normalize_service_name(service_info):
    service_info = service_info.split('(')[0].strip() 
    parts = service_info.split()
    
    if 'OpenSSH' in service_info:
        version = parts[1].split('p')[0]  
        return f"OpenSSH {version}"
    
    if 'MariaDB' in service_info or 'MySQL' in service_info:
        version = parts[1].split('-')[-1]
        return f"MariaDB {version}"
    
    return ' '.join(parts[:3])

def vulnerabilities(output):
    results = []

    pattern = re.compile(r'^\d+/tcp\s+open\s+\S+\s+(.+)', re.MULTILINE)
    matches = pattern.findall(output)

    if not matches:
        return "[-] No services found for vulnerability search."

    for service_info in matches:
        search_term = normalize_service_name(service_info)
        result = subprocess.run(f"searchsploit {search_term}", shell=True, capture_output=True, text=True)

        if result.stdout.strip():
            results.append(f"\n=== Vulnerabilities for {search_term} ===\n{result.stdout.strip()}")
        else:
            results.append(f"\n=== No known vulnerabilities found for {search_term} ===")

    return '\n'.join(results)
    
def system(ip_target):
    while True: 
        try:
            print(f"[+] Connecting to {ip_target}")
            resultado = subprocess.run(f"ping -c 1 {ip_target}", shell=True, capture_output=True, text=True)
            ttl_match = re.search(r"ttl=(\d+)", resultado.stdout.lower())
            if ttl_match:
                ttl = ttl_match.group(1)
                so = detect_os_by_ttl(ttl)
                print(f"[+] Detected OS (by TTL {ttl}): {so}")
            else:
                print("[-] Could not determine TTL from ping response.")   
                break             

            more = input("\nMore details? (y/n): ").strip().lower()
            if more in ['y', 'yes']:
                print(f"[*] Scanning {ip_target} (this may take a while)...")
                nmap = subprocess.run(f"nmap -sS -O --open -sV {ip_target}", shell=True, capture_output=True, text=True)
                port_info = extract_port_info(nmap.stdout)
                print("[+] Open ports and service versions:")
                print(port_info)
                vuln_info = vulnerabilities(nmap.stdout)
                print(vuln_info)
                break
            else:
                print("[-] No open ports found or scan failed.")   
                break 
            
        except subprocess.TimeoutExpired:
            print(f"Timeout {ip_target}")
            return False
        except Exception as e:
            print(f"Error {str(e)}")
            return False
    

def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        print(f"[+] Resolved {hostname} → {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] Could not resolve {hostname}")
        return False
    
def validate_ip(ip):
    if resolve_hostname(ip):
        return ip
    
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def main():
    print(r"""
  __  __          _____ _    _ _____ _   _ ______            _   _          _  __     _______  _____ _____  _____ 
 |  \/  |   /\   / ____| |  | |_   _| \ | |  ____|     /\   | \ | |   /\   | | \ \   / /_   _|/ ____|_   _|/ ____|
 | \  / |  /  \ | |    | |__| | | | |  \| | |__       /  \  |  \| |  /  \  | |  \ \_/ /  | | | (___   | | | (___  
 | |\/| | / /\ \| |    |  __  | | | | . ` |  __|     / /\ \ | . ` | / /\ \ | |   \   /   | |  \___ \  | |  \___ \ 
 | |  | |/ ____ \ |____| |  | |_| |_| |\  | |____   / ____ \| |\  |/ ____ \| |____| |   _| |_ ____) |_| |_ ____) |
 |_|  |_/_/    \_\_____|_|  |_|_____|_| \_|______| /_/    \_\_| \_/_/    \_\______|_|  |_____|_____/|_____|_____/ 
                                                                                                                                                                                                                  
    """)
    while True:
        try:
            ip = input("\n[+] Enter the IP address or the hostname: ").strip()

            if ip.lower() in ['q', 'quit', 'exit']:
                print("\nQuitting...")
                break
            
            if not validate_ip(ip):
                print("Error. Try again.")
                continue

            system(ip)

        except Exception as e:
            print(f"\nError inesperado: {str(e)}")

if __name__ == "__main__":
    main()