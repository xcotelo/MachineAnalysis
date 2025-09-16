import subprocess
import re
import socket

# Colors
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
LIGHTBLUE = '\033[94m'
RESET = '\033[0m'

def detect_os_by_ttl(ttl):
    ttl = int(ttl)
    if ttl >= 250:
        return f"{GREEN}Solaris/Cisco/Unix{RESET}"
    elif 120 <= ttl <= 128:
        return f"{GREEN}Windows{RESET}"
    elif 60 <= ttl <= 64:
        return f"{GREEN}Linux/macOS/Red Hat 9{RESET}"
    elif 32 <= ttl <= 59:
        return f"{GREEN}Windows 96/98/NT3.51{RESET}"
    elif 30 <= ttl <= 31:
        return f"{GREEN}IoT or DC-OSx{RESET}"
    else:
        return f"{GREEN}Unknown OS (TTL: {ttl}){RESET}"

def extract_port_info(output):
    port_lines = []
    for line in output.split('\n'):
        if re.match(r'^\d+/tcp\s+open\s+\w+', line):
            port_lines.append(f"{BLUE}{line}{RESET}")
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
        return f"{YELLOW}[-] No services found for vulnerability search.{RESET}"

    for service_info in matches:
        search_term = normalize_service_name(service_info)
        result = subprocess.run(f"searchsploit {search_term}", shell=True, capture_output=True, text=True)

        if result.stdout.strip():
            results.append(f"\n{RED}=== Vulnerabilities for {search_term} ===\n{RESET}{result.stdout.strip()}")
        else:
            results.append(f"\n{GREEN}=== No known vulnerabilities found for {search_term} ==={RESET}")

    return '\n'.join(results)

def save(output, filename_hint="results"):
    save = input(f"{YELLOW}\nDo you want to save the results? (y/n): {RESET}").strip().lower()
    if save in ['y', 'yes']:
        filename = f"{filename_hint}.txt"
        with open(filename, 'w') as f:
            f.write(output)
        print(f"{GREEN}[+] Results saved to {filename}{RESET}")
    else:
        return

def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        print(f"{GREEN}[+] Resolved {hostname} → {ip}{RESET}")
        return ip
    except socket.gaierror:
        print(f"{RED}[-] Could not resolve {hostname}{RESET}")
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

def system(ip_target):
    while True:
        try:
            print(f"{YELLOW}[+] Connecting to {ip_target}{RESET}")
            resultado = subprocess.run(f"ping -c 1 {ip_target}", shell=True, capture_output=True, text=True)
            ttl_match = re.search(r"ttl=(\d+)", resultado.stdout.lower())
            if ttl_match:
                ttl = ttl_match.group(1)
                so = detect_os_by_ttl(ttl)
                print(f"{GREEN}[+] Detected OS (by TTL {ttl}): {so}{RESET}")
            else:
                print(f"{RED}[-] Could not determine TTL from ping response.{RESET}")
                break

            more = input(f"\n{YELLOW}More details? (y/n): {RESET}").strip().lower()
            if more in ['y', 'yes']:
                print(f"{YELLOW}[*] Scanning {ip_target} (this may take a while)...{RESET}")
                nmap = subprocess.run(f"nmap -p- -sS --min-rate 5000 -n -Pn --open -O -sV {ip_target}", shell=True, capture_output=True, text=True)
                
                port_info = extract_port_info(nmap.stdout)
                print(f"{GREEN}[+] Open ports and service versions:{RESET}")
                print(port_info)
                save(port_info, filename_hint="open_ports")

                print(f"{MAGENTA}[+] List of vulnerabilities:{RESET}")
                vuln_info = vulnerabilities(nmap.stdout)
                print(vuln_info)
                save(vuln_info, filename_hint="vulnerabilities")
                break
            else:
                print(f"{GREEN}[-] No open ports found or scan skipped.{RESET}")
                break

        except subprocess.TimeoutExpired:
            print(f"{RED}Timeout {ip_target}{RESET}")
            return False
        except Exception as e:
            print(f"{RED}Error {str(e)}{RESET}")
            return False

def main():
    print(fr"""{LIGHTBLUE}
  __  __          _____ _    _ _____ _   _ ______            _   _          _  __     _______  _____ _____  _____ 
 |  \/  |   /\   / ____| |  | |_   _| \ | |  ____|     /\   | \ | |   /\   | | \ \   / /_   _|/ ____|_   _|/ ____|
 | \  / |  /  \ | |    | |__| | | | |  \| | |__       /  \  |  \| |  /  \  | |  \ \_/ /  | | | (___   | | | (___  
 | |\/| | / /\ \| |    |  __  | | | | . ` |  __|     / /\ \ | . ` | / /\ \ | |   \   /   | |  \___ \  | |  \___ \ 
 | |  | |/ ____ \ |____| |  | |_| |_| |\  | |____   / ____ \| |\  |/ ____ \| |____| |   _| |_ ____) |_| |_ ____) |
 |_|  |_/_/    \_\_____|_|  |_|_____|_| \_|______| /_/    \_\_| \_/_/    \_\______|_|  |_____|_____/|_____|_____/ 
                                                                                                      
{RESET}by: {RED}xcotelo{RESET}""")

    while True:
        try:
            ip = input(f"\n{YELLOW}[+] Enter the IP address or the hostname or press 'q' to quit: {RESET}").strip()

            if ip.lower() in ['q', 'quit', 'exit']:
                print(f"\n{RED}Quitting...{RESET}")
                break

            if not validate_ip(ip):
                print(f"{RED}Error. Try again.{RESET}")
                continue

            system(ip)

        except Exception as e:
            print(f"\n{RED}Unexpected error: {str(e)}{RESET}")

if __name__ == "__main__":
    main()
