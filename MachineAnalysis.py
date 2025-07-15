import subprocess
import re
import socket
from colorama import Fore, Style, init

init(autoreset=True)

def detect_os_by_ttl(ttl):
    ttl = int(ttl)
    if 120 <= ttl <= 128:
        return f"{Fore.GREEN}Windows{Style.RESET_ALL}"
    elif 60 <= ttl <= 64:
        return f"{Fore.GREEN}Linux/Unix/macOS{Style.RESET_ALL}"
    elif ttl >= 250:
        return f"{Fore.GREEN}Solaris/AIX/Router Cisco{Style.RESET_ALL}"
    elif 30 <= ttl <= 60:
        return f"{Fore.GREEN}IoT or legacy system (e.g. HP-UX){Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}Unknown OS (TTL: {ttl}){Style.RESET_ALL}"

def extract_port_info(output):
    port_lines = []
    for line in output.split('\n'):
        if re.match(r'^\d+/tcp\s+open\s+\w+', line):
            port_lines.append(f"{Fore.BLUE}{line}{Style.RESET_ALL}")
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
        return f"{Fore.YELLOW}[-] No services found for vulnerability search.{Style.RESET_ALL}"

    for service_info in matches:
        search_term = normalize_service_name(service_info)
        result = subprocess.run(f"searchsploit {search_term}", shell=True, capture_output=True, text=True)

        if result.stdout.strip():
            results.append(f"\n{Fore.RED}=== Vulnerabilities for {search_term} ===\n{Style.RESET_ALL}{result.stdout.strip()}")
        else:
            results.append(f"\n{Fore.GREEN}=== No known vulnerabilities found for {search_term} ==={Style.RESET_ALL}")

    return '\n'.join(results)

def save(output, filename_hint="results"):
    save = input(f"{Fore.YELLOW}\nDo you want to save the results? (y/n): {Style.RESET_ALL}").strip().lower()
    if save in ['y', 'yes']:
        filename = f"{filename_hint}.txt"
        with open(filename, 'w') as f:
            f.write(output)
        print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")
    else:
        return

def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        print(f"{Fore.GREEN}[+] Resolved {hostname} → {ip}{Style.RESET_ALL}")
        return ip
    except socket.gaierror:
        print(f"{Fore.RED}[-] Could not resolve {hostname}{Style.RESET_ALL}")
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
            print(f"{Fore.YELLOW}[+] Connecting to {ip_target}{Style.RESET_ALL}")
            resultado = subprocess.run(f"ping -c 1 {ip_target}", shell=True, capture_output=True, text=True)
            ttl_match = re.search(r"ttl=(\d+)", resultado.stdout.lower())
            if ttl_match:
                ttl = ttl_match.group(1)
                so = detect_os_by_ttl(ttl)
                print(f"{Fore.GREEN}[+] Detected OS (by TTL {ttl}): {so}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Could not determine TTL from ping response.{Style.RESET_ALL}")
                break

            more = input(f"\n{Fore.YELLOW}More details? (y/n): {Style.RESET_ALL}").strip().lower()
            if more in ['y', 'yes']:
                print(f"{Fore.YELLOW}[*] Scanning {ip_target} (this may take a while)...{Style.RESET_ALL}")
                nmap = subprocess.run(f"nmap -sS -O --open -sV {ip_target}", shell=True, capture_output=True, text=True)
                
                port_info = extract_port_info(nmap.stdout)
                print(f"{Fore.GREEN}[+] Open ports and service versions:{Style.RESET_ALL}")
                print(port_info)
                save(port_info, filename_hint="open_ports")

                print(f"{Fore.MAGENTA}[+] List of vulnerabilities:{Style.RESET_ALL}")
                vuln_info = vulnerabilities(nmap.stdout)
                print(vuln_info)
                save(vuln_info, filename_hint="vulnerabilities")
                break
            else:
                print(f"{Fore.GREEN}[-] No open ports found or scan skipped.{Style.RESET_ALL}")
                break

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}Timeout {ip_target}{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}Error {str(e)}{Style.RESET_ALL}")
            return False

def main():
    print(fr"""{Fore.LIGHTBLUE_EX}
  __  __          _____ _    _ _____ _   _ ______            _   _          _  __     _______  _____ _____  _____ 
 |  \/  |   /\   / ____| |  | |_   _| \ | |  ____|     /\   | \ | |   /\   | | \ \   / /_   _|/ ____|_   _|/ ____|
 | \  / |  /  \ | |    | |__| | | | |  \| | |__       /  \  |  \| |  /  \  | |  \ \_/ /  | | | (___   | | | (___  
 | |\/| | / /\ \| |    |  __  | | | | . ` |  __|     / /\ \ | . ` | / /\ \ | |   \   /   | |  \___ \  | |  \___ \ 
 | |  | |/ ____ \ |____| |  | |_| |_| |\  | |____   / ____ \| |\  |/ ____ \| |____| |   _| |_ ____) |_| |_ ____) |
 |_|  |_/_/    \_\_____|_|  |_|_____|_| \_|______| /_/    \_\_| \_/_/    \_\______|_|  |_____|_____/|_____|_____/ 
                                                                                                      
{Style.RESET_ALL}by: {Fore.RED}xcotelo{Style.RESET_ALL}""")

    while True:
        try:
            ip = input(f"\n{Fore.YELLOW}[+] Enter the IP address or the hostname or press 'q' to quit: {Style.RESET_ALL}").strip()

            if ip.lower() in ['q', 'quit', 'exit']:
                print(f"\n{Fore.RED}Quitting...{Style.RESET_ALL}")
                break

            if not validate_ip(ip):
                print(f"{Fore.RED}Error. Try again.{Style.RESET_ALL}")
                continue

            system(ip)

        except Exception as e:
            print(f"\n{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
