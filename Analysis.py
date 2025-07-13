import subprocess
import re

def detect_os_by_ttl(ttl):
    ttl = int(ttl)
    if 120 <= ttl <= 128:
        return "Windows"
    elif 60 <= ttl <= 64:
        return "Linux/Unix"
    elif ttl >= 250:
        return "Solaris/AIX"
    
def extract_port_info(output):
    port_lines = []
    for line in output.split('\n'):
        if re.match(r'^\d+/tcp\s+open\s+\w+', line):
            port_lines.append(line)
    return '\n'.join(port_lines)
    
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
                continue             

            more = input("\nMore details? (y/n): ").strip().lower()
            if more in ['y', 'yes']:
                print(f"[+] Scanning {ip_target} (this may take a while)...")
                nmap = subprocess.run(f"nmap -sS -O --open -sV {ip_target}", shell=True, capture_output=True, text=True)
                port_info = extract_port_info(nmap.stdout)
                print("\n[+] Open ports and service versions:")
                print(port_info)
                break
            else:
                print("[-] No open ports found or scan failed.")   
                continue 
            
        except subprocess.TimeoutExpired:
            print(f"Timeout {ip_target}")
            return False
        except Exception as e:
            print(f"Error {str(e)}")
            return False
    

def validate_ip(ip):
    if not ip or any(char.isspace() for char in ip):
        return False
    
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def main():
    print("<<< MACHINE ANALYSIS >>>")
    while True:
        try:
            ip = input("\nEnter the IP or press 'q' to quit: ").strip()

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