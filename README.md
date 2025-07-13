# 🔎 Machine Analysis

**Machine Analysis** is a Python-based reconnaissance tool designed for basic OS fingerprinting and network scanning using `ping` and `nmap`. It works with both IP addresses and hostnames, providing insights into the target system's OS (based on TTL) and listing open TCP ports with associated services.

> ⚠️ **Note:** This project is a work in progress. Future releases will include vulnerability detection using `searchsploit` and extended scanning features.

---

## 🚀 Features

- 📡 **Hostname Resolution** – Automatically converts domain names into IP addresses.
- 🧠 **Operating System Detection** – Uses TTL values from ping replies to infer the operating system.
- 🔍 **Nmap Integration** – Runs stealth SYN scans with OS and service detection.
- 🔐 **Open Port Extraction** – Lists open TCP ports along with detected services.
- 🧰 **Input Validation** – Accepts and validates both domain names and IP addresses.
- ⚠️ **Optional Vulnerability Check** – Uses `searchsploit` to find known vulnerabilities for discovered services.

---

## 🛠️ Requirements

- Python 3.6 or higher
- [Nmap](https://nmap.org/) installed and available via the command line
- [SearchSploit](https://github.com/offensive-security/exploitdb) (optional for vulnerability lookup)

---

## 📦 Installation & Usage

```bash
# Clone the repository
git clone https://github.com/xcotelo/machineanalysis.git
cd machineanalysis

# Run the script
python3 MachineAnalysis.py

---

## 💻 Example
[+] Enter the IP address or the hostname: example.com
[+] Resolved example.com → 93.184.216.34
[+] Connecting to 93.184.216.34
[+] Detected OS (by TTL 56): Linux/Unix/macOS

More details? (y/n): y
[*] Scanning 93.184.216.34 (this may take a while)...
[+] Open ports and service versions:
80/tcp   open  http   Apache httpd 2.4.41
443/tcp  open  https  OpenSSL 1.1.1f

=== Vulnerabilities for Apache 2.4.41 ===
...
