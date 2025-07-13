# 🔎 Advanced Network Analyzer (Python-based)

**Advanced Network Analyzer** is a Python tool designed for basic reconnaissance and OS fingerprinting using `ping` and `nmap`. It supports both IP addresses and hostnames, offering insights into the target's TTL-based OS and open TCP ports with detected services.

> ⚠️ **Note:** This project is a work in progress. Features such as vulnerability detection (after Nmap scanning) and extended analysis are planned for future releases.

---

## 🚀 Features

- 📡 **Hostname Resolution** – Converts domain names to IPs automatically.
- 🧠 **Operating System Detection** – Estimates the target OS using the TTL value from a ping response.
- 🔍 **Nmap Integration** – Performs a stealth SYN scan with OS and service detection.
- 🔐 **Open Port Extraction** – Lists open ports and their associated services.
- 🧰 **Validation** – Handles both IP addresses and domain names, including basic validation.

---

## 🛠️ Requirements

- Python 3.6+
- `nmap` must be installed and accessible from the command line.

---

## 📦 Installation

```bash
git clone https://github.com/xcotelo/machineanalysis.git
cd advanced-network-analyzer
python3 analyzer.py
