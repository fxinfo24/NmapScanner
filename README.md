# NmapScanner

# Nmap Automation Script

## Overview
This script is designed to automate Nmap scans with a variety of customizable options to suit different use cases. It simplifies the process of running Nmap commands by providing a user-friendly interface and predefined arguments for common scanning scenarios.

## Features
- Supports multiple scan types, including TCP, UDP, and aggressive scans.
- Allows specification of custom port ranges and target IPs.
- Includes advanced Nmap arguments for vulnerability detection, service version detection, and more.
- Saves scan results in multiple formats (normal, XML, grepable).
- Provides timing control for stealth or speed optimization.
- Supports custom NSE scripts for specialized tasks.

## Requirements
- Python 3.x
- Nmap installed on the system
- Required Python libraries (install via `pip install -r nmap-requirements.txt`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/fxinfo24/NmapScanner.git
   cd NmapScanner
   ```
Install dependencies:
```bash

pip install -r nmap-requirements.txt
```
Ensure Nmap is installed on your system. You can install it using your package manager:
On Debian/Ubuntu:
```bash


sudo apt-get install nmap
On macOS:
bash
brew install nmap
```
On Windows, download and install Nmap from nmap.org.
Usage
Run the script with the following command:

```bash


python NmapScanner.py [options]
```

Example Commands
Comprehensive scan:
```bash

python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s comprehensive
```

Stealth scan:
```bash

python NmapScanner.py -t 192.168.1.1 -p 80,443 -s stealth
```

Aggressive scan with vulnerability detection:
bash


python NmapScanner.py -t 192.168.1.1 -p 1-1000 -s aggressive --vulners
License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

Contact
For any issues or feature requests, please open an issue on GitHub or contact the maintainer at [fxinfo24@gmail.com].

User Guide for Nmap Automation Script
Introduction
This guide provides detailed instructions on how to use the Nmap automation script effectively. The script is designed to simplify the process of running Nmap scans by offering predefined options and arguments for various use cases.

Prerequisites
Ensure Python 3.x is installed on your system.
Install Nmap on your system.
Install the required Python libraries using:
```bash

pip install -r nmap-requirements.txt
```

Command-Line Arguments
The script supports the following arguments:

Argument	Description
-t or --target	Specify the target IP address or hostname.
-p or --ports	Specify the port range to scan (e.g., 1-65535 or 80,443).
-s or --scan	Specify the scan type (stealth, udp, aggressive, comprehensive).
--vulners	Enable vulnerability detection using the vulners NSE script.
--output	Specify the output format (normal, xml, grepable).
-T or --timing	Set the timing template (T0 to T5, where T4 is fast and T3 is safe).
Scan Types
Stealth Scan (-s stealth): Uses the -sS argument in Nmap. Avoids completing the TCP handshake, making it less likely to be detected by firewalls.

```bash

python NmapScanner.py -t 192.168.1.1 -p 80,443 -s stealth
```

UDP Scan (-s udp): Uses the -sU argument in Nmap. Scans for services running on UDP ports.

```bash

python NmapScanner.py -t 192.168.1.1 -p 53,161 -s udp
```

Aggressive Scan (-s aggressive): Combines OS detection, version detection, script scanning, and traceroute. Uses the -A argument in Nmap.

```bash

python NmapScanner.py -t 192.168.1.1 -p  1-1000 -s aggressive
```

Comprehensive Scan (-s comprehensive): Combines multiple scan types for a detailed analysis. Includes -sS, -sU, -A, and --script=vulners.

```bash


python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s comprehensive
Output Options
The script supports saving scan results in the following formats:

Normal (-oN): Human-readable format.
XML (-oX): Machine-readable format for further processing.
Grepable (-oG): Useful for parsing with other tools.
Example:

bash

python NmapScanner.py -t 192.168.1.1 -p 1-1000 -s aggressive --output xml
```
Advanced Usage
Custom NSE Scripts
You can specify custom NSE scripts for specialized tasks. For example:

Firewall detection:
```bash


python NmapScanner.py -t 192.168.1.1 --script http-waf-detect
```

Brute force attack:
```bash

python NmapScanner.py -t 192.168.1.1 --script ftp-brute
```

Timing Control
Adjust the speed of the scan using the -T argument:

T0: Paranoid (very slow, highly stealthy).
T4: Aggressive (fast, less stealthy).
Example:

```bash

python NmapScanner.py -t 192.168.1.1 -p 1-1000 -s stealth -T4
```

## Troubleshooting
Permission Denied: Run the script with elevated privileges (e.g., sudo on Linux).
Nmap Not Found: Ensure Nmap is installed and added to your system's PATH.
FAQ
Can I scan multiple targets? Yes, specify multiple targets separated by commas (e.g., 192.168.1.1,192.168.1.2).
How do I scan all ports? Use the -p 1-65535 argument.
Is this script safe to use? The script is a tool for legitimate security assessments. Ensure you have permission to scan the target systems.
Support
For further assistance, please contact [fxinfo24@gmail.com].

## Comprehensive list of Nmap automation script commands

 Below is a comprehensive list of Nmap automation script commands covering various use cases, compiled and analyzed from the gathered information. These commands are categorized based on their purpose and functionality to ensure clarity and usability.

### **1. Basic Scans**
1. **Quick SYN Scan**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn
   ```
   - Performs a stealthy SYN scan on the first 1024 ports for quick reconnaissance.

2. **Full Port Scan**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s syn
   ```
   - Scans all 65,535 ports using a SYN scan for a complete overview of open ports.

3. **UDP Scan**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 53,161 -s udp
   ```
   - Scans UDP ports 53 (DNS) and 161 (SNMP) to identify UDP services.

---

### **2. Comprehensive Scans**
4. **Comprehensive Scan on All Ports**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s comprehensive
   ```
   - Combines SYN scan, service/version detection, OS detection, and script scanning for a detailed analysis.

5. **Comprehensive Scan on Specific Ports**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 80,443 -s comprehensive
   ```
   - Focuses on web service ports (HTTP and HTTPS) for a detailed analysis.

---

### **3. Vulnerability Scans**
6. **Vulnerability Scan on Common Ports**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s vulnerability
   ```
   - Uses the `vulners` script to detect known vulnerabilities on the first 1024 ports.

7. **Vulnerability Scan on All Ports**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s vulnerability
   ```
   - Scans all ports for vulnerabilities using the `vulners` script.

---

### **4. Targeted Scans**
8. **Web Server Scan**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 80,443 -s syn
   ```
   - Focuses on HTTP and HTTPS ports to identify web services.

9. **Database Server Scan**:
   ```bash
   python NmapScanner.py -t 192.168.1.1 -p 3306,5432 -s syn
   ```
   - Scans MySQL (3306) and PostgreSQL (5432) ports to identify database services.

10. **Email Server Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 25,110,143 -s syn
    ```
    - Scans SMTP (25), POP3 (110), and IMAP (143) ports to identify email services.

---

### **5. Performance-Optimized Scans**
11. **Fast Scan on Top 100 Ports**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-100 -s syn
    ```
    - Scans the top 100 ports for a quick overview of open services.

12. **Aggressive Timing Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -T4
    ```
    - Uses the `-T4` timing template for faster scanning on the first 1024 ports.

---

### **6. Firewall/IDS Evasion Scans**
13. **Fragmented Packet Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --mtu 16
    ```
    - Uses fragmented packets to evade firewalls and IDS.

14. **Decoy Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -D RND:10
    ```
    - Uses 10 random decoys to mask the source of the scan.

15. **Idle Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -sI 192.168.1.2
    ```
    - Uses a zombie host (192.168.1.2) to perform an idle scan.

---

### **7. Output Management**
16. **Save Results in All Formats**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -oA scan_results
    ```
    - Saves scan results in normal, XML, and grepable formats.

17. **Save Results in XML Format**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -oX scan_results.xml
    ```
    - Saves scan results in XML format for programmatic analysis.

---

### **8. Advanced Scans**
18. **Custom NSE Script Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 80 -s syn --script http-waf-detect
    ```
    - Uses the `http-waf-detect` script to identify web application firewalls.

19. **Service Version Detection**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -sV
    ```
    - Detects the versions of services running on open ports.

20. **OS Detection**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -O
    ```
    - Identifies the operating system of the target.

---

### **9. Network Discovery**
21. **Ping Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -sn
    ```
    - Performs a ping scan to identify live hosts without scanning ports.

22. **Subnet Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.0/24 -p 1-1024 -s syn
    ```
    - Scans all hosts in the subnet 192.168.1.0/24.

---

### **10. Specialized Scans**
23. **IoT Device Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 80,443,8080 -s syn
    ```
    - Focuses on ports commonly used by IoT devices.

24. **VoIP Server Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 5060,5061 -s syn
    ```
    - Scans SIP ports (5060 and 5061) to identify VoIP servers.

25. **Custom Port Range Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1000-2000 -s syn
    ```
    - Scans a custom range of ports (1000-2000).

---

### **11. Timing and Rate Control**
26. **Slow Stealthy Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -T0
    ```
    - Uses the `-T0` timing template for a slow and stealthy scan.

27. **Rate-Limited Scan**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --min-rate 10
    ```
    - Limits the scan to a minimum rate of 10 packets per second.

---

### **12. Miscellaneous**
28. **Scan with Custom Source Port**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --source-port 53
    ```
    - Uses port 53 as the source port to bypass firewalls.

29. **Scan with Bad Checksums**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --badsum
    ```
    - Sends packets with bad checksums to detect firewalls or IDS.

30. **Scan with Randomized Ports**:
    ```bash
    python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --randomize-hosts
    ```
    - Randomizes the order of scanned ports to evade detection"""

Let me know if you need further refinements or additional details!