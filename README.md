# Network Attacks Lab

A hands-on project from my cybersecurity training on network attacks:
how to classify them using an industry-standard framework, how common
attack tools and techniques work, how to intercept traffic in a MITM
scenario, how to detect malicious activity in a packet capture, and how
to search for internet-exposed, vulnerable devices.

## Tasks

### 1. Mapping Incidents to MITRE ATT&CK
Classified eight abstract security incidents (stolen credentials used for
access, a web app exploit followed by malware execution, phishing,
privilege escalation, network reconnaissance, remote code execution,
port scanning, and log/evidence tampering) by MITRE ATT&CK tactic and
technique IDs.
- **Files:** `task_1/my_mitre.txt`

### 2. MongoDB Scanner (Python)
Wrote a multithreaded Python scanner (`scan.py`) that checks a target IP
or CIDR network for MongoDB instances exposed without authentication. It
sends a raw `isMaster` query over the MongoDB wire protocol and reports
any host that responds without requiring credentials.
```
python3 scan.py <network> [--port PORT] [--timeout TIMEOUT]
# e.g. python3 scan.py 192.168.1.0/24
```
- **Files:** `task_2/scan.py`

### 3. MITM Form Interceptor (mitmproxy addon)
Wrote an mitmproxy addon (`interceptor.py`) that detects HTTP POST
requests carrying form data (`application/x-www-form-urlencoded` or
`multipart/form-data`) and logs the submitted fields, timestamp, client
IP and URL, to demonstrate what an attacker could capture in a
man-in-the-middle position if traffic is not encrypted.
```
mitmproxy -s interceptor.py
```
- **Files:** `task_3/interceptor.py`

### 4. Detecting Malicious Activity in a Packet Capture
Analyzed a traffic capture and identified DNS tunneling: a technique
where an attacker sends and receives data by encoding it inside DNS
queries and responses, so it blends in with normal-looking DNS traffic.
- **Detection:** an IDS/IPS (such as Snort or Suricata) with signatures
  for DNS tunneling would catch this kind of activity.
- **Files:** `task_4/solution.txt`
- Note: the original packet capture file is not included in this
  repository, since it is training material, not my own work.

### 5. Finding Vulnerable Devices with Fofa
Used the Fofa search engine to find internet-connected devices
potentially vulnerable to CVE-2017-7529 (an integer overflow in Nginx's
range filter module that can cause a crash or leak memory).
- **Query used:** `app="nginx" && server="nginx/1.13.2"`
- **Files:** `task_5/i_found_it.txt` (query only; I removed the example
  IP address before publishing, since listing a specific, potentially
  vulnerable device publicly isn't something a portfolio needs to show)

## Skills Demonstrated
- MITRE ATT&CK framework for classifying attacker behavior
- Socket programming and a binary wire protocol (MongoDB) in Python
- Man-in-the-middle traffic interception and analysis with mitmproxy
- Packet capture analysis and recognizing DNS tunneling
- OSINT-style device search (Fofa/Shodan/Censys) for vulnerability research

## Key Takeaways
- Attacks map cleanly onto a small set of tactics and techniques, which
  is what makes frameworks like MITRE ATT&CK useful for both attackers'
  playbooks and defenders' coverage checks
- Many real-world exposures are as simple as "no authentication enabled"
  on a database, not a sophisticated exploit
- Encrypted traffic defeats simple interception; the point of the MITM
  exercise is to show what is exposed when it is not
- DNS tunneling is a good example of why "normal-looking" traffic still
  needs to be inspected, not just allowed because the protocol is routine

## Disclaimer
All work was done for educational purposes in a lab environment. I did
not scan or access any systems I was not authorized to test.
