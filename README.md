# Security Investigation Library

Welcome to my security investigation portfolio. This repository contains a collection of end-to-end incident response and threat hunting cases. 

Each case documents the full incident response workflow: from alert validation and data collection through analysis, IOC extraction, MITRE ATT&CK mapping, to remediation recommendations.

The investigations cover various attack scenarios including web application exploitation, malware command-and-control, phishing, lateral movement, privilege escalation, and credential theft. All cases are based on realistic simulations, CTF challenges, and lab environments.

*(This library is actively maintained and updated with new cases)*

---

## Investigation Categories

### Web Application Security
*   [Web-Application-Exploitation-and-Remote-File-Inclusion-(RFI)](./investigations/Web-Application-Exploitation-and-Remote-File-Inclusion-(RFI)) – RFI, XSS, Reverse Shell
*   [Web-Application-SQL-Injection-and-Server-Compromise](./investigations/Web-Application-SQL-Injection-and-Server-Compromise) – SQLi, Server Compromise
*   [Web-Application-Compromise-and-Multi-Stage-Attack](./investigations/Web-Application-Compromise-and-Multi-Stage-Attack) – Multi-stage web attack
*   [Web-Shell-Implant-Investigation](./investigations/Web-Shell-Implant-Investigation) – Web Shell, Persistence
*   [Academic-Phishing-Campaign-and-Credential-Harvesting](./investigations/Academic-Phishing-Campaign-and-Credential-Harvesting) – Phishing, Credential Access

### Linux Forensics & Persistence
*   [Linux-Backdoor-and-Persistence-Investigation](./investigations/Linux-Backdoor-and-Persistence-Investigation)
*   [Linux-Insider-Threat-and-Malicious-Cron-Job-Investigation](./investigations/Linux-Insider-Threat-and-Malicious-Cron-Job-Investigation)
*   [Linux-Post-Compromise-Persistence-Hunt](./investigations/Linux-Post-Compromise-Persistence-Hunt)

### Windows & Network Forensics
*   [Exchange-Server-Compromise-and-Ransomware-Staging](./investigations/Exchange-Server-Compromise-and-Ransomware-Staging)
*   [Network-Forensic-Investigation---ARP-Spoofing,-C2](./investigations/Network-Forensic-Investigation---ARP-Spoofing,-C2)
*   [Multi-Vector-Persistence-Investigation](./investigations/Multi-Vector-Persistence-Investigation)
*   [Malware-Delivery-and-Network-Threat-Investigation](./investigations/Malware-Delivery-and-Network-Threat-Investigation)

### Malware Analysis & SIEM
*   [Operation-SwiftSpend-Wazuh-IR](./investigations/Operation-SwiftSpend-Wazuh-IR) – Wazuh SIEM, Financial Malware
*   [Incident-Investigation-Report-Multi-Stage-Malware](./investigations/Incident-Investigation-Report-Multi-Stage-Malware)
*   [Incident-Investigation-Report-The-Boogeyman-Trilogy](./investigations/Incident-Investigation-Report-The-Boogeyman-Trilogy)
*   [malware-Command-and-Control-Investigation](./investigations/malware-Command-and-Control-Investigation)
*   [swiftspend-finance-malware](./investigations/swiftspend-finance-malware)

---

## Tools & Technologies

*   **Network Analysis:** Wireshark, tcpdump
*   **Threat Intelligence:** VirusTotal, MISP, AbuseIPDB
*   **Malware Analysis:** PE-studio, strings, hash calculators
*   **SIEM and Logging:** Splunk Enterprise, Wazuh, Sysmon, Windows Event Logs, PowerShell logging
*   **Frameworks:** MITRE ATT&CK, Cyber Kill Chain

---

## Skills Demonstrated

*   Incident triage and alert validation
*   Network traffic analysis (PCAP)
*   Host-based forensics (processes, registry, file system)
*   Threat intelligence correlation
*   IOC extraction and management
*   Detection engineering (SPL, rule logic)
*   MITRE ATT&CK alignment
*   Technical report writing

---