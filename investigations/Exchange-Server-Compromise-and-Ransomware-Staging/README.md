# Incident Report: Exchange Server Compromise & Ransomware Staging

**Incident Type:** Web Shell Exploitation / Credential Dumping / Ransomware Preparation  
**Status:** Completed  
**Date of Analysis:** September 20, 2026  
**Environment:** TryHackMe – SOC Simulation Exercise

## Executive Summary

An investigation into suspicious network activity revealed a full-scale compromise of an internal Exchange Server (`WIN-AOQKG2AS2Q7.bellybear.local`). The attacker exploited the Outlook Web App (OWA) to deploy a web shell, established persistence by creating a rogue administrative account, and successfully injected into the `lsass.exe` process to harvest credentials. 

The attack culminated in the execution of a malicious binary (`cmd.exe`) from an unusual directory, which proceeded to drop multiple `readme.txt` files across various user directories—a typical precursor to a ransomware deployment. 

## Investigation Workflow

The investigation followed a structured SOC workflow utilizing IIS web logs and Sysmon telemetry:

1. **Web Log Analysis** – Identify initial access vectors via OWA.  
2. **Process Creation Analysis (Sysmon Event ID 1)** – Track attacker commands and persistence mechanisms.  
3. **Remote Thread Analysis (Sysmon Event ID 8)** – Detect credential dumping attempts.  
4. **File Creation Analysis (Sysmon Event ID 11)** – Identify ransomware staging behavior.  
5. **IoC Extraction** – Compile indicators of compromise for remediation.

---

## 1. Initial Access & Defense Evasion

Analysis of IIS logs revealed multiple POST requests targeting a suspicious ASPX file within the OWA authentication directory. The requests originated from the external IP `10.10.10.6`.

* **Target URI:** `/owa/auth/i3gfPctK1c2x.aspx`

![IIS Logs - Web Shell Access](1.png)  
*Figure 1 – IIS logs showing POST requests to the deployed web shell.*

To ensure the web shell remained functional, the attacker used the living-off-the-land binary (LOLBin) `attrib.exe` to remove the read-only attribute from the file across the network share:

```cmd
attrib.exe -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```

![Command Line - attrib.exe](2.png)  
*Figure 2 – Command line execution of `attrib.exe` modifying file attributes.*

## 2. Execution & Persistence

Following the web shell deployment, the attacker spawned a command shell. Sysmon Event ID 1 logs show that `cmd.exe` was executed from an atypical user directory rather than `System32`.

| Field | Value |
|-------|-------|
| **Image** | `C:\Users\Administrator\Documents\cmd.exe` |
| **CommandLine** | `cmd.exe` |
| **CurrentDirectory** | `c:\Users\Administrator\Documents\` |
| **MD5** | `290C7DFB01E50CEA9E19DA81A781AF2C` |
| **SHA256** | `53B1C1B2F41A7FC300E97D036E57539453FF82001DD3F6ABF07F4896B1F9CA22` |

![Sysmon Event 1 - cmd.exe](3.png)  
*Figure 3 – Sysmon event detailing the execution of `cmd.exe` from the Administrator's Documents folder.*

Immediately after, the attacker executed a command to establish persistence by creating a new local user account with administrative privileges:

```cmd
C:\Windows\system32\net1 user /add securityninja hardToHack123$
```
This command was executed via `net1.exe`, spawned by `net.exe`.

![Sysmon Event 1 - net1.exe](4.png)  
*Figure 4 – Creation of the backdoor account `securityninja`.*

## 3. Credential Access

The attacker attempted to dump credentials by injecting code into the Local Security Authority Subsystem Service (`lsass.exe`). Sysmon Event ID 8 (`CreateRemoteThread`) captured the legitimate WMI utility `unsecapp.exe` being used to inject into `lsass.exe`.

| Field | Value |
|-------|-------|
| **SourceImage** | `C:\Windows\System32\wbem\unsecapp.exe` |
| **TargetImage** | `C:\Windows\System32\lsass.exe` |
| **TargetProcessId** | `672` |
| **NewThreadId** | `13980` |
| **StartAddress** | `0x000001D471950000` |

![Sysmon Event 8 - CreateRemoteThread](5.png)  
*Figure 5 – Remote thread creation indicating LSASS memory access for credential dumping.*

## 4. Ransomware Staging

The compromised `cmd.exe` process (PID 15540) began creating `readme.txt` files across multiple user directories. This behavior is highly indicative of ransomware preparing to encrypt files and leave ransom notes.

**Created Files (Sysmon Event ID 11):**
* `C:\Users\Default\AppData\Roaming\readme.txt`
* `C:\Users\Default\AppData\Local\readme.txt`
* `C:\Users\Public\Downloads\readme.txt`

![Sysmon Event 11 - readme.txt](6.png)  
*Figure 6 – Creation of `readme.txt` in the Roaming directory.*

![Sysmon Event 11 - readme.txt details](7.png)  
*Figure 7 – Creation of `readme.txt` in the Local and Public directories.*

---

## 5. Indicators of Compromise (IoC)

### Network Indicators
| Type | Value |
|------|-------|
| **Attacker IP** | `10.10.10.6` |
| **Web Shell URI** | `/owa/auth/i3gfPctK1c2x.aspx` |

### File Indicators & Hashes
| File Path / Name | Hash Type | Hash Value |
|------------------|-----------|------------|
| `C:\Users\Administrator\Documents\cmd.exe` | MD5 | `290C7DFB01E50CEA9E19DA81A781AF2C` |
| `C:\Users\Administrator\Documents\cmd.exe` | SHA256 | `53B1C1B2F41A7FC300E97D036E57539453FF82001DD3F6ABF07F4896B1F9CA22` |
| `C:\Windows\System32\net1.exe` | MD5 | `63DAD4523677E62A73A8A7494DB32E1EA2` |
| `C:\Windows\System32\net1.exe` | SHA256 | `C687157FD58EAA51...` |
| `readme.txt` | N/A | Ransomware note artifact |

### Account Indicators
* **Username:** `securityninja`
* **Password:** `hardToHack123$`

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| **Server Software Component: Web Shell** | T1505.003 | Deployment of `i3gfPctK1c2x.aspx` to maintain access. |
| **Indicator Removal: File Deletion** | T1070.004 | Use of `attrib.exe -r` to modify file attributes for evasion. |
| **Create Account: Local Account** | T1136.001 | Creation of the `securityninja` backdoor account. |
| **OS Credential Dumping: LSASS Memory** | T1003.001 | Injection into `lsass.exe` via `unsecapp.exe`. |
| **Data Encrypted for Impact** | T1486 | Creation of `readme.txt` ransom notes across user directories. |

---

## 7. Conclusion & Recommendations

The investigation confirmed that the Exchange server was fully compromised, moving from initial web shell access to credential theft and ransomware staging. The attacker demonstrated a clear intent to exfiltrate data and deploy ransomware.

**Recommendations:**

1. **Immediate Isolation** – Disconnect the server `WIN-AOQKG2AS2Q7` from the network to prevent ransomware spread.
2. **Account Remediation** – Delete the `securityninja` account immediately and force a password reset for all Administrator accounts, as LSASS was compromised.
3. **Web Shell Removal** – Remove `i3gfPctK1c2x.aspx` and conduct a thorough scan of the IIS directories for any other unauthorized files.
4. **Network Blocking** – Block the attacker IP `10.10.10.6` at the firewall level.
5. **Patch Management** – Ensure the Exchange Server is fully patched against known OWA vulnerabilities (e.g., ProxyLogon/ProxyShell) that allow web shell uploads.