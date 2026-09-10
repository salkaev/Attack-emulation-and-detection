# Incident Investigation Report – Web Shell Implant (TryHackMe "Infinity Shell")

**Incident Type:** Web Application Compromise / Web Shell Implantation  
**Status:** Completed  
**Date of Analysis:** 11 September 2026  
**Analyst:** Specter  
**Affected Host:** `ip-10-112-146-170.eu-central-1.compute.internal` (10.112.146.170), Ubuntu, Apache 2.4  
**Application:** Victor's CMS (`/var/www/html/CMSsite-master/`)

---

## Executive Summary

An attacker from IP `10.11.93.143` (AWS eu-west-1) on 6 March 2025 exploited a vulnerability in Victor's CMS and implanted a PHP web shell at `/CMSsite-master/img/images.php`. The shell accepts base64 commands via the GET parameter `query=`. Within ~50 seconds, the following were executed: `ls`, `pwd`/`whoami`, `ifconfig`, `cat /etc/passwd`, `id`. Afterwards — reconnaissance of the CMS admin panel.

---

## Investigation Workflow

1. Analysis of Apache `access.log`
2. Attacker IP identification
3. Web shell detection in `img/`
4. Decoding base64 parameters
5. Timeline construction
6. MITRE ATT&CK mapping

---

## 1. Attacker Identification

- **Source IP:** `10.11.93.143`
- **Hostname:** `ip-10-10-80-94.eu-west-1.compute.internal` (AWS EC2)
- **User-Agent:** `Chrome/133.0.0.0 Safari/537.36` (macOS 10.15.7)

---

## 2. Web Shell `images.php`

**Log evidence:**

```apache
09:50:57  GET /CMSsite-master/img/images.php?query=d2hYW1pCg==        200  212 B
09:51:11  GET /CMSsite-master/img/images.php?query=bHMKbYAnVEhNe3N1cDNYc2M0c3lfdzNiC2g6bx9Jwo=  200  660 B
09:51:20  GET /CMSsite-master/img/images.php?query=ZwNo...             200  229 B
09:51:28  GET /CMSsite-master/img/images.php?query=aWZjb25maWc=        200  203 B
09:51:40  GET /CMSsite-master/img/images.php?query=Y2F0IC9ldGMvcGFzc3dk 200 1546 B
09:51:47  GET /CMSsite-master/img/images.php?query=aWQ=                200  258 B
```

**Decoded commands:**

| Time | Base64 | Command | Response size |
|---|---|---|---|
| 09:50:57 | `d2hYW1pCg==` | probe | 212 B |
| 09:51:11 | `bHMKbYAnVEhNe3N1cDNYc2M0c3lfdzNiC2g6bx9Jwo=` | `ls` / flag `THM{sup3XsC4sy_w3nC2h6b_9J...` | 660 B |
| 09:51:20 | `ZwNo...` | `pwd` / `whoami` | 229 B |
| 09:51:28 | `aWZjb25maWc=` | `ifconfig` | 203 B |
| 09:51:40 | `Y2F0IC9ldGMvcGFzc3dk` | `cat /etc/passwd` | 1546 B |
| 09:51:47 | `aWQ=` | `id` | 258 B |

**Shell characteristics:**

- GET-based, parameter `query=` with base64
- Masqueraded as an image handler in `img/`
- Responses 200–1546 bytes = command output in the HTTP body

---

## 3. Post-Exploitation

After the shell — normal browsing of the CMS and admin panel:

```apache
09:51:58  GET / HTTP/1.1" 200 3460
10:09:58  GET /CMSsite-master/ HTTP/1.1" 200 2666
10:10:05  GET /CMSsite-master/admin/font-awesome/... 404
10:10:06  GET /CMSsite-master/img/award%20githud.JPG 404
10:10:08  GET /CMSsite-master/post.php?post=2 HTTP/1.1" 200 2730
10:10:08  GET /CMSsite-master/admin/js/tinymce/... HTTP/1.1" 200 4184
```

The attacker was looking for additional vectors (TinyMCE, uploads).

---

## 4. Timeline

| Time (UTC) | Action |
|---|---|
| 09:50:57 | First request to the shell |
| 09:51:11 | `ls` + flag fragment |
| 09:51:20–28 | `pwd`/`whoami`, `ifconfig` |
| 09:51:40 | `cat /etc/passwd` |
| 09:51:47 | `id` |
| 09:51:58–10:10:08 | Reconnaissance of CMS and admin panel |

Active shell session: **~50 seconds**.

---

## 5. Indicators of Compromise (IoC)

| Type | Value |
|---|---|
| **Attacker IP** | `10.11.93.143` |
| **Web shell path** | `/var/www/html/CMSsite-master/img/images.php` |
| **Shell parameter** | `query=` (base64 OS commands) |
| **Commands** | `ls`, `pwd`, `ifconfig`, `cat /etc/passwd`, `id` |
| **User-Agent** | `Chrome/133.0.0.0 Safari/537.36` macOS 10.15.7 |
| **Flag fragment** | `THM{sup3XsC4sy_w3nC2h6b_9J...` |

---

## 6. MITRE ATT&CK

| Technique | Tactic | ID | Evidence |
|---|---|---|---|
| Web Shell | Persistence, Execution | T1505.003 | `images.php` in `img/` |
| Unix Shell | Execution | T1059.004 | `query=` → OS commands |
| Ingress Tool Transfer | C2 | T1105 | Shell upload via CMS |
| System Information Discovery | Discovery | T1082 | `ifconfig`, `id`, `/etc/passwd` |
| Masquerading | Defense Evasion | T1036.005 | Shell in `img/` as `images.php` |
| Web Service Protocol | C2 | T1071.001 | HTTP GET as C2 channel |

---

## 7. Conclusion and Recommendations

**Conclusion:** The attacker implanted a GET-based PHP shell at `img/images.php`, within 50 seconds conducted reconnaissance and stole `/etc/passwd`, then explored the CMS admin panel for further persistence.

### Immediate Actions

1. `rm /var/www/html/CMSsite-master/img/images.php`
2. Audit `img/` for other `.php`: `find /var/www/html/CMSsite-master/img -name "*.php"`
3. Block IP `10.11.93.143` on WAF/firewall
4. Rotate all CMS and DB credentials
5. Patch the CMS vulnerability (file upload bypass / RCE)
6. Disable PHP in `img/`, `uploads/`, `assets/`:

   ```apache
   <Directory /var/www/html/CMSsite-master/img>
       php_admin_flag engine off
   </Directory>
   ```

### Long-term Measures

1. WAF rules for base64 in GET parameters
2. Alert on `.php` in non-code directories
3. Enable `mod_security` + OWASP CRS
4. FIM (AIDE/osquery) on web root
5. Restrict admin panel access by IP/VPN
6. Log all POST requests to CMS endpoints

### Lessons Learned

1. Shells in `img/` are a top persistence method — regular audits are mandatory
2. Base64 in URLs is a strong indicator — automate detection
3. Short sessions (~50s) = automated tooling (`weevely`, `c99`)
4. Post-shell admin panel browsing = search for deeper persistence — monitor new admins and modified templates

---

## Appendix – Detection Queries

```bash
# Shell signatures
grep -rnE "eval\s*\(\s*base64_decode|system\s*\(\s*\$_(GET|POST|REQUEST)" /var/www/

# PHP in image directories
find /var/www -path "*/img/*.php" -o -path "*/uploads/*.php" -o -path "*/assets/*.php"

# Base64 parameters in logs
grep -E "query=[A-Za-z0-9+/]{20,}={0,2}" /var/log/apache2/access.log

# Access to /etc/passwd
grep "/etc/passwd" /var/log/apache2/access.log
```