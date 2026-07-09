# Web Application & Server Compromise Investigation

**Incident Type:** Web Application Attack / Data Exfiltration / Server Compromise
**Status:** Completed
**Date of Analysis:** 10 July 2026
**Environment:** TryHackMe – Web Application & Log Analysis Lab (simulated SOC exercise)

---

## Executive Summary

A systematic attack against a web application and its underlying infrastructure was detected through analysis of access logs, FTP logs, and authentication logs. The attacker employed a combination of automated tools — `nmap`, `hydra`, `sqlmap`, `feroxbuster`, and `curl` — to enumerate the web application, identify vulnerabilities, and exfiltrate sensitive data. A successful SQL injection on the `/rest/products/search` endpoint allowed the attacker to retrieve user credentials (email and password). The attacker also abused the FTP service to download backup files (`www-data.bak` and `coupons_2013.md.bak`) using anonymous authentication. Ultimately, the attacker gained shell access via SSH as the `www-data` user. The host was isolated, compromised credentials were rotated, and vulnerable endpoints were patched.

---

## Investigation Workflow

The investigation followed a structured forensic approach:

1. **Tool Identification** – analyse HTTP `User-Agent` strings to identify attacker tools.
2. **SQL Injection Analysis** – review abnormal query strings and response codes.
3. **Directory Enumeration** – identify discovered endpoints and file retrieval attempts.
4. **FTP Access Review** – examine `vsftpd.log` for successful logins and file downloads.
5. **Privilege Escalation** – review SSH authentication logs for shell access.
6. **IoC Extraction** – compile indicators for remediation.
7. **MITRE ATT&CK Mapping** – classify the attacker's techniques.

---

## 1. Tool Identification – `User-Agent` Analysis

The investigation began with a frequency analysis of the last field (the `User-Agent` string) from the access log to identify the tools used by the attacker.

```bash
awk '{print $(NF)}' access.log | sort | uniq -c | sort -nr
```

**Figure 1 – User-Agent frequency analysis**
`screenshots/image_1.png`

The output reveals a clear pattern: Hydra was the most frequently used tool, followed by Firefox/78.0 (likely manual browsing), sqlmap, nmap (via NSE scripts), feroxbuster, and curl. The presence of `"_"` suggests a malformed or custom User-Agent.

| Tool | Occurrences | Purpose |
|---|---|---|
| Hydra | 288 | Brute-force attack against login endpoint |
| Firefox/78.0 | 258 | Manual reconnaissance |
| sqlmap | 78 | Automated SQL injection exploitation |
| nmap | 10 | Network/service scanning |
| feroxbuster | 9 | Directory and file brute-forcing |
| curl | 1 | Ad-hoc HTTP requests |

---

## 2. SQL Injection Analysis

The attacker used sqlmap to probe the `/rest/products/search` endpoint with various malicious payloads designed to test for SQL injection vulnerabilities.

**Figure 2 – SQL injection attempts with sqlmap**
`screenshots/image_2.png`

The logs show a high volume of GET requests to `/rest/products/search` with the `q` parameter containing SQL injection payloads. Examples include:

- `q=1%20AND%208355%3DDBMS_PIPE.RECEIVE_MESSAGE...` (time-based blind)
- `q=1%29%20ORDER%20BY%201--` (ORDER BY enumeration)
- `q=1%20ORDER%20BY%201--` (column count discovery)

The endpoint consistently returned `200 OK` responses, confirming that the application was processing the malicious input and returning data, indicating a successful SQL injection vulnerability.

**Figure 3 – Cleaner SQL injection payloads (ORDER BY and UNION SELECT)**
`screenshots/image_6.png`

The attacker subsequently used UNION SELECT payloads to extract data from the Users table:

```sql
q='%29 UNION SELECT '1', '2', '3', '4', '5', '6', '7', '8', '9' FROM Users--
```

A second payload specifically targeted `id`, `email`, and `password` columns:

```sql
q=qwert'%29 UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--
```

**Figure 4 – UNION SELECT payload extracting id, email, password**
`screenshots/image_6.png`

The `200` response status confirms that the query was executed successfully, allowing the attacker to retrieve user email addresses and password hashes.

---

## 3. Directory & File Enumeration

The attacker used feroxbuster and manual browsing to enumerate the web application's directory structure and locate sensitive files.

**Figure 5 – Feroxbuster directory enumeration on /ftp**
`screenshots/image_3.png`

The tool discovered the `/ftp` directory and identified two backup files:

- `/ftp/www-data.bak` – returned `403 Forbidden` (300 bytes)
- `/ftp/coupons_2013.md.bak` – returned `403 Forbidden` (78,965 bytes)

**Figure 6 – FTP access attempts with feroxbuster**
`screenshots/image_7.png`

The logs confirm that `feroxbuster/2.2.1` was used to probe the `/ftp` directory, while Firefox/78.0 was used to attempt direct access to the backup files, both of which initially returned `403 Forbidden`.

---

## 4. Web Application Reconnaissance

The attacker also performed reconnaissance on other web application endpoints, likely to understand the application's functionality and identify further attack vectors.

**Figure 7 – Reconnaissance on /rest/products and /rest/products/1/reviews**
`screenshots/image_4.png`

The logs show:

- `GET /rest/products/search?q=` – testing the search endpoint with an empty query
- `GET /rest/products/1/reviews` – retrieving reviews for product ID 1 (multiple times)
- `GET /rest/user/whoami` – attempting to identify the current authenticated user
- `GET /rest/basket/1` – checking the shopping basket for user ID 1

**Figure 8 – User and basket information requests**
`screenshots/image_5.png`

These requests returned `200 OK` responses, indicating that the endpoints were accessible and likely leaking information.

---

## 5. FTP Service Abuse

The attacker leveraged the FTP service to download sensitive backup files from the server. Analysis of the `vsftpd.log` reveals the sequence of events.

**Figure 9 – vsftpd.log – FTP login attempts and successes**
`screenshots/image_8.png`

Key findings from the FTP log:

| Timestamp | Event | Client IP | Details |
|---|---|---|---|
| 08:13:32 | CONNECT | ::ffff:127.0.0.1 | Local connection |
| 08:13:40 | FAIL LOGIN | ::ffff:127.0.0.1 | Anonymous login failed |
| 08:15:09 | CONNECT | ::ffff:127.0.0.1 | Another local connection |
| 08:15:14 | FAIL LOGIN | ::ffff:127.0.0.1 | Anonymous login failed again |
| 08:15:58 | OK LOGIN | ::ffff:127.0.0.1 | ftp user logged in with password ? |
| 08:16:07 | OK LOGIN | ::ffff:127.0.0.1 | ftp user logged in with password Ls |
| 08:16:34 | OK LOGIN (x3) | ::ffff:192.168.10.5 | ftp user logged in with password IEUser@ |

The successful logins from `192.168.10.5` with the password `IEUser@` are particularly significant. This IP matches the source IP observed in the web access logs, confirming that the attacker used the FTP service to retrieve files.

**Figure 10 – FTP file access from web logs**
`screenshots/image_7.png`

The access logs show successful requests to:

- `GET /ftp HTTP/1.1` – `200 OK` (directory listing)
- `GET /ftp/www-data.bak HTTP/1.1` – `403 Forbidden`
- `GET /ftp/coupons_2013.md.bak HTTP/1.1` – `403 Forbidden`

Although the direct HTTP requests returned `403`, the attacker likely used the FTP service (with anonymous login) to download these files, as indicated by the successful FTP logins.

---

## 6. SSH Shell Access

The attacker successfully gained shell access to the server using SSH.

**Figure 11 – SSH authentication logs**
`screenshots/image_9.png`

The log shows:

- `Apr 11 09:41:19` – Received disconnect from `192.168.10.5` port `40110` (previous session)
- `Apr 11 09:41:19` – Disconnected from authenticating user `www-data` `192.168.10.5`
- `Apr 11 09:41:19` – Accepted password for `www-data` from `192.168.10.5` port `40112`
- `Apr 11 09:41:19` – session opened for user `www-data`

The attacker successfully authenticated as the `www-data` user using a password and established an interactive shell session. The log also shows the preceding line: `PAM service(sshd) ignoring max retries; 6 > 3`, indicating that the attacker exceeded the maximum retry limit (6 > 3) before successfully logging in.

The successful login from `192.168.10.5` as `www-data` confirms that the attacker used compromised credentials — likely obtained via the SQL injection — to gain shell access.

---

## 7. Brute-Force Attack Analysis

The attacker also performed a brute-force attack against the application's login endpoint.

**Figure 12 – Product reviews endpoint used for scraping**
`screenshots/image_4.png`

The attacker repeatedly accessed `/rest/products/1/reviews` to scrape user email addresses. This endpoint returned user-generated content, which likely included email addresses in the review text or associated metadata.

The brute-force attack was successful. Based on the logs, the successful login timestamp is: