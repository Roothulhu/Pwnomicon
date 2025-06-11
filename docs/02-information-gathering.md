# 🔎 Information Gathering

This module consolidates essential manual commands and quick utility snippets useful for active enumeration, system reconnaissance, and service interaction during a pentest workflow.

---

<details>
  <summary><strong>🌐 WEB EDITION</strong></summary>

  This section offers a curated set of manual commands and quick utilities specifically designed for web-focused reconnaissance. It supports both passive techniques—gathering publicly available intel without directly touching the target—and active methods—interacting with the web app to discover hidden elements or vulnerabilities. These techniques help build a rich contextual map of the target, revealing domains, subdomains, technologies, directories, and potential attack surfaces.

  ---

  <details>
    <summary><strong>🌍 WHOIS</strong></summary>

  Command
  ```bash
  whois domain.com
  ```
  
  </details>

  ---

  <details>
    <summary><strong>🖧 DNS</strong></summary>

  Default A record lookup
  ```bash
  dig domain.com
  ```

  Just IPs
  ```bash
  dig +short domain.com
  ```

  Mail Servers
  ```bash
  dig domain.com MX
  ```

  Reverse Lookup to find the associated host name.
  ```bash
  dig -x <IP>
  ```

  </details>

  ---

  <details>
    <summary><strong>🔗 Subdomains</strong></summary>

  FFUF
  ```bash
  ffuf -u http://domain.com/ \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.domain.com" \
  -t 100 \
  -p 0.02 \
  -timeout 10 \
  -mc 200,204,301,302,307,401,403 \
  -fc 404 \
  -ac \
  -o ffuf-subdomains.json \
  -of json \
  -s

  ```

  gobuster
  ```bash
  gobuster dns \
  -d inlanefreight.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 100 \
  --timeout 5s \
  -i \
  -o gobuster-dns.txt
  ```

  dnsenum
  ```bash
  dnsenum \
  --enum \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  domain.com
  ```

  </details>

  ---

</details>
