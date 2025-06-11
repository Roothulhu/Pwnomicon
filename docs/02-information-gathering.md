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
  whois <DOMAIN>
  ```
  
  </details>

  ---

  <details>
    <summary><strong>🖧 DNS</strong></summary>

  Default A record lookup
  ```bash
  dig <DOMAIN>
  ```

  Just IPs
  ```bash
  dig +short <DOMAIN>
  ```

  Mail Servers
  ```bash
  dig <DOMAIN> MX
  ```

  Reverse Lookup to find the associated host name.
  ```bash
  dig -x <IP>
  ```

  </details>

  ---

  <details>
    <summary><strong>🔗 Subdomains</strong></summary>

  **gobuster**
  ```bash
  gobuster dns \
  -d <DOMAIN> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 100 \
  --timeout 5s \
  -i \
  -o gobuster-dns.txt
  ```

  **FFUF**
  ```bash
  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
   -u http://FUZZ.<DOMAIN>/ \
   -t 50 \
   -timeout 10 \
   -mc all \
   -ac \
   -o ffuf-dns-vhost.json \
   -of json
  ```

  **dnsenum**
  ```bash
  dnsenum \
  --threads 20 \
  --timeout 5 \
  --noreverse \
  --file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --subfile valid-subdomains.txt \
  -o domain-dnsenum.xml \
  <DOMAIN>
  ```

  </details>

  ---

  <details>
    <summary><strong>↔️ DNS Zone Transfers</strong></summary>

  Command
  ```bash
  dig axfr <DOMAIN> @<IP>
  ```
  
  </details>

  ---

  <details>
    <summary><strong>🗄️ VHOSTS</strong></summary>

  Command
  ```bash
  sudo gobuster vhost -u <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --append-domain

  ```
  
  </details>

  ---

  <details>
    <summary><strong>🌀 Fingerprinting</strong></summary>

  **Wafw00f**

  Install
  ```bash
  pip3 install git+https://github.com/EnableSecurity/wafw00f
  ```

  Use
  ```bash
  wafw00f <DOMAIN>
  ```

  **Nikto**

  Install
  ```bash
  sudo apt update && sudo apt install -y perl
  git clone https://github.com/sullo/nikto
  cd nikto/program
  chmod +x ./nikto.pl
  ```

  Use
  ```bash
  nikto -h <DOMAIN> -Tuning b
  ```

  </details>

  ---

  <details>
    <summary><strong>🕷️ Crawling / Spidering</strong></summary>

  **Scrapy**

  Install
  ```bash
  pip3 install scrapy
  ```

  Use
  ```bash
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
  unzip ReconSpider.zip
  python3 ReconSpider.py <DOMAIN>
  cat results.json
  ```


  
  </details>

  ---

</details>
