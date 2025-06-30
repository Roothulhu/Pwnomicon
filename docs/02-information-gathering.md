# 🔎 Information Gathering

In this chapter, the practitioner peers beyond the veil — unveiling fragments of knowledge scattered across domains, records, and headers. These rites allow one to trace the digital echo of a target's presence, long before interaction begins.

> *"Even the faintest signal speaks volumes to those who know how to listen."*

---

<details>
  <summary><h1>🌐 WEB EDITION</h1></summary>

Herein lie the rites of web-focused reconnaissance — rituals woven to divine the structures and shadows behind domains, subdomains, and hidden directories. These incantations blend passive observation with active probing to reveal the true anatomy of a target’s digital presence.
> *"In the vast abyss of the web, even the smallest echo may lead to an open gate."*

  ---

  <details>
    <summary><h2>🌍 WHOIS</h2></summary>

  `whois` is a command-line utility that retrieves registration information for domains, such as owner, registrar, and contact details.
  ```bash
  whois <DOMAIN>
  ```
  
  </details>

  ---

  <details>
    <summary><h2>🖧 DNS</h2></summary>

  `dig` is a flexible DNS lookup tool for querying DNS name servers and troubleshooting DNS problems.

  Default A record lookup
  ```bash
  dig <DOMAIN>
  ```

  Just IPs (returns only the IP addresses)
  ```bash
  dig +short <DOMAIN>
  ```

  Mail Servers (queries MX records for mail servers)
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
    <summary><h2>🔗 Subdomains</h2></summary>

  **gobuster** is a tool for brute-forcing DNS subdomains using wordlists.
  ```bash
  gobuster dns \
  -d <DOMAIN> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 100 \
  --timeout 5s \
  -i \
  -o gobuster-dns.txt
  ```

  **FFUF** is a fast web fuzzer that can also be used for DNS subdomain enumeration.
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

  **dnsenum** is a multi-threaded perl script to enumerate DNS information and discover subdomains.
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
    <summary><h2>↔️ DNS Zone Transfers</h2></summary>

  `dig axfr` attempts a DNS zone transfer, which can reveal all DNS records for a domain if misconfigured.
  ```bash
  dig axfr <DOMAIN> @<IP>
  ```
  
  </details>

  ---

  <details>
    <summary><h2>🗄️ VHOSTS</h2></summary>

  `gobuster vhost` is used to brute-force virtual hosts on a target domain, useful for discovering hidden vhosts.
  ```bash
  sudo gobuster vhost -u <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --append-domain

  ```
  
  </details>

  ---

  <details>
    <summary><h2>🌀 Fingerprinting</h2></summary>

  **Wafw00f** detects and identifies web application firewalls (WAFs) in front of web applications.

  Install
  ```bash
  pip3 install git+https://github.com/EnableSecurity/wafw00f
  ```

  Use
  ```bash
  wafw00f <DOMAIN>
  ```

  **Nikto** is a web server scanner that tests for dangerous files, outdated server software, and other security issues.

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
    <summary><h2>🕷️ Crawling / Spidering</h2></summary>

  **Scrapy** is a powerful Python framework for web crawling and scraping.

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

  <details>
    <summary><h2>🏁 FinalRecon</h2></summary>

  **FinalRecon** is an all-in-one web reconnaissance tool for gathering information about a target domain.

  Install
  ```bash
  git clone https://github.com/thewhiteh4t/FinalRecon.git
  cd FinalRecon
  pip3 install -r requirements.txt
  chmod +x ./finalrecon.py
  ./finalrecon.py --help
  ```

  Use
  ```bash
  ./finalrecon.py --full --url <DOMAIN>
  ```
  
  </details>

---

</details>

---

<details>
<summary><h1>🌍 Nmap</h1></summary>

Network Mapper (Nmap) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua.

**Install**
```bash
sudo apt install nmap -y
```

**Verify installation**
```bash
nmap --version
```
<details>
<summary><h2>Introduction</h2></summary>

It is used to:

* Audit the security aspects of networks
* Simulate penetration tests
* Check firewall and IDS settings and configurations
* Types of possible connections
* Network mapping
* Response analysis
* Identify open ports
* Vulnerability assessment as well.

It be divided into the following scanning techniques:

* Host discovery
* Port scanning
* Service enumeration and detection
* OS detection
* Scriptable interaction with the target service (Nmap Scripting * Engine)

</details>

<details>
<summary><h2>Host Discovery</h2></summary>

**Scan Network Range**

```bash
sudo nmap 10.129.2.0/24 -sn | grep for | cut -d" " -f5
```

Expected output

```bash
# 10.129.2.4
# 10.129.2.10
# 10.129.2.11
# 10.129.2.18
# 10.129.2.19
# 10.129.2.20
# 10.129.2.28
```

**Scan IP List**

```bash
sudo nmap -sn -iL hosts.lst | grep for | cut -d" " -f5
```

hosts.lst example
```bash
cat hosts.lst

# 10.129.2.4
# 10.129.2.10
# 10.129.2.11
# 10.129.2.18
# 10.129.2.19
# 10.129.2.20
# 10.129.2.28
```


Expected output

```bash
# 10.129.2.18
# 10.129.2.19
# 10.129.2.20
```


</details>

<details>
<summary><h2>Host and Port Scanning</h2></summary>

**Scanning Top 10 TCP Ports**  

```bash
sudo nmap <TARGET IP> --top-ports=10
```

**Trace the Packets**

```bash
sudo nmap <TARGET IP> -p <TARGET PORT> --packet-trace --disable-arp-ping -Pn -n 
```

**Connect Scan**

The Connect scan (also known as a full TCP connect scan) is highly accurate because it completes the three-way TCP handshake, allowing us to determine the exact state of a port (open, closed, or filtered).

```bash
sudo nmap <TARGET IP> -p <TARGET PORT> --packet-trace --disable-arp-ping -Pn -n --reason -sT 
```

**UDP Port Scan**

If the UDP port is open, we only get a response if the application is configured to do so.
If we get an ICMP response with error code 3 (port unreachable), we know that the port is indeed closed.
For all other ICMP responses, the scanned ports are marked as (open|filtered).



```bash
sudo nmap <TARGET IP> -sU -Pn -n --disable-arp-ping --packet-trace -p <TARGET PORT> --reason 
```



</details>

</details>

📘 **Next step:** Continue with [VULNERABILITY ASSESSMENT](./03-vulnerability-assessment.md)
