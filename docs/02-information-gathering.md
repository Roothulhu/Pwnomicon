# 🔎 Information Gathering

In this chapter, the practitioner peers beyond the veil — unveiling fragments of knowledge scattered across domains, records, and headers. These rites allow one to trace the digital echo of a target's presence, long before interaction begins.

> _"Even the faintest signal speaks volumes to those who know how to listen."_

---

<details>
<summary><h1>🌐 WEB EDITION</h1></summary>

Herein lie the rites of web-focused reconnaissance — rituals woven to divine the structures and shadows behind domains, subdomains, and hidden directories. These incantations blend passive observation with active probing to reveal the true anatomy of a target's digital presence.

> _"In the vast abyss of the web, even the smallest echo may lead to an open gate."_

---

<details>
<summary><h2>🌍 WHOIS</h2></summary>

`whois` is a command-line utility that retrieves registration information for domains, such as owner, registrar, and contact details.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
whois <DOMAIN>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🖧 DNS</h2></summary>

`dig` is a flexible DNS lookup tool for querying DNS name servers and troubleshooting DNS problems.

**Default A record lookup**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
dig <DOMAIN>
```

</td>
</tr>
</table>

**Just IPs (returns only the IP addresses)**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
dig +short <DOMAIN>
```

</td>
</tr>
</table>

**Mail Servers (queries MX records)**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
dig <DOMAIN> MX
```

</td>
</tr>
</table>

**Reverse Lookup to find the associated host name**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
dig -x <IP>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🔗 Subdomains</h2></summary>

**gobuster** is a tool for brute-forcing DNS subdomains using wordlists.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
gobuster dns \
  -d <DOMAIN> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 100 \
  --timeout 5s \
  -i \
  -o gobuster-dns.txt
```

</td>
</tr>
</table>

**FFUF** is a fast web fuzzer that can also be used for DNS subdomain enumeration.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

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

</td>
</tr>
</table>

**dnsenum** is a multi-threaded perl script to enumerate DNS information and discover subdomains.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

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

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>↔️ DNS Zone Transfers</h2></summary>

`dig axfr` attempts a DNS zone transfer, which can reveal all DNS records for a domain if misconfigured.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
dig axfr <DOMAIN> @<IP>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🗄️ VHOSTS</h2></summary>

`gobuster vhost` is used to brute-force virtual hosts on a target domain, useful for discovering hidden vhosts.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo gobuster vhost \
  -u <DOMAIN> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -t 50 \
  --append-domain
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🌀 Fingerprinting</h2></summary>

**Wafw00f** detects and identifies web application firewalls (WAFs) in front of web applications.

1. **Install** wafw00f

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
pip3 install git+https://github.com/EnableSecurity/wafw00f
```

</td>
</tr>
</table>

2. **Run** against target

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
wafw00f <DOMAIN>
```

</td>
</tr>
</table>

**Nikto** is a web server scanner that tests for dangerous files, outdated server software, and other security issues.

1. **Install** Nikto

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```

</td>
</tr>
</table>

2. **Run** against target

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
nikto -h <DOMAIN> -Tuning b
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🕷️ Crawling / Spidering</h2></summary>

**Scrapy** is a powerful Python framework for web crawling and scraping.

1. **Install** Scrapy

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
pip3 install scrapy
```

</td>
</tr>
</table>

2. **Download** and run ReconSpider

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py <DOMAIN>
cat results.json
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🏁 FinalRecon</h2></summary>

**FinalRecon** is an all-in-one web reconnaissance tool for gathering information about a target domain.

1. **Install** FinalRecon

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
```

</td>
</tr>
</table>

2. **Run** full reconnaissance

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
./finalrecon.py --full --url <DOMAIN>
```

</td>
</tr>
</table>

</details>

---

</details>

---

<details>
<summary><h1>🌍 Nmap</h1></summary>

Network Mapper (Nmap) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua.

**Install**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo apt install nmap -y
```

</td>
</tr>
</table>

**Verify installation**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
nmap --version
```

</td>
</tr>
</table>

<details>
<summary><h2>Introduction</h2></summary>

It is used to:

- Audit the security aspects of networks
- Simulate penetration tests
- Check firewall and IDS settings and configurations
- Types of possible connections
- Network mapping
- Response analysis
- Identify open ports
- Vulnerability assessment as well.

It can be divided into the following scanning techniques:

- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

</details>

<details>
<summary><h2>Host Discovery</h2></summary>

**Scan Network Range**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo nmap 10.129.2.0/24 -sn | grep for | cut -d" " -f5
```

</td>
</tr>
<tr>
<td colspan="2">

---

```text
10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```

</td>
</tr>
</table>

**Scan IP List**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo nmap -sn -iL hosts.lst | grep for | cut -d" " -f5
```

</td>
</tr>
</table>

</details>

<details>
<summary><h2>Host and Port Scanning</h2></summary>

**Scanning Top 10 TCP Ports**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo nmap <TARGET IP> --top-ports=10
```

</td>
</tr>
</table>

**Trace the Packets**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo nmap <TARGET IP> -p <TARGET PORT> --packet-trace --disable-arp-ping -Pn -n
```

</td>
</tr>
</table>

**Connect Scan**

The Connect scan (also known as a full TCP connect scan) is highly accurate because it completes the three-way TCP handshake, allowing us to determine the exact state of a port (open, closed, or filtered).

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo nmap <TARGET IP> -p <TARGET PORT> --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

</td>
</tr>
</table>

**UDP Port Scan**

If the UDP port is open, we only get a response if the application is configured to do so. If we get an ICMP response with error code 3 (port unreachable), we know that the port is indeed closed. For all other ICMP responses, the scanned ports are marked as (open|filtered).

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo nmap <TARGET IP> -sU -Pn -n --disable-arp-ping --packet-trace -p <TARGET PORT> --reason
```

</td>
</tr>
</table>

</details>

</details>

---

📘 **Next step:** Continue with [Vulnerability Assessment](./03-vulnerability-assessment.md)
