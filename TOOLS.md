# 🛠️ Tools Installation Guide

_Every engagement demands the right instrument. This guide centralizes installation procedures for every tool referenced in the Pwnomicon, ensuring a reproducible and battle-ready attack environment across sessions._

> _"Chance favors the prepared mind." — Louis Pasteur_

---

## Table of Contents

| Category | Tools |
| -------- | ----- |
| [🔍 Network Scanning & Enumeration](#-network-scanning--enumeration) | Nmap, Enum4Linux-ng, SSH-Audit, RDP-Sec-Check, enum4linux, ldap-utils, windapsearch, smbmap |
| [🌐 Web Reconnaissance](#-web-reconnaissance) | Wafw00f, Nikto, Scrapy, FinalRecon, ReconSpider, Subbrute |
| [🔓 Vulnerability Assessment](#-vulnerability-assessment) | Nessus, OpenVAS / GVM |
| [💣 Exploitation Frameworks](#-exploitation-frameworks) | Metasploit Framework |
| [🔑 Password Attacks & Authentication](#-password-attacks--authentication) | Kerbrute, Evil-WinRM, NetExec, CrackMapExec, Hashcat, Username-Anarchy, DefaultCreds-Cheat-Sheet, Dislocker, Kerberos 5 |
| [🧠 Credential Extraction](#-credential-extraction) | Pypykatz, Mimipenguin, LaZagne, Firefox_Decrypt, Decrypt-Chrome-Passwords, Linikatz, PCredz, MANSPIDER |
| [🚇 Network Tunneling & Pivoting](#-network-tunneling--pivoting) | Chisel, rpivot, dnscat2, dnscat2-powershell, ptunnel-ng, Pyenv |
| [🏛️ Active Directory & Kerberos](#️-active-directory--kerberos) | BloodHound, BloodHound.py, Impacket, Responder, PKINITtools, Pywhisker, adidnsdump, gpp-decrypt, noPac.py, PetitPotam.py, CVE-2021-1675.py |
| [🪟 Windows Attack Tools](#-windows-attack-tools) | Mimikatz, Rubeus, PowerView / SharpView, SharpHound, Inveigh, DomainPasswordSpray, LAPSToolkit, Snaffler, PingCastle, ADRecon, Group3r, AD Explorer |
| [📡 Network Analysis](#-network-analysis) | Wireshark, Tesseract-OCR, Antiword |
| [🔧 Utilities](#-utilities) | cifs-utils, PWsafe, RAR |

---

## How to Reference This Guide

When a document references a tool installation, use this format:

```
📦 **Installation:** See [Tool Name](../TOOLS.md#anchor) in the Tools Guide.
```

---

<details>
<summary><h2>🔍 Network Scanning & Enumeration</h2></summary>

<details>
<summary><h3 id="nmap">Nmap</h3></summary>

Network mapper — the foundational port scanner for host discovery, service detection, OS fingerprinting, and script-based enumeration.

**Install:**

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

**Verify:**

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

</details>

---

<details>
<summary><h3 id="enum4linux-ng">Enum4Linux-ng</h3></summary>

Next-generation rewrite of enum4linux in Python 3 — enumerates SMB/NetBIOS information from Windows and Samba hosts, including users, groups, shares, and policies.

**Install:**

1. **Clone** the repository and install dependencies.

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
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```

</td>
</tr>
</table>

2. **Install** the script system-wide.

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
sudo cp enum4linux-ng.py /usr/local/bin/enum4linux-ng
sudo chmod +x /usr/local/bin/enum4linux-ng
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="ssh-audit">SSH-Audit</h3></summary>

Audits SSH server and client configurations, detecting weak algorithms, deprecated ciphers, and known vulnerabilities.

**Install:**

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
git clone https://github.com/jtesta/ssh-audit.git
cd ssh-audit
pip3 install -r requirements.txt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="rdp-sec-check">RDP-Sec-Check</h3></summary>

Checks a Windows RDP endpoint for security vulnerabilities, including NLA enforcement, encryption levels, and known CVEs.

**Install:**

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
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
cd rdp-sec-check
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="enum4linux">enum4linux</h3></summary>

Original Perl-based enumeration tool for Samba and Windows hosts — retrieves users, groups, shares, and OS info via SMB/RPC null sessions.

**Install:**

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
sudo apt install enum4linux -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="ldap-utils">ldap-utils (ldapsearch)</h3></summary>

Command-line LDAP client utilities — `ldapsearch` queries LDAP/Active Directory for users, groups, OUs, and other objects. Essential for manual AD enumeration.

**Install:**

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
sudo apt install ldap-utils -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="windapsearch">windapsearch</h3></summary>

Python script for automated LDAP enumeration against AD — retrieves users, groups, computers, privileged accounts, and SPNs without requiring full domain credentials.

**Install:**

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
git clone https://github.com/ropnop/windapsearch.git
cd windapsearch
pip3 install ldap3
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="smbmap">smbmap</h3></summary>

SMB share enumerator — lists share permissions, recursively lists directory contents, uploads/downloads files, and executes commands across Windows SMB shares.

**Install:**

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
sudo apt install smbmap -y
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🌐 Web Reconnaissance</h2></summary>

<details>
<summary><h3 id="wafw00f">Wafw00f</h3></summary>

Web Application Firewall fingerprinting tool — identifies WAF products protecting a web application.

**Install:**

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

</details>

---

<details>
<summary><h3 id="nikto">Nikto</h3></summary>

Web server scanner that checks for dangerous files/programs, outdated server software, and version-specific problems.

**Install:**

1. **Install** the Perl dependency.

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
```

</td>
</tr>
</table>

2. **Clone** the Nikto repository and make it executable.

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
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="scrapy">Scrapy</h3></summary>

Python web crawling and scraping framework — used to spider websites and extract structured data.

**Install:**

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

</details>

---

<details>
<summary><h3 id="finalrecon">FinalRecon</h3></summary>

All-in-one OSINT and web reconnaissance tool covering WHOIS, DNS, headers, SSL, subdomain enumeration, Wayback Machine lookup, and more.

**Install:**

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
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="reconspider">ReconSpider</h3></summary>

Advanced OSINT framework for gathering information from websites and digital footprints.

**Install:**

1. **Download** and extract the archive.

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
```

</td>
</tr>
</table>

2. **Install** Python dependencies.

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
pip3 install -r requirements.txt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="subbrute">Subbrute</h3></summary>

Fast subdomain enumeration tool that uses DNS resolvers to brute-force subdomains with multi-threading support.

**Install:**

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
git clone https://github.com/TheRook/subbrute.git
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🔓 Vulnerability Assessment</h2></summary>

<details>
<summary><h3 id="nessus">Nessus</h3></summary>

Industry-standard vulnerability scanner by Tenable — performs credentialed and uncredentialed scans across networks, detecting thousands of CVEs and misconfigurations.

**Install:**

1. **Download** the `.deb` package from [tenable.com/downloads/nessus](https://www.tenable.com/downloads/nessus) and install it.

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
sudo dpkg -i Nessus-*.deb
sudo systemctl enable --now nessusd
```

</td>
</tr>
</table>

2. **Activate** Nessus by navigating to `https://localhost:8834` in your browser and entering your activation code.

> **NOTE:** A free Nessus Essentials license is available for home use at tenable.com.

</details>

---

<details>
<summary><h3 id="openvas">OpenVAS / GVM</h3></summary>

Open-source vulnerability management solution (Greenbone Vulnerability Manager) — community alternative to Nessus with a web-based interface.

**Install:**

1. **Install** GVM and run the initial setup.

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
sudo apt-get install gvm -y
sudo gvm-setup
```

</td>
</tr>
</table>

2. **Start** the GVM services and access the web interface at `https://127.0.0.1:9392`.

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
sudo gvm-start
```

</td>
</tr>
</table>

> **NOTE:** Setup can take 30+ minutes due to NVT feed synchronization.

</details>

</details>

---

<details>
<summary><h2>💣 Exploitation Frameworks</h2></summary>

<details>
<summary><h3 id="metasploit">Metasploit Framework</h3></summary>

The world's most widely used penetration testing framework — provides exploits, payloads, auxiliary modules, post-exploitation, and more.

**Install:**

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
sudo apt update && sudo apt install metasploit-framework -y
```

</td>
</tr>
</table>

**Initialize the database:**

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
sudo msfdb init
```

</td>
</tr>
</table>

**Update:**

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
sudo apt-get upgrade metasploit-framework -y
```

</td>
</tr>
</table>

**Install community plugins (optional):**

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
git clone https://github.com/darkoperator/Metasploit-Plugins
sudo cp Metasploit-Plugins/*.rb /usr/share/metasploit-framework/plugins/
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🔑 Password Attacks & Authentication</h2></summary>

<details>
<summary><h3 id="hashcat">Hashcat</h3></summary>

World's fastest password recovery tool — GPU-accelerated cracker supporting 300+ hash types (NTLM, Kerberos, bcrypt, etc.) with extensive attack modes (dictionary, rule-based, mask, combinator).

**Install:**

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
sudo apt install hashcat -y
```

</td>
</tr>
</table>

**Verify:**

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
hashcat --version
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="crackmapexec">CrackMapExec (CME)</h3></summary>

Network attack and enumeration swiss army knife — tests credentials and executes commands over SMB, WinRM, MSSQL, LDAP, and SSH. Predecessor to NetExec.

> **NOTE:** CrackMapExec is no longer actively maintained. Its successor is [NetExec](#netexec), which is a drop-in replacement with the same interface (`nxc` instead of `cme`).

**Install:**

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
sudo apt install crackmapexec -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="kerbrute">Kerbrute</h3></summary>

Fast Kerberos pre-auth brute-forcing and username enumeration tool — works without triggering account lockouts when using `userenum`.

**Install:**

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
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="evil-winrm">Evil-WinRM</h3></summary>

WinRM shell for pentesting — provides a PowerShell-like interactive shell over WinRM (port 5985/5986), supporting file upload/download, pass-the-hash, and more.

**Install:**

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
sudo gem install evil-winrm
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="netexec">NetExec</h3></summary>

Network execution tool (successor to CrackMapExec) — tests credentials and executes commands over SMB, WinRM, LDAP, MSSQL, SSH, and more.

**Install:**

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
sudo apt-get -y install netexec
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="username-anarchy">Username-Anarchy</h3></summary>

Generates username permutations from real names — useful for building targeted wordlists against corporate environments.

**Install:**

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
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
chmod +x username-anarchy
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="defaultcreds">DefaultCreds-Cheat-Sheet</h3></summary>

One-stop database of default credentials for hundreds of network devices, applications, and services.

**Install:**

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
pip3 install defaultcreds-cheat-sheet
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="dislocker">Dislocker</h3></summary>

Decrypts BitLocker-encrypted volumes on Linux — enables mounting and reading BitLocker drives from a Linux attack host.

**Install:**

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
sudo apt-get install dislocker -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="krb5-user">Kerberos 5 (krb5-user)</h3></summary>

Kerberos client utilities for Linux — required to perform Kerberos authentication (AS-REP Roasting, ticket requests) from a Linux attack host against AD.

**Install:**

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
sudo apt-get install krb5-user -y
```

</td>
</tr>
</table>

> **NOTE:** During installation, you will be prompted to enter the Kerberos realm (e.g., `DOMAIN.LOCAL`), KDC hostname, and admin server.

</details>

</details>

---

<details>
<summary><h2>🧠 Credential Extraction</h2></summary>

<details>
<summary><h3 id="pypykatz">Pypykatz</h3></summary>

Pure Python implementation of Mimikatz — extracts credentials from Windows memory dumps (LSASS), NTDS.dit, and SAM/SYSTEM hives without needing a Windows host.

**Install:**

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
git clone https://github.com/skelsec/pypykatz.git
cd pypykatz
sudo python3 setup.py install
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="mimipenguin">Mimipenguin</h3></summary>

Linux credential dumper — extracts plaintext passwords from memory for running processes (GNOME Keyring, LightDM, etc.).

**Install:**

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
git clone https://github.com/huntergregal/mimipenguin
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="lazagne">LaZagne</h3></summary>

Credential recovery tool for Windows and Linux — retrieves passwords stored by browsers, mail clients, databases, system components, and password managers.

**Install:**

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
git clone https://github.com/AlessandroZ/LaZagne
cd LaZagne
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="firefox-decrypt">Firefox_Decrypt</h3></summary>

Extracts credentials stored in Mozilla Firefox profiles — works on both Linux and Windows and supports master-password-protected profiles.

**Install:**

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
git clone https://github.com/unode/firefox_decrypt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="decrypt-chrome-passwords">Decrypt-Chrome-Passwords</h3></summary>

Decrypts saved Chrome passwords from the SQLite database using the Windows DPAPI key.

**Install:**

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
git clone https://github.com/ohyicong/decrypt-chrome-passwords.git
cd decrypt-chrome-passwords
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="linikatz">Linikatz</h3></summary>

Linux credential dumper for Active Directory environments — extracts Kerberos tickets, NTLM hashes, and plaintext credentials from Samba, Winbind, and SSSD.

**Install:**

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
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
chmod +x linikatz.sh
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="pcredz">PCredz</h3></summary>

Extracts credentials from live network traffic or PCAP files — captures FTP, HTTP Basic Auth, SMTP, LDAP, Kerberos (AS-REQ), NTLMv1/v2, and more.

**Install:**

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
sudo apt install -y python3-pip libpcap-dev file
sudo pip3 install Cython python-libpcap
git clone https://github.com/lgandx/PCredz.git
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="manspider">MANSPIDER</h3></summary>

SMB spider for hunting sensitive files across network shares — searches file contents and names using regex patterns, supporting multiple credential sets.

**Install:**

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
pip install pipx
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🚇 Network Tunneling & Pivoting</h2></summary>

<details>
<summary><h3 id="chisel">Chisel</h3></summary>

Fast TCP/UDP tunnel over HTTP, secured with SSH — used to create reverse SOCKS proxies and port forwards through firewalls.

**Install:**

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
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gzip -d chisel_1.9.1_linux_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
sudo mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel
```

</td>
</tr>
</table>

> **TIP:** Download the matching Windows binary (`chisel_*_windows_amd64.gz`) and transfer it to your pivot host for the client side.

</details>

---

<details>
<summary><h3 id="rpivot">rpivot</h3></summary>

Reverse SOCKS proxy tool — creates a SOCKS4 proxy through a compromised host back to the attack machine, enabling access to internal networks.

**Install:**

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
git clone https://github.com/klsecservices/rpivot.git
```

</td>
</tr>
</table>

> **NOTE:** rpivot requires Python 2. See [Pyenv](#pyenv) for installing Python 2.7 alongside Python 3.

</details>

---

<details>
<summary><h3 id="dnscat2">dnscat2</h3></summary>

Encrypted command-and-control channel over DNS — exfiltrates data and establishes shells using DNS queries, bypassing most firewalls.

**Install (server — Ruby, on attack host):**

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
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="dnscat2-powershell">dnscat2-powershell</h3></summary>

PowerShell client for dnscat2 — runs the dnscat2 client from a Windows target without requiring any additional binaries.

**Install (on attack host, then transfer to target):**

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
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="ptunnel-ng">ptunnel-ng</h3></summary>

ICMP tunneling tool — encapsulates TCP connections inside ICMP echo requests, bypassing firewalls that allow ICMP but block TCP/UDP.

**Install:**

1. **Install** build dependencies.

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
sudo apt install automake autoconf -y
```

</td>
</tr>
</table>

2. **Clone** and build the project.

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
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng
sudo ./autogen.sh
./configure
make
sudo make install
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="pyenv">Pyenv</h3></summary>

Python version manager — installs and switches between multiple Python versions. Required for tools like rpivot that need Python 2.7.

**Install:**

1. **Install** pyenv via the official installer.

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
curl https://pyenv.run | bash
```

</td>
</tr>
</table>

2. **Add** the following lines to your shell profile (`~/.bashrc` or `~/.zshrc`).

<table width="100%">
<tr>
<td colspan="2"> 📄 <b>~/.bashrc — Shell Profile</b> </td>
</tr>
<tr>
<td>

```bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"
```

</td>
</tr>
</table>

3. **Reload** your shell and install Python 2.7.

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
source ~/.bashrc
pyenv install 2.7.18
pyenv global 2.7.18
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🏛️ Active Directory & Kerberos</h2></summary>

<details>
<summary><h3 id="bloodhound">BloodHound</h3></summary>

AD attack path analysis tool — ingests data about users, groups, computers, and ACLs to visually map exploitable privilege escalation paths across the domain.

**Install (Community Edition via apt):**

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
sudo apt install bloodhound -y
```

</td>
</tr>
</table>

**Initialize the Neo4j database and start BloodHound:**

1. **Start** Neo4j.

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
sudo neo4j start
```

</td>
</tr>
</table>

2. **Open** `http://localhost:7474` in a browser, log in with `neo4j:neo4j`, and set a new password.

3. **Launch** BloodHound.

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
bloodhound
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="bloodhound-py">BloodHound.py</h3></summary>

Python-based BloodHound ingestor built on Impacket — collects AD data remotely from a Linux attack host without requiring a domain-joined machine.

**Install:**

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
pip3 install bloodhound
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="impacket">Impacket Toolkit</h3></summary>

Collection of Python classes and scripts for interacting with network protocols — the backbone of most AD attack tooling. Includes `secretsdump`, `psexec`, `wmiexec`, `GetUserSPNs`, `GetNPUsers`, `ntlmrelayx`, `ticketer`, and more.

**Install (system package — recommended for Kali):**

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
sudo apt install impacket-scripts python3-impacket -y
```

</td>
</tr>
</table>

**Install (from source — for latest version):**

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
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install .
```

</td>
</tr>
</table>

**Key scripts included:**

| Script | Purpose |
| ------ | ------- |
| `secretsdump.py` | Dump SAM, LSA secrets, NTDS.dit remotely |
| `psexec.py` | Semi-interactive shell via SMB |
| `wmiexec.py` | Command execution via WMI |
| `GetUserSPNs.py` | Kerberoasting — retrieve TGS tickets |
| `GetNPUsers.py` | AS-REP Roasting — no pre-auth accounts |
| `ntlmrelayx.py` | NTLM relay attacks |
| `ticketer.py` | Golden/Silver Ticket creation |
| `lookupsid.py` | SID brute-forcing |
| `raiseChild.py` | Child-to-parent domain escalation |
| `mssqlclient.py` | Interactive MSSQL shell |
| `smbserver.py` | Lightweight SMB server for file transfer |
| `rpcdump.py` | RPC endpoint enumeration |

</details>

---

<details>
<summary><h3 id="responder">Responder</h3></summary>

LLMNR, NBT-NS, and MDNS poisoner — captures NetNTLM hashes by responding to broadcast name resolution requests on local networks. Also includes a built-in HTTP/SMB/FTP server for credential capture.

**Install:**

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
sudo apt install responder -y
```

</td>
</tr>
</table>

**Or from source (for latest version):**

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
git clone https://github.com/lgandx/Responder.git
```

</td>
</tr>
</table>

> **WARNING:** Only run Responder on authorized engagements. It poisons broadcast traffic on the entire local subnet.

</details>

---

<details>
<summary><h3 id="adidnsdump">adidnsdump</h3></summary>

Enumerates and dumps all DNS records from an AD-integrated DNS zone — similar to a DNS zone transfer but works via LDAP against Active Directory.

**Install:**

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
pip3 install adidnsdump
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="gpp-decrypt">gpp-decrypt</h3></summary>

Decrypts Group Policy Preferences (GPP) passwords — extracts and decrypts the `cpassword` attribute from `Groups.xml` and other GPP files stored in SYSVOL (CVE-2014-1812).

**Install:**

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
sudo gem install gpp-decrypt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="nopac">noPac.py</h3></summary>

Exploit combining CVE-2021-42278 (SAM name impersonation) and CVE-2021-42287 (PAC confusion) — allows a standard domain user to impersonate a Domain Controller and achieve full domain compromise.

**Install:**

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
git clone https://github.com/Ridter/noPac.git
cd noPac
pip3 install -r requirements.txt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="petitpotam">PetitPotam.py</h3></summary>

PoC exploit for CVE-2021-36942 — coerces Windows hosts into authenticating to an arbitrary server via MS-EFSRPC (`EfsRpcOpenFileRaw`). Used to chain with NTLM relay (ntlmrelayx) for AD CS attacks.

**Install:**

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
git clone https://github.com/topotam/PetitPotam.git
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="printnightmare">CVE-2021-1675.py (PrintNightmare)</h3></summary>

PoC exploit for PrintNightmare — abuses the Windows Print Spooler service to execute arbitrary DLLs with SYSTEM privileges (local privilege escalation and remote code execution).

**Install:**

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
git clone https://github.com/cube0x0/CVE-2021-1675.git
cd CVE-2021-1675
pip3 install impacket
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="pkinittools">PKINITtools</h3></summary>

Collection of Python tools for abusing PKINIT in Kerberos — used for Pass-the-Certificate attacks (ESC8, Shadow Credentials) and Kerberos TGT requests via certificates.

**Install:**

1. **Clone** the repository and create a virtual environment.

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
git clone https://github.com/dirkjanm/PKINITtools.git
cd PKINITtools
python3 -m venv .venv
source .venv/bin/activate
```

</td>
</tr>
</table>

2. **Install** dependencies (note: oscrypto requires the git version).

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
pip3 install -r requirements.txt
pip3 install -I git+https://github.com/wbond/oscrypto.git
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="pywhisker">Pywhisker</h3></summary>

Python implementation of Whisker — manipulates `msDS-KeyCredentialLink` AD attributes to perform Shadow Credentials attacks for TGT retrieval without knowing the account password.

**Install:**

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
pip3 install pywhisker
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🪟 Windows Attack Tools</h2></summary>

_These tools run on Windows machines (attack hosts, pivot hosts, or targets). Installation is typically done by downloading a binary or script via PowerShell._

> **NOTE:** Many of these tools are flagged by Windows Defender and AV solutions. Disable or bypass AV before attempting to run them on a target, or use AMSI bypass techniques.

<details>
<summary><h3 id="mimikatz">Mimikatz</h3></summary>

The definitive Windows credential dumper — extracts plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory. Also supports pass-the-hash, pass-the-ticket, and golden ticket attacks.

**Download (PowerShell on Windows):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/ParrotSec/mimikatz/raw/master/x64/mimikatz.exe" -OutFile "mimikatz.exe"
```

</td>
</tr>
</table>

> **TIP:** Alternatively, transfer a pre-compiled binary from your attack host using SMB or HTTP.

</details>

---

<details>
<summary><h3 id="rubeus">Rubeus</h3></summary>

C# Kerberos abuse toolkit — performs AS-REP Roasting, Kerberoasting, pass-the-ticket, overpass-the-hash, ticket harvesting, and S4U abuse directly from a Windows host.

**Download pre-compiled binary (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" -OutFile "Rubeus.exe"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="powerview">PowerView / SharpView</h3></summary>

PowerShell/C# AD situational awareness tools — enumerate users, groups, GPOs, ACLs, trusts, and sessions. Effectively replace `net*` Windows commands with far richer output.

**Download PowerView (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "PowerView.ps1"
Import-Module .\PowerView.ps1
```

</td>
</tr>
</table>

**Download SharpView (C# binary):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/tevora-threat/SharpView/raw/master/Compiled/SharpView.exe" -OutFile "SharpView.exe"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="sharphound">SharpHound</h3></summary>

C# data collector for BloodHound — enumerates AD objects (users, groups, computers, ACLs, GPOs, sessions) and produces JSON files for ingestion into BloodHound for graph analysis.

**Download (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/SpecterOps/BloodHound-Legacy/raw/master/Collectors/SharpHound.exe" -OutFile "SharpHound.exe"
```

</td>
</tr>
</table>

**Or use the PowerShell version:**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/SpecterOps/BloodHound-Legacy/raw/master/Collectors/SharpHound.ps1" -OutFile "SharpHound.ps1"
Import-Module .\SharpHound.ps1
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="inveigh">Inveigh / InveighZero</h3></summary>

PowerShell and C# network spoofing/poisoning tool — Windows equivalent of Responder. Poisons LLMNR, NBT-NS, and mDNS to capture NetNTLM hashes from the target network.

**Download Inveigh.ps1 (PowerShell version):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1" -OutFile "Inveigh.ps1"
Import-Module .\Inveigh.ps1
```

</td>
</tr>
</table>

**Download InveighZero (C# binary):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/Kevin-Robertson/Inveigh/releases/latest/download/Inveigh.exe" -OutFile "Inveigh.exe"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="domainpasswordspray">DomainPasswordSpray.ps1</h3></summary>

PowerShell password spraying tool — reads the domain's password policy to avoid lockouts and sprays a single password across all domain accounts.

**Download:**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1" -OutFile "DomainPasswordSpray.ps1"
Import-Module .\DomainPasswordSpray.ps1
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="lapstoolkit">LAPSToolkit</h3></summary>

PowerShell toolkit for auditing and abusing Microsoft LAPS (Local Administrator Password Solution) — finds computers with LAPS enabled, identifies who can read LAPS passwords, and retrieves stored passwords.

**Download:**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/master/LAPSToolkit.ps1" -OutFile "LAPSToolkit.ps1"
Import-Module .\LAPSToolkit.ps1
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="snaffler">Snaffler</h3></summary>

Automated credential and sensitive file hunter across SMB shares — searches domain-joined computers for juicy files (credentials, keys, config files) using smart filtering rules.

**Download (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe" -OutFile "Snaffler.exe"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="pingcastle">PingCastle</h3></summary>

AD security auditing tool — generates a risk-scored report of AD misconfigurations, weak policies, and attack paths using a CMMI-based maturity framework.

**Download (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/vletoux/pingcastle/releases/latest/download/PingCastle.zip" -OutFile "PingCastle.zip"
Expand-Archive -Path "PingCastle.zip" -DestinationPath "PingCastle"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="adrecon">ADRecon</h3></summary>

PowerShell AD reconnaissance tool — collects comprehensive AD data (users, groups, computers, GPOs, ACLs, trusts, password policies) and exports it to an Excel workbook with pivot tables for analysis.

**Download:**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/adrecon/ADRecon/master/ADRecon.ps1" -OutFile "ADRecon.ps1"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="group3r">Group3r</h3></summary>

AD Group Policy Object (GPO) auditor — finds GPO misconfigurations and security issues such as plaintext credentials, weak script permissions, and dangerous settings.

**Download (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://github.com/Group3r/Group3r/releases/latest/download/Group3r.exe" -OutFile "Group3r.exe"
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="ad-explorer">Active Directory Explorer</h3></summary>

Sysinternals AD viewer and editor — browse AD objects and attributes in real time, save offline snapshots of the directory, and compare two snapshots to identify changes.

**Download (PowerShell):**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows (Attack Host)</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/AdExplorer.zip" -OutFile "AdExplorer.zip"
Expand-Archive -Path "AdExplorer.zip" -DestinationPath "AdExplorer"
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>📡 Network Analysis</h2></summary>

<details>
<summary><h3 id="wireshark">Wireshark</h3></summary>

The industry-standard packet analyzer — captures and dissects network traffic in real time, supporting hundreds of protocols.

**Install:**

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
sudo apt update && sudo apt install wireshark -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="tesseract-ocr">Tesseract-OCR</h3></summary>

Open-source OCR engine — extracts text from image files. Used alongside PCredz and document parsers for credential hunting in images and scanned PDFs.

**Install:**

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
sudo apt install tesseract-ocr -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="antiword">Antiword</h3></summary>

Converts legacy Microsoft Word `.doc` files to plain text — used for extracting readable content from old Word documents during credential hunts.

**Install:**

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
sudo apt install antiword -y
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>🔧 Utilities</h2></summary>

<details>
<summary><h3 id="cifs-utils">cifs-utils</h3></summary>

Common Internet File System utilities for Linux — required to mount SMB/CIFS shares on Linux attack hosts.

**Install:**

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
sudo apt install cifs-utils -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="pwsafe">PWsafe</h3></summary>

Open-source password manager compatible with the Password Safe format — used during password management exercises and safe database analysis.

**Install:**

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
sudo apt install pwsafe -y
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h3 id="rar">RAR</h3></summary>

Command-line archiver for creating and extracting RAR archives on Linux — used during file compression and transfer exercises.

**Install:**

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
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
tar -xzvf rarlinux-x64-612.tar.gz
cd rar
sudo make install
```

</td>
</tr>
</table>

</details>

</details>

---

_Last updated: 2026-02-28_
