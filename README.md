<h1 align="center">📜🐙 The Pwnomicon 🐙📜</h1>
<p align="center"><strong>
A forbidden repository of arcane hacking knowledge for OSCP, CPTS and red team practitioners — where ancient exploits whisper to those who dare to <code>sudo</code>
</strong></p>

> *"Containing eldritch one-liners that would make Cthulhu himself drop his shell (reverse or otherwise)"*  

## 🔮 What This Unholy Tome Contains  
- **🕵️‍♂️ Reconnaissance Spells** - `nmap` incantations to map forgotten networks  
- **💀 Privilege Escalation Rituals** - From lowly mortal to `root` elder god  
- **📜 Exam Forbidden Knowledge** - OSCP/CPTS/HackTheBox dark arts  
- **⏳ Time-Defying Cheat Sheets** - Because sanity is temporary, shells are forever  

## 🌌 Why This Grimoire?
- Battle-tested in CTFs and real-world engagements
- OSCP-aligned workflows to conquer certification trials
- Constantly evolving like the Great Old Ones themselves

---

## 📂 Repository Structure (The Forbidden Archives)  
*"Where ancient hacking knowledge is cataloged in cursed markdown scrolls"*  

### 🗃️ The Black Library Sections:

| #  | Topic | Description |  
|----|-------|-------------|  
| 00 | [General](./docs/00-general.md) | Core concepts, environment setup, methodology overview, and general notes for the full process. |  
| 01 | [Footprinting](./docs/01-footprinting.md) | External reconnaissance techniques such as Shodan enumeration, DNS analysis, CIDR/IP range identification, and service mapping. |  
| 02 | [Information Gathering - Web Edition](./docs/02-information-gathering.md) | Web-based recon: WHOIS lookups, subdomain enumeration, DNS analysis, service fingerprinting (e.g. Wafw00f, Nikto), and crawling. |  
| 03 | [Vulnerability Assessment](./docs/03-vulnerability-assessment.md) | Identifying, analyzing, and validating vulnerabilities through automated and manual scanning techniques. |  
| 04 | [File Transfers](./docs/04-file-transfers.md) | Techniques for transferring files between machines using FTP, SMB, HTTP, and other protocols. |  
| 05 | [Shells & Payloads](./docs/05-shells-payloads.md) | Methods for gaining remote access, including reverse shells, bind shells, and custom payload creation with tools like msfvenom. |  
| 06 | [Metasploit Framework](./docs/06-metasploit-framework.md) | Exploitation and post-exploitation using Metasploit modules, payloads, and auxiliary tools. |  
| 07 | [Password Attacks](./docs/07-password-attacks.md) | Techniques like brute-force attacks, password spraying, and hash cracking using tools like Hydra and John the Ripper. |  
| 08 | [Attacking Common Services](./docs/08-common-services.md) | Exploiting misconfigurations and vulnerabilities in services like FTP, SSH, SMB, and RDP. |  
| 09 | [Pivoting & Tunneling](./docs/09-pivoting-tunneling.md) | Methods for lateral movement and internal network access using port forwarding, proxying, and tunneling. |  
| 10 | [Active Directory](./docs/10-active-directory.md) | Attacks against AD environments: enumeration, Kerberos exploitation, and privilege escalation. |  
| 11 | [Web Proxies](./docs/11-web-proxies.md) | Using Burp Suite, OWASP ZAP, and manual proxy techniques for traffic inspection and manipulation. |  
| 12 | [Attacking Web Applications with Ffuf](./docs/12-web-apps-ffuf.md) | Web content discovery using Ffuf for fuzzing endpoints, parameters, and file paths. |  
| 13 | [Login Brute Forcing](./docs/13-login-brute-forcing.md) | Automated brute-force attacks against web login forms using common tools and techniques. |  
| 14 | [SQL Injection Fundamentals](./docs/14-sql-injection-fundamentals.md) | Manual detection and exploitation of SQL Injection vulnerabilities. |  
| 15 | [SQLMap Essentials](./docs/15-sqlmap-essentials.md) | Automated SQLi exploitation using SQLMap, including DB enumeration and data extraction. |  
| 16 | [Cross-Site Scripting (XSS)](./docs/16-xss.md) | Identifying and exploiting XSS vulnerabilities (reflected, stored, DOM-based). |  
| 17 | [File Inclusion](./docs/17-file-inclusion.md) | Exploiting LFI and RFI vulnerabilities to read files, execute code, or gain shell access. |  
| 18 | [File Upload Attacks](./docs/18-file-upload-attacks.md) | Bypassing filters and protections to upload malicious files (e.g., web shells). |  
| 19 | [Command Injections](./docs/19-command-injections.md) | Executing system commands via vulnerable web input fields and bypassing input sanitization. |  
| 20 | [Web Attacks](./docs/20-web-attacks.md) | Collection of common web application attacks beyond injection (e.g., IDOR, SSRF, open redirect). |  
| 21 | [Attacking Common Applications](./docs/21-attacking-common-applications.md) | Exploiting software like CMSs (WordPress, Joomla), email clients, and office tools. |  
| 22 | [Linux Privilege Escalation](./docs/22-linux-privilege-escalation.md) | Methods to escalate privileges on Linux systems, including SUID, cronjobs, and misconfigurations. |  
| 23 | [Windows Privilege Escalation](./docs/23-windows-privilege-escalation.md) | Techniques to gain administrative access on Windows, using token manipulation, services, and misconfigurations. |  
| 24 | [Attacking Enterprise Networks](./docs/24-attacking-enterprise-networks.md) | Advanced techniques for compromising corporate environments: VPN abuse, trust relationships, and multi-host attacks. |

---

## 🛠️ Quick Start  

**1️⃣ SUMMONING RITUAL (CLONE)**
   ```bash
   # Speak the incantation to manifest the tome:  
   git clone https://github.com/RafaHdzCh/Pwnomicon.git  
   cd Pwnomicon
   ```
**2️⃣ NAVIGATING THE BLACK LIBRARY**  
   Scrolls: Each .md file contains forbidden knowledge:
   
**3️⃣ SCRYING FOR KNOWLEDGE (SEARCH)** 
   ```bash 
   grep -Ri "hydra" docs/  
   grep -Ri "rockyou.txt" docs/
   ```
**4️⃣ SYNCHRONIZING WITH THE VOID (UPDATE)**  
   ```bash 
   git pull
   ```

---

## 📜 Join the Cult of Knowledge  
*"The Pwnomicon grows stronger with each acolyte's contribution..."*  

### 🔮 How to Summon Your Dark Arts:  
- **📜 Scroll Corrections**: Found a corrupted incantation? Open an [Issue](https://github.com/RafaHdzCh/Pwnomicon/issues) to purge the corruption.  
- **✍️ Forbidden Edits**: Wield your [Pull Request](https://github.com/RafaHdzCh/Pwnomicon/pulls) to inscribe new spells.  
- **🌌 Request Tomes**: Seeking knowledge not yet uncovered? Summon a [Discussion](https://github.com/RafaHdzCh/Pwnomicon/discussions)!  

---

### ⚠️ The Elder Sign (Terms of Use):  
- **Sanctified Testing Only**: These arts are for sworn pentesters and certified scholars.  
- **The First Law**: Thou shalt not pwn without consent (written in blood, preferably).  

> "With great `sudo` comes great responsibility" - Uncle Ben (probably)  

*"The Old Ones watch... and so does your ISP."*  
