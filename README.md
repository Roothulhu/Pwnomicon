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
| 00 | [General](./docs/00-general.md)                                             | Foundational notes, environment setup, and methodologies used throughout the assessment process.     |
| 01 | [Footprinting](./docs/01-footprinting.md)                                   | External information gathering techniques focused on identifying targets and exposed infrastructure. |
| 02 | [Information Gathering - Web Edition](./docs/02-information-gathering.md)   | Reconnaissance techniques targeting web assets, including domain mapping and web fingerprinting.     |
| 03 | [Vulnerability Assessment](./docs/03-vulnerability-assessment.md)           | Detection and analysis of system and application vulnerabilities using manual and automated methods. |
| 04 | [File Transfers](./docs/04-file-transfers.md)                               | Procedures for sending and receiving files across different systems using various protocols.         |
| 05 | [Shells & Payloads](./docs/05-shells-payloads.md)                           | Techniques to obtain interactive shells and generate payloads for remote access.                     |
| 06 | [Metasploit Framework](./docs/06-metasploit-framework.md)                   | Use of the Metasploit Framework for exploitation, post-exploitation, and auxiliary functions.        |
| 07 | [Password Attacks](./docs/07-password-attacks.md)                           | Methods for discovering and cracking passwords via brute force, spraying, or hash analysis.          |
| 08 | [Attacking Common Services](./docs/08-common-services.md)                   | Service-specific enumeration and exploitation of commonly exposed network services.                  |
| 09 | [Pivoting & Tunneling](./docs/09-pivoting-tunneling.md)                     | Accessing internal networks through compromised hosts using port forwarding and tunneling.           |
| 10 | [Active Directory](./docs/10-active-directory.md)                           | Enumeration and exploitation of AD environments through trust abuse and misconfigurations.           |
| 11 | [Web Proxies](./docs/11-web-proxies.md)                                     | Use of web interception tools to inspect, modify, and replay HTTP/S requests.                        |
| 12 | [Attacking Web Applications with Ffuf](./docs/12-web-apps-ffuf.md)          | Directory and parameter fuzzing using Ffuf for hidden content discovery.                             |
| 13 | [Login Brute Forcing](./docs/13-login-brute-forcing.md)                     | Automated attacks targeting authentication portals using wordlists and password guessing.            |
| 14 | [SQL Injection Fundamentals](./docs/14-sql-injection-fundamentals.md)       | Manual techniques to detect and exploit SQL injection flaws in web applications.                     |
| 15 | [SQLMap Essentials](./docs/15-sqlmap-essentials.md)                         | Automating SQL injection exploitation and data extraction using SQLMap.                              |
| 16 | [Cross-Site Scripting (XSS)](./docs/16-xss.md)                              | Identification and exploitation of XSS vulnerabilities to execute JavaScript in browsers.            |
| 17 | [File Inclusion](./docs/17-file-inclusion.md)                               | Exploiting Local and Remote File Inclusion vulnerabilities to access or execute files.               |
| 18 | [File Upload Attacks](./docs/18-file-upload-attacks.md)                     | Exploiting insecure file upload functionalities to gain code execution or data access.               |
| 19 | [Command Injections](./docs/19-command-injections.md)                       | Exploiting input validation flaws to execute arbitrary commands on the system.                       |
| 20 | [Web Attacks](./docs/20-web-attacks.md)                                     | Overview of various web attack vectors including SSRF, IDOR, and open redirects.                     |
| 21 | [Attacking Common Applications](./docs/21-attacking-common-applications.md) | Vulnerability analysis and exploitation of widely used applications and CMS platforms.               |
| 22 | [Linux Privilege Escalation](./docs/22-linux-privilege-escalation.md)       | Exploiting common Linux misconfigurations to escalate privileges from user to root.                  |
| 23 | [Windows Privilege Escalation](./docs/23-windows-privilege-escalation.md)   | Techniques for elevating privileges on Windows hosts using service abuse and credential access.      |
| 24 | [Attacking Enterprise Networks](./docs/24-attacking-enterprise-networks.md) | Complex network attack strategies for compromising multi-host enterprise infrastructures.            |

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
