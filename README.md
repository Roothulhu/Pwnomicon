# 🚀 Pentest Notes  
**A battle-tested collection of offensive security techniques, tools, and methodologies for penetration testers and red teamers.**  

Designed to cover *every possible scenario* for certifications like **OSCP**, **CPTS**, and similar practical exams, this notebook provides:  
- **🛠️ Ready-to-use commands** (no fluff, just actionable code)  
- **📦 Curated tool references** (from reconnaissance to post-exploitation)  
- **🎯 Exam-focused workflows** (phases aligned with HTB/OSCP labs)  
- **⏱️ Time-savers** (pre-built cheat sheets for common pitfalls)  
 
---

## 📂 Repository Structure  
Each module is organized into markdown files for quick reference:

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

1. **Clone the repository**
   ```bash
   Download the repo to have all modules available locally:  
   git clone https://github.com/RafaHdzCh/pentest-notes.git  
   cd pentest-notes
   ```
2. **Browse modules**  
   Each `.md` file contains commands and wordlists for a specific pentesting phase.
3. **Search commands or tools**  
   Use `grep` to quickly find commands, tools, or paths across modules:
   ```bash 
   grep -Ri "hydra" docs/  
   grep -Ri "rockyou.txt" docs/
   ```
4. **Stay up to date**  
   If you already cloned the repo, update it with:
   ```bash 
   git pull
   ```

---

## 📌 Contribute  
Contributions are welcome! Here's how you can help:  

- **Report issues**: Found a typo or outdated command? Open an [Issue](https://github.com/RafaHdzCh/pentest-notes/issues).  
- **Improve content**: Submit a [Pull Request](https://github.com/RafaHdzCh/pentest-notes/pulls) with your enhancements.  
- **Suggest topics**: Missing a critical technique? Let’s discuss it!  

---

- **Use responsibly**: All content is for educational and authorized penetration testing only.  
- **Ethical hacking**: Always obtain proper permissions before testing.  

> ⚠️ **Disclaimer**: The maintainers are not responsible for misuse.  
