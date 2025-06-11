# 🚀 Pentest Notes  
*A curated collection of offensive security techniques, tools, and methodologies for penetration testers and red teamers.*  

---

## 📂 Repository Structure  
Each module is organized into markdown files for quick reference:  

| File | Topic | Description |  
|------|-------|-------------|  
| [`00-general.md`](./docs/00-general.md) | **General** | Core concepts, setup, and workflow |  
| [`01-footprinting.md`](./docs/01-footprinting.md) | **Footprinting** | Target reconnaissance (Shodan, DNS, CIDR, service scanning) |  
| [`02-information-gathering.md`](./docs/02-information-gathering.md) | **Information Gathering - Web Edition** | WHOIS, subdomains, DNS, fingerprinting (Wafw00f, Nikto), crawling |  
| [`03-vulnerability-assessment.md`](./docs/03-vulnerability-assessment.md) | **Vulnerability Assessment** | Scanning, analysis, and vulnerability validation |  
| [`04-file-transfers.md`](./docs/04-file-transfers.md) | **File Transfers** | Data exfiltration techniques (FTP, SMB, HTTP, etc.) |  
| [`05-shells-payloads.md`](./docs/05-shells-payloads.md) | **Shells & Payloads** | Reverse shells, Meterpreter, and payload crafting |  
| [`06-metasploit-framework.md`](./docs/06-metasploit-framework.md) | **Metasploit Framework** | Modules, exploits, and post-exploitation |  
| [`07-password-attacks.md`](./docs/07-password-attacks.md) | **Password Attacks** | Brute-forcing, hash cracking, and credential spraying |  
| [`08-common-services.md`](./docs/08-common-services.md) | **Attacking Common Services** | FTP, SSH, SMB, RDP, etc. |  
| [`09-pivoting-tunneling.md`](./docs/09-pivoting-tunneling.md) | **Pivoting & Tunneling** | Port forwarding, SOCKS proxies, and lateral movement |  
| [`10-active-directory.md`](./docs/10-active-directory.md) | **Active Directory** | Enumeration, Kerberos attacks, and privilege escalation |  
| [`11-web-proxies.md`](./docs/11-web-proxies.md) | **Web Proxies** | Burp Suite, OWASP ZAP, and manual testing |  
| [`12-web-applications.md`](./docs/12-web-applications.md) | **Web Applications** | Ffuf, SQLi, XSS, file inclusion, uploads, and command injection |  
| [`13-linux-privesc.md`](./docs/13-linux-privesc.md) | **Linux PrivEsc** | Kernel exploits, misconfigurations, and sudo abuse |  
| [`14-windows-privesc.md`](./docs/14-windows-privesc.md) | **Windows PrivEsc** | Token impersonation, service abuses, and registry exploits |  
| [`15-documentation.md`](./docs/15-documentation.md) | **Documentation & Reporting** | Templates, findings, and executive summaries |  
| [`16-enterprise-networks.md`](./docs/16-enterprise-networks.md) | **Enterprise Networks** | Advanced tactics for corporate environments |  

---

## 🔥 Key Features  
- **Hands-on Commands**: Ready-to-use snippets for tools like `nmap`, `gobuster`, `ffuf`, and `Metasploit`.  
- **Service-Specific Tactics**: FTP, SMB, SQL, SSH, RDP, and more.  
- **Web App Focus**: Subdomain brute-forcing, SQLi, XSS, file uploads, and proxies.  
- **PrivEsc**: Linux/Windows privilege escalation checklists.  
- **Reporting**: Templates and best practices for documentation.  

---

## 🛠️ Quick Start  
1. Clone the repo:  
   ```bash
   git clone https://github.com/RafaHdzCh/pentest-notes.git

   ## 📌 Contribute  
Contributions are welcome! Here's how you can help:  

- **Report issues**: Found a typo or outdated command? Open an [Issue](https://github.com/RafaHdzCh/pentest-notes/issues).  
- **Improve content**: Submit a [Pull Request](https://github.com/RafaHdzCh/pentest-notes/pulls) with your enhancements.  
- **Suggest topics**: Missing a critical technique? Let’s discuss it!  

---

- **Use responsibly**: All content is for educational and authorized penetration testing only.  
- **Ethical hacking**: Always obtain proper permissions before testing.  

> ⚠️ **Disclaimer**: The maintainers are not responsible for misuse.  
