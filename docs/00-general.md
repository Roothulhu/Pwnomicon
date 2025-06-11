# 🤖 General

This module consolidates essential manual commands and quick utility snippets useful for active enumeration, system reconnaissance, and service interaction during a pentest workflow.

---

<details>
<summary><strong>🌐 Get current IP</summary>

Windows
```bash
ipconfig /all | find /i "IPV4"
```

Linux
```bash
hostname -I | awk '{print $1}'
```

</details>

---

<details>
<summary><strong>🚢 Common ports</summary>
</details>

---

<details>
<summary><strong>📋 Wordlists</summary>

```bash
# APIs
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Subdomains and VHOSTS
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/Web-Content/vhosts.txt

# Generic Files and Routes
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
/usr/share/seclists/Discovery/Web-Content/Configuration-Files.txt
/usr/share/seclists/Discovery/Web-Content/Logs.txt

# Specific Technologies
/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.txt
/usr/share/seclists/Discovery/Web-Content/jenkins.txt
/usr/share/seclists/Discovery/Web-Content/cloud-metadata.txt

# Users
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt

# Passwords
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
```

</details>
