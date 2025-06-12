# 🧠 General

This unholy scroll gathers essential one-liners and spectral commands — rites forged to uncover hidden paths to wordlists, summon critical data from the void, or inject precise strings into cursed systems. These are the foundational whispers you’ll return to when navigating the abyss of reconnaissance, enumeration, and interaction with ancient services.

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
<summary><strong>📝 Add host to /etc/hosts/</summary>
  
```bash
echo "<IP> <DOMAIN>" | sudo tee -a /etc/hosts
```
  
</details>

---

<details>
<summary><strong>📁 Folders</summary>
  
```bash
tree .
```
  
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

---

📘 **Next step:** Continue with [FOOTPRINTING](./01-footprinting.md)
