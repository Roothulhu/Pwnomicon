# 🧠 General

This unholy scroll gathers essential one-liners and spectral commands — rites forged to uncover hidden paths to wordlists, summon critical data from the void, or inject precise strings into cursed systems. These are the foundational whispers you’ll return to when navigating the abyss of reconnaissance, enumeration, and interaction with ancient services.

---

<details>
<summary><h2>🌐 Get Network Interfaces</h2></summary>

<details>
<summary><h3>🪟 Windows</h3></summary>

<details>
<summary><h4>PowerShell</h4></summary>

List all IPv4 addresses with interface names (detailed)  

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress
```

List interfaces with IPv4 addresses (filtered, concise)  

```powershell
Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | Select-Object InterfaceAlias, @{n='IPv4';e={$_.IPv4Address.IPAddress}}
```

</details>

<details>
<summary><h4>CMD</h4></summary>

REM Show all network configuration details

```cmd
ipconfig /all
```

REM Show only IPv4 addresses and adapter names

```cmd
ipconfig /all | findstr /R /C:"IPv4 Address" /C:"adapter"
```

</details>

</details>

<details>
<summary><h3>🐧 Linux</h3></summary>

Show all network interfaces and addresses (modern)

```bash
ip addr
```

One-line summary of all interfaces and addresses

```bash
ip -o addr | awk -F ' +|/' '/inet/ {print $2, $4}'
```

One-line summary of IPv4 addresses only

```bash
ip -4 -o addr | awk -F ' +|/' '/inet/ {print $2, $4}'
```

Legacy: Show all interfaces and IPv4 addresses

```bash
ifconfig -a | grep -w inet | awk '{print $1, $2}'
```

</details>

</details>

---

<details>
<summary><h2>🔍 Find</h2></summary>

<details>
<summary><h3>🪟 Windows</h3></summary>

<details>
<summary><h4>PowerShell</h4></summary>

Recursively find files named flag.txt and show full paths

```powershell
Get-ChildItem -Path C:\ -Recurse -Filter "flag.txt" -File -ErrorAction SilentlyContinue | Select-Object FullName
```

</details>

<details>
<summary><h4>CMD</h4></summary>

Recursively search for flag.txt from current directory

```cmd
dir flag.txt /S /P
```

</details>
</details>

<details>
<summary><h3>🐧 Linux</h3></summary>

Recursively find files named flag.txt, suppress errors

```bash
find / -type f -iname flag.txt 2>/dev/null
```

Find files by extension

```bash
for ext in $(echo ".txt .env .xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

Find SSH Keys

```bash
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```

</details>

</details>

---

<details>
<summary><h2>🚢 Common Ports</h2></summary>

| TCP Port | TCP Service                         | UDP Port | UDP Service            |
|----------|--------------------------------------|----------|-------------------------|
| 1        | tcpmux                               | 1        | N/A                     |
| 3        | CompressNET                          | 7        | Echo                    |
| 5        | RJE                                  | 9        | Discard                 |
| 7        | Echo                                 | 17       | QOTD                    |
| 9        | Discard                              | 19       | Chargen                 |
| 11       | SYSTAT                               | 37       | Time                    |
| 13       | Daytime                              | 49       | TACACS                  |
| 17       | QOTD                                 | 53       | DNS                     |
| 18       | Message Send Protocol                | 67       | DHCP Server             |
| 19       | Chargen                              | 68       | DHCP Client             |
| 20       | FTP Data                             | 69       | TFTP                    |
| 21       | FTP Control                          | 111      | RPCbind                 |
| 22       | SSH                                  | 123      | NTP                     |
| 23       | Telnet                               | 135      | MS RPC                  |
| 25       | SMTP                                 | 137      | NetBIOS Name Service    |
| 37       | Time                                 | 138      | NetBIOS Datagram        |
| 39       | RLP                                  | 161      | SNMP                    |
| 42       | WINS Replication                     | 162      | SNMP Trap               |
| 43       | WHOIS                                | 177      | XDMCP                   |
| 49       | TACACS                               | 500      | ISAKMP                  |
| 53       | DNS                                  | 514      | Syslog                  |
| 70       | Gopher                               | 520      | RIP                     |
| 79       | Finger                               | 631      | IPP                     |
| 80       | HTTP                                 | 1434     | MSSQL Monitor           |
| 88       | Kerberos                             | 1645     | RADIUS (alt)            |
| 109      | POP2                                 | 1646     | RADIUS Accounting       |
| 110      | POP3                                 | 1812     | RADIUS                  |
| 111      | RPCbind                              | 1813     | RADIUS Accounting       |
| 113      | Ident                                | 2049     | NFS                     |
| 119      | NNTP                                 | 2222     | DirectAdmin             |
| 123      | NTP                                  | 3306     | MySQL                   |
| 135      | MS RPC                               | 3456     | VAT                     |
| 139      | NetBIOS                              | 3702     | WS-Discovery            |
| 143      | IMAP                                 | 4500     | IPsec NAT-T             |
| 161      | SNMP                                 | 5353     | mDNS                    |
| 179      | BGP                                  | 5060     | SIP                     |
| 194      | IRC                                  | 5355     | LLMNR                   |
| 201      | AppleTalk                            | 6000     | X11                     |
| 220      | IMAP3                                | 10000    | Webmin                  |
| 389      | LDAP                                 | 17185    | Sounds Virtual          |
| 443      | HTTPS                                | 49152    | Windows RPC Dynamic     |
| 445      | SMB                                  |          |                         |
| 464      | Kerberos Change/Set Password         |          |                         |
| 465      | SMTPS                                |          |                         |
| 514      | Shell                                |          |                         |
| 515      | Printer                              |          |                         |
| 543      | Kerberos login                       |          |                         |
| 544      | Kerberos shell                       |          |                         |
| 548      | AFP                                  |          |                         |
| 554      | RTSP                                 |          |                         |
| 587      | SMTP Submission                      |          |                         |
| 631      | IPP                                  |          |                         |
| 636      | LDAPS                                |          |                         |
| 646      | LDP                                  |          |                         |
| 873      | rsync                                |          |                         |
| 990      | FTPS                                 |          |                         |
| 993      | IMAPS                                |          |                         |
| 995      | POP3S                                |          |                         |
| 1025     | Microsoft RPC                        |          |                         |
| 1080     | SOCKS                                |          |                         |
| 1194     | OpenVPN                              |          |                         |
| 1433     | MSSQL                                |          |                         |
| 1434     | MSSQL Monitor                        |          |                         |
| 1521     | Oracle DB                            |          |                         |
| 1723     | PPTP                                 |          |                         |
| 2049     | NFS                                  |          |                         |
| 2082     | cPanel                               |          |                         |
| 2083     | cPanel SSL                           |          |                         |
| 2100     | Oracle XDB                           |          |                         |
| 2483     | Oracle DB Listener                   |          |                         |
| 2484     | Oracle DB Listener SSL               |          |                         |
| 3128     | Squid Proxy                          |          |                         |
| 3306     | MySQL                                |          |                         |
| 3389     | RDP                                  |          |                         |
| 3690     | Subversion                           |          |                         |
| 4444     | Metasploit                           |          |                         |
| 4664     | Google Desktop                       |          |                         |
| 4899     | Radmin                               |          |                         |
| 5000     | UPnP                                 |          |                         |
| 5060     | SIP                                  |          |                         |
| 5432     | PostgreSQL                           |          |                         |
| 5500     | VNC                                  |          |                         |
| 5631     | pcAnywhere                           |          |                         |
| 5900     | VNC                                  |          |                         |
| 6000     | X11                                  |          |                         |
| 6667     | IRC                                  |          |                         |
| 7000     | AFS                                  |          |                         |
| 8000     | HTTP Alt                             |          |                         |
| 8080     | HTTP Proxy                           |          |                         |
| 8443     | HTTPS Alt                            |          |                         |
| 8888     | HTTP Alt                             |          |                         |
| 9100     | Printer                              |          |                         |
| 9999     | Abyss Web Server                     |          |                         |
| 10000    | Webmin                               |          |                         |
| 32768    | Windows RPC                          |          |                         |
| 49152    | Windows RPC Dynamic                  |          |                         |

</details>


---

<details>
<summary><h2>📝 Add host to /etc/hosts/</summary>
  
```bash
echo "<IP> <DOMAIN>" | sudo tee -a /etc/hosts
```
  
</details>

---

<details>
<summary><h2>📁 Folders</summary>
  
```bash
tree .
```
  
</details>

---

<details>
<summary><h2>📋 Wordlists</summary>

Unzip rockyou from SecLists

```bash
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

SecLists

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
