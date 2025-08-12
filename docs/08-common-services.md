# 🛠️ Attacking Common Services  
*In the vast networked domains, familiar services stand as both guardians and unwitting gateways to the abyss. This module guides the adept through the ritual of enumerating and probing these common sentinels, unveiling hidden weaknesses and ancient vulnerabilities ripe for exploitation.*

> *“Every open port is a whisper in the dark, waiting to be answered.”*

---

<details>
<summary><h1>📢 Introduction</h1></summary>

Vulnerabilities are often discovered by individuals who deeply understand a technology, protocol, or service. As we progress in this field, we will encounter a variety of services to interact with, requiring us to **continuously adapt and learn new technologies**.

To successfully attack a service, we must understand **its purpose, how to interact with it, which tools are available, and the potential actions we can perform**.

This section will explore **common services** and demonstrate practical ways to interact with them effectively.

<details>
<summary><h2>Interacting with Common Services</h2></summary>

<details>
<summary><h3>File Share Services</h3></summary>

A file-sharing service is a system that facilitates, manages, and monitors the transfer of computer files. Historically, organizations relied primarily on internal file-sharing protocols such as **SMB**, **NFS**, **FTP**, **TFTP**, and **SFTP**. However, with the widespread adoption of cloud technologies, many companies now also use **third-party cloud-based** solutions like **Dropbox**, **Google Drive**, **OneDrive**, **SharePoint**, and cloud storage services such as **AWS S3**, **Azure Blob Storage**, and **Google Cloud Storage**.

In practice, we will often encounter a hybrid environment where both internal and external file-sharing systems are in use. For example, a server may host internal SMB shares while also synchronizing data with cloud storage.

This section will focus primarily on **internal file-sharing services**, although the same principles can apply to cloud storage solutions that are synced locally to servers and workstations.

</details>

<details>
<summary><h3>Server Message Block (SMB)</h3></summary>

**SMB** is a network file-sharing protocol most commonly used in **Windows environments**. It enables users and applications to read, write, and manage files on remote servers as if they were local. In a Windows network, it is common to find **shared folders** accessible over SMB, often used for collaboration or centralized file storage.

We can interact with SMB shares through:
* **Graphical User Interface (GUI)** – e.g., Windows File Explorer.
* **Command-Line Interface (CLI)** – e.g., `net use`, `dir`, or PowerShell commands in Windows; `smbclient` in Linux.
* **Specialized tools** – e.g., Impacket scripts, CrackMapExec, enum4linux.

The following sections will outline common methods for accessing and interacting with SMB from both Windows and Linux systems.

<details>
<summary><h3>Windows</h3></summary>

<details>
<summary><h4>GUI Method</h4></summary>

**Step 1: Open the Run Dialog Box**

Press `WINKEY` + `R` on your keyboard.

**Step 2: Enter the SMB Share Path**

In the Run dialog box, type the file share location in the following format:

```cmd
\\<IP>\<SHARE_NAME>
```

**Step 3: Authenticate if required**

If prompted, enter valid username and password credentials for the remote system.

**Step 4: Browse the Share**

Once connected, you can view, copy, edit, or delete files according to your permissions.

</details>

<details>
<summary><h4>Windows CMD - DIR</h4></summary>

The command dir displays a list of a directory's files and subdirectories.

**Run the `dir` command on the share**

```cmd
dir  \\<IP>\<SHARE_NAME>
```

**Example Output:**

```cmd
C:\tom> dir \\192.168.220.129\Finance\

Volume in drive \\192.168.220.129\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\192.168.220.129\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```

</details>

<details>
<summary><h4>Windows CMD - Net Use</h4></summary>


**OPTION 1 > Step 1: Use `net use` to connect to the share**

```cmd
net use n: \\<IP>\<SHARE_NAME>
```

**OPTION 2 > Step 1: Use `net use` and provide a username and password to authenticate to the share**

```cmd
net use n: \\<IP>\<SHARE_NAME> /user:<USER> <PASSWORD>
```

With the shared folder mapped as the `n` drive, we can execute Windows commands as if this shared folder is on our local computer. Let's find how many files the shared folder and its subdirectories contain.

**Step 2: Find how many files the shared folder and its subdirectories contain.**

```cmd
dir n: /a-d /s /b | find /c ":\"
```

You can refer to the [GENERAL](./00-general.md) module to find different ways to explore and list files.

</details>

<details>
<summary><h4>Windows PowerShell - Get-ChildItem</h4></summary>

**Run the `Get-ChildItem` command on the share**

```powershell
Get-ChildItem \\<IP>\<SHARE_NAME>
```

**Example Output:**

```powershell
# PS C:\tom> Get-ChildItem \\192.168.220.129\Finance\

#     Directory: \\192.168.220.129\Finance

# Mode                 LastWriteTime         Length Name
# ----                 -------------         ------ ----
# d-----         2/23/2022   3:27 PM                Contracts
```

</details>

<details>
<summary><h4>Windows PowerShell - New-PSDrive</h4></summary>

**OPTION 1 > Step 1: Map the shared folder to a drive letter using `New-PSDrive`**

```powershell
New-PSDrive -Name "N" -Root "\\<IP>\<SHARE_NAME>" -PSProvider "FileSystem"
```

**OPTION 2 > Step 1: Provide a username and password with Powershell to map the shared folder to a drive letter using `New-PSDrive`**

```powershell
$username = '<USER>'
$password = '<PASWORD>'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\<IP>\<SHARE_NAME>" -PSProvider "FileSystem" -Credential $cred
```

**Example Output:**

```powershell
# Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
# ----           ---------     --------- --------      ----                                               ---------------
# N                                      FileSystem    \\192.168.220.129\Finance
```

**Step 2: Find how many files the shared folder and its subdirectories contain.**

```powershell
N:
(Get-ChildItem -File -Recurse | Measure-Object).Count
```

</details>

</details>

<details>
<summary><h3>Linux</h3></summary>

</details>

</details>

</details>

</details>

---

<details>
<summary><h1>🎯 Protocol Specific Attacks</h1></summary>

<details>
<summary><h2>The Concept of Attacks</h2></summary>

</details>

<details>
<summary><h2>Service Misconfigurations</h2></summary>

</details>

<details>
<summary><h2>Finding Senitive Information</h2></summary>

</details>

</details>

---

<details>
<summary><h1>📄 FTP</h1></summary>

<details>
<summary><h2>Attacking FTP</h2></summary>

</details>

<details>
<summary><h2>Latest FTP Vulnerabilities</h2></summary>

</details>

</details>

---

<details>
<summary><h1>🗃️ SMB</h1></summary>

<details>
<summary><h2>Attacking FTP</h2></summary>

</details>

<details>
<summary><h2>Latest FTP Vulnerabilities</h2></summary>

</details>

</details>

---

<details>
<summary><h1>🛢️ SQL Databases</h1></summary>

<details>
<summary><h2>Attacking SQL Databases</h2></summary>

</details>

<details>
<summary><h2>Latest SQL Vulnerabilities</h2></summary>

</details>

</details>

---

<details>
<summary><h1>🖧 RDP</h1></summary>

<details>
<summary><h2>Attacking RDP</h2></summary>

</details>

<details>
<summary><h2>Latest RDP Vulnerabilities</h2></summary>

</details>

</details>

---

<details>
<summary><h1>🌐 DNS</h1></summary>

<details>
<summary><h2>Attacking DNS</h2></summary>

</details>

<details>
<summary><h2>Latest DNS Vulnerabilities</h2></summary>

</details>

</details>

---

<details>
<summary><h1>📨 SMTP</h1></summary>

<details>
<summary><h2>Attacking Email</h2></summary>

</details>

<details>
<summary><h2>Latest Email Service Vulnerabilities</h2></summary>

</details>

</details>

---

<details>
<summary><h1>🛠️ Skills Assessment</h1></summary>

<details>
<summary><h2>Attacking Common Services (EASY)</h2></summary>

</details>

<details>
<summary><h2>Attacking Common Services (MEDIUM)</h2></summary>

</details>

<details>
<summary><h2>Attacking Common Services (HARD)</h2></summary>

</details>

</details>

---

📘 **Next step:** Continue with [PIVOTING-TUNNELING](./09-pivoting-tunneling.md)