
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

Target Specification

```bash
set RHOSTS <TARGET IP>
```  

Permanent Target Specification

```bash
setg RHOSTS <TARGET IP>
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
<summary><h3>Targets</h3></summary>

Text

</details>

<details>
<summary><h3>Payloads</h3></summary>

Text

</details>

<details>
<summary><h3>Encoders</h3></summary>

Text

</details>

<details>
<summary><h3>Databases</h3></summary>

Text

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
