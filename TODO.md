# Pwnomicon Standardization Progress

This file tracks the progress of standardizing all documentation to match [STYLE_GUIDE.md](STYLE_GUIDE.md).

---

## Status Legend

| Symbol | Meaning                                |
| ------ | -------------------------------------- |
| ⬜     | Not started                            |
| 🟡     | In progress (partial)                  |
| ✅     | Completed                              |
| 📝     | Placeholder only (needs content first) |

---

## Files with Content (Need Standardization)

| Status | File                             | Lines | Notes                                    |
| ------ | -------------------------------- | ----- | ---------------------------------------- |
| ✅     | `00-general.md`                  | 1061  | Standardized                             |
| ✅     | `01-footprinting.md`             | 1395  | Standardized                             |
| ✅     | `02-information-gathering.md`    | 759   | Standardized                             |
| ✅     | `03-vulnerability-assessment.md` | 195   | Standardized                             |
| ✅     | `04-file-transfers.md`           | 2250  | Standardized                             |
| ✅     | `05-shells-payloads.md`          | 1848  | Standardized                             |
| ✅     | `06-metasploit-framework.md`     | 3061  | Standardized                             |
| ✅     | `07-password-attacks.md`         | 6991  | Standardized (expanded to ~12,175 lines) |
| ✅     | `08-common-services.md`          | 5766  | Standardized (expanded to ~5,766 lines)  |
| ✅     | `09-pivoting-tunneling.md`       | 4387  | Standardized (expanded to ~4,387 lines)  |

---

## 07-password-attacks.md Breakdown

Due to its size (6991 lines), this file is split into 5 sections for incremental standardization:

| Status | Section | Lines     | h1 Sections Included                                   |
| ------ | ------- | --------- | ------------------------------------------------------ |
| ✅     | Part 1  | 1-1386    | 💡 Introduction, 🔑 Password Cracking Techniques       |
| ✅     | Part 2  | 1387-2705 | 📡 Remote Password Attacks, 🪟 Extracting from Windows |
| ✅     | Part 3  | 2706-3827 | 🐧 Extracting from Linux, 🕸️ Browsers, 🌐 Network      |
| ✅     | Part 4  | 3828-5841 | ↔️ Windows Lateral Movement (PtH, PtT, Pass the Cert)  |
| ✅     | Part 5  | 5842-6991 | 🔐 Password Management, 📝 Practical Example           |

---

## Placeholder Files (Need Content)

| Status | File                                  | Notes      |
| ------ | ------------------------------------- | ---------- |
| 📝     | `11-web-proxies.md`                   | Title only |
| 📝     | `12-web-apps-ffuf.md`                 | Title only |
| 📝     | `13-login-brute-forcing.md`           | Title only |
| 📝     | `14-sql-injection-fundamentals.md`    | Title only |
| 📝     | `15-sqlmap-essentials.md`             | Title only |
| 📝     | `16-xss.md`                           | Title only |
| 📝     | `17-file-inclusion.md`                | Title only |
| 📝     | `18-file-upload-attacks.md`           | Title only |
| 📝     | `19-command-injections.md`            | Title only |
| 📝     | `20-web-attacks.md`                   | Title only |
| 📝     | `21-attacking-common-applications.md` | Title only |
| 📝     | `22-linux-privilege-escalation.md`    | Title only |
| 📝     | `23-windows-privilege-escalation.md`  | Title only |
| 📝     | `24-attacking-enterprise-networks.md` | Title only |

---

## Session Log

Use this section to track progress across sessions.

### Session 11 — 2026-03-23

- ✅ Added **📋 Quick Navigation** index to all 11 docs (00–10)
  - Small files: inline `·`-separated section list
  - Medium files (02, 04, 05): two-column H1 → H2 table
  - Large files (07, 08, 09, 10): chapter table with sections grouped by H1
  - Files 05, 06, 07 had no `---` separator before first `<details>` — added one as part of index insertion

### Session 10 — 2026-03-22

- ✅ Completed Emoji Navigation Pass on `10-active-directory.md`
  - H2 (~18): 🏛️ AD Explained, 💡 Why Care, 📖 Real-World Examples, 📧 Tasking Email, 🏆 Module Assessment, 📋 Assessment Scope, 🔍 External Recon/Initial Enum, ☠️ LLMNR Linux/Windows, 📌 Post-Capture, ⚡ Cracking, 💥 Password Spraying, 📋 Password Policies, 🎯 Target User List, 🐧 Spraying Linux, 🪟 Spraying Windows
  - H3 (~25): 💥 Enum/Attack Techniques, 🎯 Assessment Goals, 🌿 Living Off the Land, 🔍 What/Where Are We Looking, 📖 Example Enum Process, 💀 TTPs, 🔍 Identifying Users/Vulns, ⚠️ Caution Stealth/Noise, 🔍 Next Mission, 📋 Step-by-Step ×2, 🛡️ Remediation LLMNR, 🔍 Detection LLMNR, 🐧 Enum Policy Linux, 🪟 Enum Null Session/Policy Windows, 👤 Enum Policy Unauthenticated, 🔍 Analyzing Policy, 🔑 Method 1 Credentialed, 👤 Method 2 Unauthenticated, 🐧💥💥 Tactics 1-3, ✅ Validating Creds, 🔀 Lateral Movement, 🔍 External Attack Surface
  - H4 (~15): 🔍 Finding Address Spaces, 🌐 DNS, 🔍 Public Data/OSINT, 👂🔍🔍🔍 Steps 1-4, 🔑 Credentialed, 👤 Unauthenticated, 📟 net use, 🔍 ldapsearch, 📟 CMD, ⚡ PowerShell
- ✅ **Emoji Navigation Pass COMPLETE — all 11 files (00–10) done**

### Session 9 — 2026-03-22

- ✅ Completed Emoji Navigation Pass on `09-pivoting-tunneling.md`
  - H2 (~20): 🔄 Pivoting, 🕳️ Tunneling, ↔️ Lateral Movement, 🌐 IP/NICs, 🛣️ Routing, 📡 Protocols/Ports, 🔌 Socat Reverse/Bind, 🪟 plink.exe, 🚇 Sshuttle, 🌐 Rpivot/DNS Tunneling, 🪟 Netsh, 🕳️ Chisel, 🔌 ICMP, 🖥️ SocksOverRDP, 🏆 Steps, 📋 Summary, 📏 Setting Baseline, 👥 People/Processes/Technology, 🌐 From Outside, 🔬 MITRE
  - H3 (~25): 🪟 Windows Example, 🐧 Linux/macOS Example, 🔍🔌✅🔧🔐🔧🔍🔍💣 Steps 1-5/4.1-4.4, 💀 Method 1, 🕳️ Method 2, 🔌🔧🖥️ plink steps 1-3, 🔍🔑🔐🔍🔍🔀🏁💀🔓🔍🔍🔀🏁💥 SA Steps 1-14, 🔍 Perimeter First, 🏠 Internal, 👥⚙️🔧 People/Processes/Technology
  - H4 (7): ⚙️ multi/handler config, 🛣️ Autoroute, 🕳️ SOCKS Proxy, 🔧 proxychains.conf, 🔍 Scan Internal, 🔀 Port Forward, 🖥️ Connect RDP

### Session 8 — 2026-03-22

- ✅ Completed Emoji Navigation Pass on `08-common-services.md`
  - H2 (~25): 🔍 Nmap Scan/scan ×5, ⚠️ Misconfigurations ×3, 💥 Attack Vectors ×2 + Protocol Specific Attacks ×2, 💡 Concept of Attacks, ⚠️ Service Misconfigs, 🔍 Finding Sensitive Info, 📌 Post-Access, 💥 Brute Forcing/FTP Bounce, 🔑 Auth Mechanisms, 🪙 RDP PtH, 🔀 DNS Zone Transfer, 🎯 Domain Takeovers, ☠️ DNS Spoofing/Local Cache, 🔍 Enumeration, ☁️ Cloud Enum, 💥 Password Attacks, 📧 Open Relay, 🏆 Skills Assessment ×3
  - H3 (~35): 📂 File Share Services, 🤝 SMB, ⌨️ CLI Utils, 🔧 Tools/Troubleshooting, 🌐⚙️🔑🎯 1-4 Source/Process/Privs/Dest, 🔑 Auth, ⚙️ Unnecessary Defaults, 🛡️ Preventing Misconfig, 💥 Brute Forcing/RCE/Forced Auth, 🔍 Enum Logged-on Users, 🔓 SAM Hashes, 🪙 PtH, ⚠️ Misconfigs, 🔑 Privileges, 🗄️ MySQL/MSSQL ×2, 👤 Anon Auth, 📂 File Share, 🔌 RPC, 🔍 Enumeration ×2, ☁️ O365 Spray, 💥 Hydra/O365 Spraying, 🔍🔍💥🔑🐚 Skills steps, ✅ Result, 🤝 SMB, 💥 Brute-force
  - H4 (~20): 🖥️ GUI, 📟 CMD DIR/Net Use, ⚡ PS Get-ChildItem/New-PSDrive, 🐧 Linux Mount/SQSH/SQLCMD/MySQL, 🪟 Windows MySQL, 👤 Anon Auth, ⚠️ Misconfig Access Rights, 🔌🔍💥 SQL Steps 1-3 ×2, 🔓 Step 4 Hash, 👤 Step 5 Impersonate, 🔀 Step 6 Linked DBs

### Session 7 — 2026-03-22

- ✅ Completed Emoji Navigation Pass on `07-password-attacks.md` (H2/H3 from prior session + all H4 this session)
  - H4: 🎯 Single, 📖 Dictionary Attack ×2, 🎭 Mask attack, 🪟/🐧 BitLocker mounts, 💀 Dump LSASS, 🔓 Pypykatz, 🔍 OSINT/Enum/LaZagne ×2/findstr, ✍️ Custom usernames, 💥 Brute-force, ⚙️/🔧 Option 1/2, 🪟 Windows Search, 💀 Mimipenguin, tshark numbered subs (🔍🔑📡🔓💡), 🕷️ Snaffler, 🔍 PowerHuntShares, 🕷️ MANSPIDER, 🌐 NetExec, ⚡ Invoke-TheHash SMB, 🔌 Netcat listener, 💥 Command Execution, 🎫 Kerberos/PtT headers ×6, 🔑 OverPass the Hash, PtT from Linux steps 🔍🔑💾🔓⚔️🔄🪟💀, 📏📋⚙️🔐 Password policy, 🎣🔀🔧🔌🏛️ Skills Assessment steps
  - `07-password-attacks.md` Emoji Navigation Pass fully complete

### Session 6 — 2026-03-22

- ✅ Completed `git clone` install-reference sweep across docs/00–09
  - Identified that prior sweep missed `git clone` blocks (treated as non-install)
  - Added new `🐚 Web Shells` section to `TOOLS.md` with Laudanum, Nishang, wwwolf-php-webshell
  - Updated TOOLS.md Table of Contents with new Web Shells category
  - `05-shells-payloads.md`: replaced 3 git clone blocks (Laudanum, Nishang, wwwolf-php-webshell) with `📦 Installation:` references
  - `06-metasploit-framework.md`: replaced Metasploit-Plugins git clone (missed in original sweep) with reference to `#metasploit`

### Session 5 — 2026-02-19

- ✅ Completed `09-pivoting-tunneling.md` (3265 → 4387 lines)
  - Converted all remaining raw code blocks to HTML tables with proper blank-line spacing
  - Socat Bind Shell section: msfvenom bind_tcp, socat listener, msfconsole, MSF bind handler, Meterpreter session
  - plink.exe section: `plink -ssh -D 9050` CMD, `mstsc.exe` CMD
  - sshuttle section: apt-get install, sshuttle run + full output, nmap via sshuttle + full output
  - rpivot section: git clone, pyenv/Python2.7 install, server.py, SOCKS5 sed, scp transfer, client.py + output, firefox proxychains, NTLM proxy variant
  - Netsh section verified already converted in prior session
  - dnscat2 / chisel / ICMP / SocksOverRDP sections verified already converted
  - All 87 conversion targets now complete; `09-pivoting-tunneling.md` fully standardized
  - New context: `🚇 bash — Ubuntu (Pivot)` with `ubuntu@pivot:~$` prompt for pivot host actions

### Session 4 — 2026-02-19

- ✅ Completed `08-common-services.md` Part 5 (Skills Assessment)
  - Converted EASY section 5 (Reverse Shell): MariaDB SELECT INTO OUTFILE, curl whoami, nc listener, nano rev.ps1, rev.ps1 file content, iconv base64, curl powershell, nc reverse shell session
  - Converted all MEDIUM blocks: nmap, dig AXFR, FTP anonymous (port 30021), cat mynotes.txt, hydra FTP, FTP authenticated (port 2121), cat flag.txt
  - Converted all HARD blocks: nmap, smbclient -L + share navigation, Fiona/John/Simon SMB sessions + cat outputs, hydra rdp, sqsh MSSQL interactive session
  - `08-common-services.md` now fully standardized (~5,766 lines)

### Session 3 — 2026-02-18

- ✅ Completed `07-password-attacks.md` Parts 4 & 5 (6991 → ~12,175 lines)
  - Part 4: Converted Linikatz, Pass the Certificate (ESC8), Shadow Credentials sections
  - Part 5: Converted Password Management + full Practical Example walkthrough
  - New table types introduced: `🔧 Ligolo-ng — Console`, `📄 <description> — Output`
  - Mermaid diagram blocks intentionally left as fenced code blocks per STYLE_GUIDE

### Session 2 — 2026-01-24

- ✅ Standardized `05-shells-payloads.md` (924 → 1848 lines)
  - Converted all code blocks to HTML tables
  - Used context-aware table types (⚔️ AttackHost, 🎯 Target, 💣 Metasploit, 📟 CMD, ⚡ PowerShell)
  - Preserved header hierarchy (h1 → h2 → h3 → h4)
- ✅ Standardized `06-metasploit-framework.md` (1383 → 3061 lines)
  - Converted all code blocks to HTML tables
  - Differentiated bash (⚔️ AttackHost) from Metasploit console (💣 Metasploit) and Meterpreter (💣 Meterpreter)
  - Added output sections with proper formatting

### Session 1 — 2025-01-23

- Created `STYLE_GUIDE.md`
- Created `TODO.md`
- ✅ Standardized `03-vulnerability-assessment.md` (57 → 195 lines)
  - Added HTML tables for all commands
  - Added numbered instructions with bold verbs
  - Fixed error: duplicate "Start" → "Stop"
  - Added tool descriptions and notes
- ✅ Standardized `00-general.md` (1023 → 1061 lines)
  - Fixed unclosed `</h2>` tags (4 instances)
  - Changed Ping Sweep from `<h3>` to `<h2>`
  - Converted Meterpreter block to HTML table
  - Converted SecLists paths to HTML table
- ✅ Standardized `01-footprinting.md` (564 → 1395 lines)
  - Changed all `<strong>` headers to `<h2>`
  - Converted all code blocks to HTML tables
  - Used appropriate table types (⚔️ AttackHost, 🎯 Target, 💣 Metasploit, 🟦 PHP)
- ✅ Standardized `02-information-gathering.md` (313 → 759 lines)
  - Converted all code blocks to HTML tables
  - Added numbered steps for tool installation/usage
  - Added output example for nmap scan
- ✅ Standardized `04-file-transfers.md` (1098 → 2250 lines)
  - Removed all `&nbsp;` indentation hacks
  - Converted all code blocks to HTML tables
  - Used context-aware table types (⚔️ AttackHost, 🎯 Target, ⚡ PowerShell, 📟 CMD)
  - Added numbered steps for multi-machine workflows

---

## TOOLS.md — Installation Guide

Tracks which tool installation sections have been written in [`TOOLS.md`](TOOLS.md).
When standardizing a doc that contains a tool install command, replace the install block with a reference link and mark that tool ✅ here.

### Reference link format (from within `docs/`)

```
📦 **Installation:** See [Tool Name](../TOOLS.md#anchor) in the Tools Guide.
```

### Tool Index

| Status | Tool | Anchor | First Referenced In |
| ------ | ---- | ------ | ------------------- |
| ✅ | Nmap | `#nmap` | `02-information-gathering.md` |
| ✅ | Enum4Linux-ng | `#enum4linux-ng` | `01-footprinting.md` |
| ✅ | SSH-Audit | `#ssh-audit` | `01-footprinting.md` |
| ✅ | RDP-Sec-Check | `#rdp-sec-check` | `01-footprinting.md` |
| ✅ | Wafw00f | `#wafw00f` | `02-information-gathering.md` |
| ✅ | Nikto | `#nikto` | `02-information-gathering.md` |
| ✅ | Scrapy | `#scrapy` | `02-information-gathering.md` |
| ✅ | FinalRecon | `#finalrecon` | `02-information-gathering.md` |
| ✅ | ReconSpider | `#reconspider` | `02-information-gathering.md` |
| ✅ | Subbrute | `#subbrute` | `08-common-services.md` |
| ✅ | Nessus | `#nessus` | `03-vulnerability-assessment.md` |
| ✅ | OpenVAS / GVM | `#openvas` | `03-vulnerability-assessment.md` |
| ✅ | Metasploit Framework | `#metasploit` | `06-metasploit-framework.md` |
| ✅ | Kerbrute | `#kerbrute` | `07-password-attacks.md` |
| ✅ | Evil-WinRM | `#evil-winrm` | `07-password-attacks.md` |
| ✅ | NetExec | `#netexec` | `07-password-attacks.md` |
| ✅ | Username-Anarchy | `#username-anarchy` | `07-password-attacks.md` |
| ✅ | DefaultCreds-Cheat-Sheet | `#defaultcreds` | `07-password-attacks.md` |
| ✅ | Dislocker | `#dislocker` | `07-password-attacks.md` |
| ✅ | Kerberos 5 (krb5-user) | `#krb5-user` | `07-password-attacks.md` |
| ✅ | Pypykatz | `#pypykatz` | `07-password-attacks.md` |
| ✅ | Mimipenguin | `#mimipenguin` | `07-password-attacks.md` |
| ✅ | LaZagne | `#lazagne` | `07-password-attacks.md` |
| ✅ | Firefox_Decrypt | `#firefox-decrypt` | `07-password-attacks.md` |
| ✅ | Decrypt-Chrome-Passwords | `#decrypt-chrome-passwords` | `07-password-attacks.md` |
| ✅ | Linikatz | `#linikatz` | `07-password-attacks.md` |
| ✅ | PCredz | `#pcredz` | `07-password-attacks.md` |
| ✅ | MANSPIDER | `#manspider` | `07-password-attacks.md` |
| ✅ | Chisel | `#chisel` | `07-password-attacks.md`, `09-pivoting-tunneling.md` |
| ✅ | rpivot | `#rpivot` | `09-pivoting-tunneling.md` |
| ✅ | dnscat2 | `#dnscat2` | `09-pivoting-tunneling.md` |
| ✅ | dnscat2-powershell | `#dnscat2-powershell` | `09-pivoting-tunneling.md` |
| ✅ | ptunnel-ng | `#ptunnel-ng` | `09-pivoting-tunneling.md` |
| ✅ | Pyenv | `#pyenv` | `09-pivoting-tunneling.md` |
| ✅ | PKINITtools | `#pkinittools` | `07-password-attacks.md` |
| ✅ | Pywhisker | `#pywhisker` | `07-password-attacks.md` |
| ✅ | Wireshark | `#wireshark` | `07-password-attacks.md` |
| ✅ | Tesseract-OCR | `#tesseract-ocr` | `07-password-attacks.md` |
| ✅ | Antiword | `#antiword` | `07-password-attacks.md` |
| ✅ | cifs-utils | `#cifs-utils` | `08-common-services.md` |
| ✅ | PWsafe | `#pwsafe` | `07-password-attacks.md` |
| ✅ | RAR | `#rar` | `06-metasploit-framework.md` |
| ✅ | Laudanum | `#laudanum` | `05-shells-payloads.md` |
| ✅ | Nishang | `#nishang` | `05-shells-payloads.md` |
| ✅ | wwwolf-php-webshell | `#wwwolf-php-webshell` | `05-shells-payloads.md` |
| ✅ | enum4linux | `#enum4linux` | `10-active-directory.md` |
| ✅ | ldap-utils (ldapsearch) | `#ldap-utils` | `10-active-directory.md` |
| ✅ | windapsearch | `#windapsearch` | `10-active-directory.md` |
| ✅ | smbmap | `#smbmap` | `10-active-directory.md` |
| ✅ | Hashcat | `#hashcat` | `10-active-directory.md` |
| ✅ | CrackMapExec (CME) | `#crackmapexec` | `10-active-directory.md` |
| ✅ | BloodHound | `#bloodhound` | `10-active-directory.md` |
| ✅ | BloodHound.py | `#bloodhound-py` | `10-active-directory.md` |
| ✅ | Impacket Toolkit | `#impacket` | `10-active-directory.md` |
| ✅ | Responder | `#responder` | `10-active-directory.md` |
| ✅ | adidnsdump | `#adidnsdump` | `10-active-directory.md` |
| ✅ | gpp-decrypt | `#gpp-decrypt` | `10-active-directory.md` |
| ✅ | noPac.py | `#nopac` | `10-active-directory.md` |
| ✅ | PetitPotam.py | `#petitpotam` | `10-active-directory.md` |
| ✅ | CVE-2021-1675.py (PrintNightmare) | `#printnightmare` | `10-active-directory.md` |
| ✅ | Mimikatz | `#mimikatz` | `10-active-directory.md` |
| ✅ | Rubeus | `#rubeus` | `10-active-directory.md` |
| ✅ | PowerView / SharpView | `#powerview` | `10-active-directory.md` |
| ✅ | SharpHound | `#sharphound` | `10-active-directory.md` |
| ✅ | Inveigh / InveighZero | `#inveigh` | `10-active-directory.md` |
| ✅ | DomainPasswordSpray | `#domainpasswordspray` | `10-active-directory.md` |
| ✅ | LAPSToolkit | `#lapstoolkit` | `10-active-directory.md` |
| ✅ | Snaffler | `#snaffler` | `10-active-directory.md` |
| ✅ | PingCastle | `#pingcastle` | `10-active-directory.md` |
| ✅ | ADRecon | `#adrecon` | `10-active-directory.md` |
| ✅ | Group3r | `#group3r` | `10-active-directory.md` |
| ✅ | Active Directory Explorer | `#ad-explorer` | `10-active-directory.md` |

---

## Install-Reference Sweep — docs/00 through docs/09

Replace every inline tool install block with `📦 **Installation:** See [Tool](../TOOLS.md#anchor)`.
Only replace tools that are in TOOLS.md. Skip utility libs (pyftpdlib, uploadserver, wsgidav) and tools not yet catalogued (ligolo-ng, sshuttle, Laudanum, Nishang, wwwolf-php-webshell).

| Status | File | Tools to replace |
| ------ | ---- | ---------------- |
| ✅ | `01-footprinting.md` | enum4linux-ng, ssh-audit, rdp-sec-check |
| ✅ | `02-information-gathering.md` | nmap, wafw00f, nikto, scrapy, reconspider, finalrecon |
| ✅ | `03-vulnerability-assessment.md` | nessus, openvas |
| ✅ | `04-file-transfers.md` | _(nothing — only utility libs)_ |
| ✅ | `05-shells-payloads.md` | laudanum, nishang, wwwolf-php-webshell (git clone) |
| ✅ | `06-metasploit-framework.md` | metasploit, rar, metasploit-plugins (git clone) |
| ✅ | `07-password-attacks.md` | dislocker, evil-winrm, defaultcreds, pypykatz, username-anarchy (×2), kerbrute, mimipenguin, lazagne, firefox_decrypt, decrypt-chrome-passwords, wireshark, pcredz, tesseract-ocr + antiword, manspider, chisel, linikatz, pkinittools (×2), pywhisker, krb5-user (×2), pwsafe, mimikatz |
| ✅ | `08-common-services.md` | cifs-utils, subbrute |
| ✅ | `09-pivoting-tunneling.md` | rpivot, dnscat2, dnscat2-powershell, chisel, ptunnel-ng |

---

## Emoji Navigation Pass

Two complementary uses — apply both in the same pass per file.

### 1. Header Emojis (H2–H4)

Add a **single meaningful emoji** to `<h2>`–`<h4>` headings that genuinely aid navigation — landmark sections, distinct techniques, warning callouts. Skip generic structural headings ("Steps", "Usage", "Example", "Output", etc.).

**Reference:** `10-active-directory.md` → `<h2>🔬 Methods Used</h2>`, `<h2>🧱 Mitigation Strategies</h2>`, `<h4>⚠️ Crucial Considerations & Warnings</h4>`

### 2. Inline Bold Callout Emojis

Within explanatory paragraphs, add emojis to **bold paragraph labels** that introduce a distinct concept, impact, warning, or remediation block. These act as visual anchors inside dense prose — the reader's eye can jump to `**💥 The Impact**` or `**🛡️ Blue Team Remediation**` without scanning every line.

**Reference:** `10-active-directory.md` lines 4643–4658:
- `**💥 The Impact: \`(Pwn3d!)\`**` — consequence of a successful attack
- `**⚠️ OPSEC Warning: The Noise Factor**` — stealth/detection risk
- `**🛡️ Blue Team Remediation: LAPS**` — defensive countermeasure

**Candidate label types:** Impact, Warning, OPSEC, Tip, Note, Mitigation, Remediation, Requirement, Result, Caution — only where the label introduces a self-contained conceptual block, not decorative use on every bold word.

**Principle (both):** One emoji, thematically meaningful, only where it helps the reader orient at a glance.

| Status | File | Notes |
| ------ | ---- | ----- |
| ✅ | `00-general.md` | H4: ⚡ PowerShell, 📟 CMD (×2 each); bold: 🐧🐧📟⚡💣 Ping Sweep variants, 📂 SecLists Paths |
| ✅ | `01-footprinting.md` | bold: 🐧 Bash, 🔌 Netcat, 🐍 Python, 💣 MSF Payloads, 💀 Meterpreter, 🖥️ Spawn TTY, 💣 MSSQL Ping, 🔀 Port Forwarding, 🔓 Dump Hashes, 🔧 Oracle-Tools, 🧪 Testing ODAT, 🪟 WinRM, ⚙️ WMI, 🔍 RDP Sec Check |
| ✅ | `02-information-gathering.md` | H2: 🔍 Host Discovery, 🎯 Host and Port Scanning; bold: 🌐 A record, 🔢 IPs only, 📧 MX, 🔄 Reverse, 🌐 Net Range, 📋 IP List, 🎯 Top 10 TCP, 📡 Trace, 🔌 Connect, 📶 UDP |
| ✅ | `03-vulnerability-assessment.md` | H2 already complete; bold labels generic — no changes |
| ✅ | `04-file-transfers.md` | H3: ⚡ PS DL/UL, 🤝 SMB DL/UL, 📂 FTP DL/UL, 🔡 Base64, 🌐 Wget, 🔗 Curl, 🐧 Bash tcp, 🔐 SSH/SCP DL+UL, ☁️ Web Upload, 🔄 Alt Transfer, 🐍🐘💎🐪📜🪟 langs, 🔌 nc/ncat, 🐧 Bash/tcp Misc, 📋🗂️🐧 RDP, ⚡ AES ps1, 🔐 Examples, 🛡️ openssl; H4: 👻 Fileless, 🔑 Creds, 🔡 Base64 ×2, 🐍 UploadServer, 🔑 AuthServer |
| ✅ | `05-shells-payloads.md` | H3: 🔌 NC shells ×3, 💣 MSF, 🔨 MSFvenom, 🎯 Infiltrating, 🎬 Walkthrough, 🔀 CMD/PS; H4: 🔍 Enum Win, 💣 Payloads, 🔧 Procedures, 🔑 Exec Perms; bold: 🛡️ AV, 💣 MSF Console, 📟⚡ Use X when, 🐪 Perl, 💎 Ruby, 🔍 Find, 🖥️ Exec, 🔑 Perms/Sudo, ⚙️ Proxy, 🔓 Bypass, 🎯 Tradecraft |
| ✅ | `06-metasploit-framework.md` | H3: 📦 Modules, 💣 Payloads ×2, 🎯 Targets, 🤝 Staged, 🎭 Encoders, 🗄️ DBs, 🔌 Plugins, 🖥️ Sessions, ⚙️ Jobs, 💀 Meterpreter, 📥 Import, 🔨 MSFVenom, 👻 Evasion; H4: 🔍 Search, 🎯 Select, ⚙️ Set, 💥 Exec, 🎯🤝💀 Payload types, 💀 Meter Payload, 🗄️ DB Setup, 🎯 Objectives, 🛠️ Capabilities, 💀 Using Meter, 🎬 Walkthrough, ⬆️ Upgrade, 📋 Manual, 🔨 Creating, 👻 Evasion Tech; bold: 📦🔌📜🔧 MSF dirs, 🤝 Conn Method, ⚠️ Notes, 🔀 BG Methods, 💀×4 + 🔓×2 attack milestones, 🔨🎭 Gen Payload, 🔍 Exploit Suggester, 🎣 Handler, 💥 Execute |
| ✅ | `07-password-attacks.md` | H2: 30 additions; H3: ~45 additions; H4: ~55 additions — all passes complete |
| ✅ | `08-common-services.md` | H2: ~25 additions; H3: ~35 additions; H4: ~20 additions — all passes complete |
| ✅ | `09-pivoting-tunneling.md` | H2: ~20 additions; H3: ~25 additions; H4: 7 additions — all passes complete |
| ✅ | `10-active-directory.md` | H2: ~18 additions; H3: ~25 additions; H4: ~15 additions — all passes complete |

---

## Index Pass

Add a **📋 Quick Navigation** block at the top of each file (after intro, before first `<details>`) showing all H1/H2 sections at a glance.

- Small files (00, 01, 03, 06): inline `·`-separated list
- Medium files (02, 04, 05): two-column table (H1 → H2 list)
- Large files (07, 08, 09, 10): chapter table (H1 chapter → H2 sections)

| Status | File |
| ------ | ---- |
| ✅ | `00-general.md` |
| ✅ | `01-footprinting.md` |
| ✅ | `02-information-gathering.md` |
| ✅ | `03-vulnerability-assessment.md` |
| ✅ | `04-file-transfers.md` |
| ✅ | `05-shells-payloads.md` |
| ✅ | `06-metasploit-framework.md` |
| ✅ | `07-password-attacks.md` |
| ✅ | `08-common-services.md` |
| ✅ | `09-pivoting-tunneling.md` |
| ✅ | `10-active-directory.md` |

---

## Notes

- **Reference file:** `10-active-directory.md` has the most up-to-date style (section emojis on H2+)
- **Tools guide:** `TOOLS.md` centralizes all installation commands — add `📦 **Installation:**` references when standardizing future docs
- **Largest files:** `07-password-attacks.md` (~12,175 lines), `08-common-services.md` (~5,766 lines)
- **Strategy:** Work one file at a time, commit after each completion
