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
| ✅ | `05-shells-payloads.md` | _(nothing — web shells not in TOOLS.md)_ |
| ✅ | `06-metasploit-framework.md` | metasploit, rar |
| ✅ | `07-password-attacks.md` | dislocker, evil-winrm, defaultcreds, pypykatz, username-anarchy (×2), kerbrute, mimipenguin, lazagne, firefox_decrypt, decrypt-chrome-passwords, wireshark, pcredz, tesseract-ocr + antiword, manspider, chisel, linikatz, pkinittools (×2), pywhisker, krb5-user (×2), pwsafe, mimikatz |
| ✅ | `08-common-services.md` | cifs-utils, subbrute |
| ✅ | `09-pivoting-tunneling.md` | rpivot, dnscat2, dnscat2-powershell, chisel, ptunnel-ng |

---

## Notes

- **Reference file:** `09-pivoting-tunneling.md` has the most up-to-date style (fully standardized)
- **Tools guide:** `TOOLS.md` centralizes all installation commands — add `📦 **Installation:**` references when standardizing future docs
- **Largest files:** `07-password-attacks.md` (~12,175 lines), `08-common-services.md` (~5,766 lines)
- **Strategy:** Work one file at a time, commit after each completion
