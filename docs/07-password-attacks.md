# 🔐 Password Attacks  
*Passwords remain the fragile seals guarding the gateways of corporate realms. When these wards are weak or neglected, the shadows may crack them open with ease. This module unveils the secrets of password storage, retrieval, and the arcane art of cracking or leveraging hashes—guiding the seeker through the labyrinth of authentication’s frailties.*

> *“Even the strongest lock may yield to the patient whisper of ancient incantations.”*

<details>
<summary><h1>Introduction</h1></summary>

Passwords are commonly hashed when stored, in order to provide some protection in the event they fall into the hands of an attacker.

Hash functions are cryptographically designed to be one-way operations, making it computationally infeasible to derive the original input from its hashed output. When malicious actors attempt to reverse this process, it constitutes password cracking. Common methodologies include:

1. Rainbow Table Attacks

    * Leveraging precomputed hash chains for rapid lookups

2. Dictionary Attacks

    * Testing known wordlists and common password variations

3. Brute-Force Attacks

    * Systematic trial of all possible character combinations (typically last-resort)


<details>
<summary><h2>Generate a hash</h2></summary>

**MD5**

```bash
echo -n password123! | md5sum

# b7e283a09511d95d6eac86e39e7942c0
```

**SHA1**

```bash
echo -n "password123!" | sha1sum

# addbd3aa5619f2932733104eb8ceef08f6fd2693
```

**SHA256**

```bash
echo -n password123! | sha256sum

# 5751a44782594819e4cb8aa27c2c9d87a420af82bc6a5a05bc7f19c3bb00452b
```

**SHA512**

```bash
echo -n "password123!" | sha512sum

# 7d66f28d648ca474e357d78e9fbdeb9bbdb46e1603d4ec63f7affe217e6400f3f3211e6e4e1b29dc10617417e502b19c813ced4cec07360e7e3151c290388176
```

**CRC32**
```bash
echo -n "password123!" | gzip -1 | tail -c 8 | hexdump -n4 -e '"%08x\n"'

# 3cdccd7e
```

</details>

<details>
<summary><h2>Rainbow Tables</h2></summary>

Rainbow tables represent extensive pre-generated databases that map plaintext inputs to their corresponding hash outputs for specific cryptographic algorithms. These tables enable rapid password recovery through direct hash lookup.

| Password    | MD5 Hash                           |
|-------------|------------------------------------|
| 123456      | e10adc3949ba59abbe56e057f20f883e |
| 12345       | 827ccb0eea8a706c4c34a16891f84e7b |
| 123456789   | 25f9e794323b453885f5181f1b624d0b |
| password    | 5f4dcc3b5aa765d61d8327deb882cf99 |
| iloveyou    | f25a2fc72690b780b2a14e140ef6a9e0 |
| princess    | 8afa847f50a716e64932d995c8e7435a |
| 1234567     | fcea920f7412b5da7be0cf42b8c93759 |
| rockyou     | f806fc5a2a0d5ba2471600758452799c |
| 12345678    | 25d55ad283aa400af464c76d713c07ad |
| abc123      | e99a18c428cb38d5f260853678922e03 |
| ...  | ...                        |

> Because rainbow tables are such a powerful attack, salting is used.

</details>

<details>
<summary><h2>Salt</h2></summary>

A salt, in cryptographic terms, is a random sequence of bytes added to a password before it is hashed.

For example, if the salt *PWN0M1C0N_* is prepended to the same password, the MD5 hash would now be as follows:

```bash
echo -n PWN0M1C0N_password123! | md5sum

# ded0e91215d34046aca709995c794045
```

**Why use a Salt?**

* Prevents Identical Hashes: Without a salt, the same password always produces the same hash. Salts ensure uniqueness, even if two users have the same password.

* Defeats Rainbow Tables: Precomputed hash tables (rainbow tables) become useless because each salt requires a separate lookup table.

**How Salts Break Rainbow Tables**

A 1-byte salt (256 possible values) forces attackers to generate 256 versions of every precomputed hash. A rainbow table with 15 billion entries would need 3.84 trillion entries (15B × 256) to cover all salt combinations.
Modern Systems use larger salts (e.g., 16+ bytes), making rainbow tables computationally infeasible.

</details>

<details>
<summary><h2>Dictionary attack</h2></summary>

Dictionary attacks (or wordlist attacks) represent one of the most effective password cracking methods, particularly valuable for time-constrained engagements like penetration testing.

**Key Characteristics**

* **High Efficiency:** Targets common passwords first, maximizing success rate per attempt

* **Time Optimization:** Critical for engagements with limited testing windows

* **Customization:** Wordlists can be tailored to specific industries, regions, or targets

**Common Wordlist Resources**

* [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt): Contains millions of real passwords from historical breaches

* [SecLists](https://github.com/danielmiessler/SecLists): Comprehensive security testing collection including:

    * Common credentials

    * Default passwords

    * Pattern-based variations

</details>

</details>

<details>
<summary><h1>Password Cracking Techniques</h1></summary>

<details>
<summary><h2>John The Ripper</h2></summary>

Tool used for cracking passwords through various attacks including brute-force and dictionary.

[Here](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats) is a very useful cheat-sheet by PentestMonkey.

<details>
<summary><h3>JtR FOrmats</h3></summary>

| Hash Format           | Example Command                          | Description |
|-----------------------|-----------------------------------------|-------------|
| afs                   | `john --format=afs [...] <HASH_FILE>`    | AFS (Andrew File System) password hashes |
| bfegg                 | `john --format=bfegg [...] <HASH_FILE>`  | bfegg hashes used in Eggdrop IRC bots |
| bf                    | `john --format=bf [...] <HASH_FILE>`     | Blowfish-based crypt(3) hashes |
| bsdi                  | `john --format=bsdi [...] <HASH_FILE>`   | BSDi crypt(3) hashes |
| crypt(3)              | `john --format=crypt [...] <HASH_FILE>`  | Traditional Unix crypt(3) hashes |
| des                   | `john --format=des [...] <HASH_FILE>`    | Traditional DES-based crypt(3) hashes |
| dmd5                  | `john --format=dmd5 [...] <HASH_FILE>`   | DMD5 (Dragonfly BSD MD5) password hashes |
| dominosec             | `john --format=dominosec [...] <HASH_FILE>` | IBM Lotus Domino 6/7 password hashes |
| EPiServer SID hashes  | `john --format=episerver [...] <HASH_FILE>` | EPiServer SID (Security Identifier) password hashes |
| hdaa                  | `john --format=hdaa [...] <HASH_FILE>`   | hdaa password hashes used in Openwall GNU/Linux |
| hmac-md5              | `john --format=hmac-md5 [...] <HASH_FILE>` | hmac-md5 password hashes |
| hmailserver           | `john --format=hmailserver [...] <HASH_FILE>` | hmailserver password hashes |
| ipb2                  | `john --format=ipb2 [...] <HASH_FILE>`   | Invision Power Board 2 password hashes |
| krb4                  | `john --format=krb4 [...] <HASH_FILE>`   | Kerberos 4 password hashes |
| krb5                  | `john --format=krb5 [...] <HASH_FILE>`   | Kerberos 5 password hashes |
| LM                    | `john --format=LM [...] <HASH_FILE>`     | LM (Lan Manager) password hashes |
| lotus5                | `john --format=lotus5 [...] <HASH_FILE>` | Lotus Notes/Domino 5 password hashes |
| mscash                | `john --format=mscash [...] <HASH_FILE>` | MS Cache password hashes |
| mscash2               | `john --format=mscash2 [...] <HASH_FILE>` | MS Cache v2 password hashes |
| mschapv2              | `john --format=mschapv2 [...] <HASH_FILE>` | MS CHAP v2 password hashes |
| mskrb5                | `john --format=mskrb5 [...] <HASH_FILE>` | MS Kerberos 5 password hashes |
| mssql05               | `john --format=mssql05 [...] <HASH_FILE>` | MS SQL 2005 password hashes |
| mssql                 | `john --format=mssql [...] <HASH_FILE>`  | MS SQL password hashes |
| mysql-fast            | `john --format=mysql-fast [...] <HASH_FILE>` | MySQL fast password hashes |
| mysql                 | `john --format=mysql [...] <HASH_FILE>`  | MySQL password hashes |
| mysql-sha1            | `john --format=mysql-sha1 [...] <HASH_FILE>` | MySQL SHA1 password hashes |
| NETLM                 | `john --format=netlm [...] <HASH_FILE>`  | NETLM (NT LAN Manager) password hashes |
| NETLMv2               | `john --format=netlmv2 [...] <HASH_FILE>` | NETLMv2 (NT LAN Manager version 2) password hashes |
| NETNTLM               | `john --format=netntlm [...] <HASH_FILE>` | NETNTLM (NT LAN Manager) password hashes |
| NETNTLMv2             | `john --format=netntlmv2 [...] <HASH_FILE>` | NETNTLMv2 (NT LAN Manager version 2) password hashes |
| NEThalfLM             | `john --format=nethalflm [...] <HASH_FILE>` | NEThalfLM (NT LAN Manager) password hashes |
| md5ns                 | `john --format=md5ns [...] <HASH_FILE>`  | md5ns (MD5 namespace) password hashes |
| nsldap                | `john --format=nsldap [...] <HASH_FILE>` | nsldap (OpenLDAP SHA) password hashes |
| ssha                  | `john --format=ssha [...] <HASH_FILE>`   | ssha (Salted SHA) password hashes |
| NT                    | `john --format=nt [...] <HASH_FILE>`     | NT (Windows NT) password hashes |
| openssha              | `john --format=openssha [...] <HASH_FILE>` | OPENSSH private key password hashes |
| oracle11              | `john --format=oracle11 [...] <HASH_FILE>` | Oracle 11 password hashes |
| oracle                | `john --format=oracle [...] <HASH_FILE>` | Oracle password hashes |
| pdf                   | `john --format=pdf [...] <HASH_FILE>`    | PDF (Portable Document Format) password hashes |
| phpass-md5            | `john --format=phpass-md5 [...] <HASH_FILE>` | PHPass-MD5 (Portable PHP password hashing framework) password hashes |
| phps                  | `john --format=phps [...] <HASH_FILE>`   | PHPS password hashes |
| pix-md5               | `john --format=pix-md5 [...] <HASH_FILE>` | Cisco PIX MD5 password hashes |
| po                    | `john --format=po [...] <HASH_FILE>`     | Po (Sybase SQL Anywhere) password hashes |
| rar                   | `john --format=rar [...] <HASH_FILE>`    | RAR (WinRAR) password hashes |
| raw-md4               | `john --format=raw-md4 [...] <HASH_FILE>` | Raw MD4 password hashes |
| raw-md5               | `john --format=raw-md5 [...] <HASH_FILE>` | Raw MD5 password hashes |
| raw-md5-unicode       | `john --format=raw-md5-unicode [...] <HASH_FILE>` | Raw MD5 Unicode password hashes |
| raw-sha1              | `john --format=raw-sha1 [...] <HASH_FILE>` | Raw SHA1 password hashes |
| raw-sha224            | `john --format=raw-sha224 [...] <HASH_FILE>` | Raw SHA224 password hashes |
| raw-sha256            | `john --format=raw-sha256 [...] <HASH_FILE>` | Raw SHA256 password hashes |
| raw-sha384            | `john --format=raw-sha384 [...] <HASH_FILE>` | Raw SHA384 password hashes |
| raw-sha512            | `john --format=raw-sha512 [...] <HASH_FILE>` | Raw SHA512 password hashes |
| salted-sha            | `john --format=salted-sha [...] <HASH_FILE>` | Salted SHA password hashes |
| sapb                  | `john --format=sapb [...] <HASH_FILE>`   | SAP CODVN B (BCODE) password hashes |
| sapg                  | `john --format=sapg [...] <HASH_FILE>`   | SAP CODVN G (PASSCODE) password hashes |
| sha1-gen              | `john --format=sha1-gen [...] <HASH_FILE>` | Generic SHA1 password hashes |
| skey                  | `john --format=skey [...] <HASH_FILE>`   | S/Key (One-time password) hashes |
| ssh                   | `john --format=ssh [...] <HASH_FILE>`    | SSH (Secure Shell) password hashes |
| sybasease             | `john --format=sybasease [...] <HASH_FILE>` | Sybase ASE password hashes |
| xsha                  | `john --format=xsha [...] <HASH_FILE>`   | xsha (Extended SHA) password hashes |
| zip                   | `john --format=zip [...] <HASH_FILE>`    | ZIP (WinZip) password hashes |

</details>

<details>
<summary><h3>Cracking passwords</h3></summary>

<details>
<summary><h4>Wordlists</h4></summary>

Verify the hash type

```bash
hashid -j "<HASH_STRING>"
```

> By adding the -j flag, hashID will, in addition to the hash format, list the corresponding JtR format

Create the hash file

```bash
echo "<HASH_STRING>" > hash.txt
```

> To process multiple hashes in a single operation, place each hash on a separate line and ensure no empty lines or extraneous characters.

Example valid format

```bash
d1c5c8f3b5f1e0a7a6b8d9c2e4f6a3b1d0e7f8c9  
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8  
7c4a8d09ca3762af61e59520943dc26494f8941b
```

Run john

```bash
john --format=<HASH_FORMAT> --wordlist=/usr/share/wordlists/rockyou.txt hash.txt > cracked_hash.txt
```

Verify the results

```bash
john --show --format=raw-md5 hash.txt
```

</details>

<details>
<summary><h4>Single</h4></summary>

Verify the hash type

```bash
hashid -j "<HASH_STRING>"
```

Create the hash file

```bash
echo "<HASH_STRING>" > hash.txt
```

Example valid format

```bash
r0lf:\$6\$ues25dIanlctrWxg\$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

Run john

```bash
john --single --format=<HASH_FORMAT> hash.txt
```

Verify the results

```bash
john --show --format=<HASH_FORMAT> hash.txt
```

</details>

</details>

<details>
<summary><h3>Cracking files</h3></summary>

John the Ripper includes specialized utilities for extracting hashes from encrypted/password-protected files. These companion tools follow a consistent syntax pattern:

```bash
<TOOL> <FILE_TO_CRACK> > file.hash
```

Some of the tools included with JtR are:

| Tool                     | Example Usage                     | Description |
|--------------------------|-----------------------------------|-------------|
| `pdf2john`               | `pdf2john file.pdf > hash.txt`    | Extracts password hashes from PDF files for John |
| `ssh2john`               | `ssh2john id_rsa > hash.txt`      | Converts SSH private keys to John format |
| `mscash2john`            | `mscash2john cache.dat > hash.txt`| Extracts MS Cash password hashes |
| `keychain2john`          | `keychain2john login.keychain > hash.txt` | Processes macOS keychain files |
| `rar2john`               | `rar2john archive.rar > hash.txt` | Extracts RAR archive passwords |
| `pfx2john`               | `pfx2john cert.pfx > hash.txt`    | Converts PKCS#12 files for cracking |
| `truecrypt_volume2john`  | `truecrypt_volume2john volume.tc > hash.txt` | Extracts TrueCrypt volume passwords |
| `keepass2john`           | `keepass2john database.kdbx > hash.txt` | Extracts KeePass database credentials |
| `vncpcap2john`           | `vncpcap2john capture.pcap > hash.txt` | Extracts VNC passwords from PCAP files |
| `putty2john`             | `putty2john putty_key.ppk > hash.txt` | Converts PuTTY private keys |
| `zip2john`               | `zip2john archive.zip > hash.txt` | Extracts ZIP archive passwords |
| `hccap2john`             | `hccap2john capture.cap > hash.txt` | Converts WPA handshakes for cracking |
| `office2john`            | `office2john document.docx > hash.txt` | Extracts MS Office document passwords |
| `wpa2john`               | `wpa2john capture.pcap > hash.txt` | Alternative WPA handshake converter |

An even larger collection can be found:

```bash
locate *2john*
```

</details>

</details>

<details>
<summary><h2>John The Ripper</h2></summary>

</details>

</details>