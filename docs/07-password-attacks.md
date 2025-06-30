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

**SHA256**

```bash
echo -n password123! | sha256sum

# 5751a44782594819e4cb8aa27c2c9d87a420af82bc6a5a05bc7f19c3bb00452b
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