# QueryEasy 🔎
**Ask your data. Stay private.**

QueryEasy is a secure, web-based control panel that lets teams interact with **MySQL 8 databases using plain English**. Instead of writing complex SQL syntax, users simply type what they need—and QueryEasy translates, verifies, previews, and executes the request safely.

---

## Why QueryEasy?
Working directly with MySQL databases creates two major bottlenecks for businesses: non-technical staff have to wait on specialists for simple reports, while giving direct database access risks accidental data loss or exposing private records to external AI tools.

**QueryEasy solves both** by combining plain-English AI translation with multi-layer database safety locks.

---

## How One Request Works

```
Plain English → AI writes SQL → Validator checks it → You review it → It runs → You see the result
```

1. **Type a request** in plain English, for example: *"show orders with total between 100 and 500, sorted by date."*
2. **Click "1. Generate SQL".** The AI turns the request into exactly one MySQL statement.
3. **The validator checks it.** Unsafe statements are blocked with a clear reason, and nothing runs.
4. **Review the SQL.** A colour label shows the risk: 🟢 read only, 🟡 changes data, 🔴 changes structure.
5. **Run it.** Reads show a table straight away. Data changes wait for **Commit** or **Rollback**. Structure changes need you to type `CONFIRM`.

---

## Features in Detail

### Plain-English to SQL
* Describe what you want in everyday words. QueryEasy writes the MySQL for you.
* Supports the SQL features people use most: `WHERE`, `BETWEEN`, `IN`, `LIKE`, `IS NULL`, `ORDER BY`, `GROUP BY`, `HAVING`, `JOIN`, subqueries, CTEs, window functions, `UNION`, aggregates, `DISTINCT` and `LIMIT`.
* Understands all common statement types: `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, `USE`, `INSERT`, `UPDATE`, `DELETE`, `CREATE` (table, view, index, database), `ALTER`, `DROP`, `TRUNCATE` and `RENAME`.
* Requests can be up to 800 characters long.

### Review Before Anything Runs
* You always see the exact SQL before it runs, with a risk label and a short explanation.
* The SQL you see is the cleaned-up version produced by the validator, not the raw text the AI wrote.
* A **"What the AI can see (names only)"** panel shows exactly which tables and columns are shared with the AI.

### Safe Results
* Results are capped at **100 rows** by default (`QE_MAX_ROWS`).
* Read queries run in a **read-only MySQL session** with a **5-second time limit** (`QE_TIMEOUT_MS`).
* Results appear in a table, and the app tells you how many rows were returned.

### Undo for Data Changes
* `INSERT`, `UPDATE` and `DELETE` run inside an open transaction first.
* You see how many rows were affected, then choose **Commit (save)** or **Rollback (undo)**.
* If you do nothing for **120 seconds**, the change is rolled back automatically.
* `UPDATE` and `DELETE` without a `WHERE` condition are blocked unless a Writer or Admin ticks **"Allow UPDATE/DELETE on ALL rows"** in the sidebar.

### Protection for Structure Changes
* `DROP`, `TRUNCATE`, `ALTER` and `RENAME` are marked destructive and need you to type `CONFIRM`.
* They are matched against strict patterns, so risky variants (such as dropping several tables in one statement) are rejected.
* Structure changes cannot be undone, and the app says so clearly.

### Database Picker
* Pick any database your MySQL account can see from the sidebar. MySQL's internal databases (`mysql`, `information_schema`, `performance_schema`, `sys`) are always hidden.
* Switching database clears any old SQL, results and unsaved changes.
* Table and column names are cached for 5 minutes for speed, and refreshed automatically after a structure change.

### Users, Roles and Passwords
* Anyone can register, but only the owner can create the first Admin (see **Secure First-Admin Setup** below).
* Admins promote users to Writer or Admin in **Manage users**. Nobody can change their own role.
* Every user can **change their own password** (the old password is required).
* Admins can **reset another user's password**. That user is logged out everywhere.
* Changing or resetting a password logs out all other open sessions of that user.
* Password rules: at least 8 characters, with letters and numbers.
* After 5 wrong passwords an account is locked for 5 minutes. Unknown usernames and wrong passwords give the same message, so attackers cannot discover which usernames exist.
* Sessions log out automatically after **30 minutes** of inactivity, and one login session is limited to **40 requests**.

### AI Key Management (Bring Your Own Key)
* Each client uses their own OpenAI key and pays for their own usage.
* Admins paste the key in **sidebar → AI key**. It is stored **encrypted** on the computer, only its last 4 characters are ever shown, and it is never written to the audit log.
* Admins can **test** or **remove** the key from the same panel.
* A key in the `.env` file (`OPENAI_API_KEY`) still works as a fallback.
* Clear messages explain common problems: rejected key, no credit left, wrong model, or too many requests.

### Audit Log
* Every request, blocked statement, committed or rolled-back change, password change and key change is written to `audit_log.jsonl`.
* The log records time, user, database, the request, the SQL and the outcome. **It never records result rows.**

### Look and Feel
* Animated splash screen, glass-style login window with logo, and a logo header in the main workspace and sidebar.
* Admins can view the MySQL setup script inside the app under **sidebar → MySQL setup script**.

---

## Key Features & Security Architecture

### 1. Zero-Data Privacy
* **Schema-Only AI Communication:** Only table names, column names, and foreign keys are sent to the AI—never stored customer rows or financial records. (Any values you type into the request itself, such as a name you want to insert, are part of your request and are sent too.)
* **Automatic Sensitive Column Redaction:** Columns matching sensitive patterns (`password`, `secret`, `token`, `cvv`, `ssn`, `cnic`, `iban`, `pin`, `card_number`) and admin-designated hidden tables are automatically stripped from the AI's view and blocked from queries.
* **Bring Your Own Key (BYOK):** Admins paste their OpenAI API key directly inside the sidebar. It is stored encrypted on disk (`ai_key.enc`), never shown again, and never written to logs.

### 2. Three-Tier Role-Based Access Control (RBAC)
Permissions are enforced at both the application level and the MySQL server level using three separate database accounts. Each statement runs with the weakest account that can do the job, so even if every other check failed, MySQL itself would refuse anything the account cannot do.

| Role | Allowed statements | MySQL account |
|---|---|---|
| Reader 🟢 | `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, `USE` | `queryeasy_ro` |
| Writer 🟡 | Reader + `INSERT`, `UPDATE`, `DELETE` | `queryeasy_rw` |
| Admin 🔴 | Writer + `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `RENAME` | `queryeasy_admin` |

### 3. Secure First-Admin Setup
* **Owner-only setup token:** The application owner sets a secret `QE_SETUP_TOKEN` in the private `.env` file. It is never displayed in the app.
* **Token required for the first account:** While no admin exists, only a person who enters the correct token during registration can create the first account, which becomes the Admin.
* **Brute-force protection:** Repeated wrong tokens temporarily lock token entry.
* **Token disabled after use:** Once an admin exists, the token stops working and cannot create another initial admin.
* **Everyone else is a Reader:** All later registrations start as Readers. An Admin promotes trusted users in **Manage users**.

### 4. Multi-Layer Guardrails Against Mistakes
* **Undoable Data Changes (`Commit` / `Rollback`):** `INSERT`, `UPDATE`, and `DELETE` run inside an uncommitted transaction first. Users see the exact number of affected rows and have **120 seconds** to click **Commit** or **Rollback** (auto-rolls back on timeout).
* **Structural Confirmation Lock:** Destructive commands (`DROP`, `TRUNCATE`, `ALTER`, `RENAME`) require manually typing `CONFIRM` before execution.
* **AST SQL Validation (`sqlglot`):** Every generated statement is parsed and inspected before execution—blocking stacked queries (`;`), comments, system schemas (`mysql`, `information_schema`), server-freezing functions (`SLEEP`, `BENCHMARK`, `LOAD_FILE`), and unconditioned bulk edits.
* **Always Blocked:** `GRANT`, `REVOKE`, `SET`, `CALL`, `LOAD DATA`, `INTO OUTFILE`, user and privilege management, and access to system schemas.
* **Prompt-Injection Defense:** The AI is told to treat your text as data, not as instructions, and its answer is still checked by the validator before anything runs.
* **Account Hardening & Audit Log:** Passwords are stored as salted `scrypt` hashes with brute-force lockouts and automatic session invalidation on password changes. All actions are logged to `audit_log.jsonl` without ever recording result rows.

---

## Example Requests

| You type | You get |
|---|---|
| *show all customers from Lahore* | 🟢 a `SELECT` with a `WHERE` filter |
| *top 5 products by total sales* | 🟢 a `SELECT` with `JOIN`, `GROUP BY`, `ORDER BY` and `LIMIT` |
| *describe the orders table* | 🟢 `DESCRIBE orders` |
| *add a customer named Ali with city Jhang* | 🟡 an `INSERT` that waits for Commit or Rollback |
| *set price to 500 where id is 12* | 🟡 an `UPDATE` that waits for Commit or Rollback |
| *create a table for suppliers* | 🔴 a `CREATE TABLE` |
| *drop the old_logs table* | 🔴 a `DROP TABLE` that needs `CONFIRM` |

If your role is not allowed to run a statement (for example a Reader asking for an `INSERT`), QueryEasy tells you and nothing runs.

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Create the MySQL Accounts
Open `setup_mysql.sql`, replace `your_database` and every `CHANGE_ME` password, then run it once in MySQL as an administrator. It creates the three accounts: reader, writer and admin.

### 3. Create Your `.env` File
Copy `.env.example` to `.env` and fill in your database name and passwords. **Never upload `.env` to GitHub.**

### 4. Set the Setup Token
Generate a long random secret:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```
Add it to your `.env` file (at least 16 characters, no quotes):
```
QE_SETUP_TOKEN=your_generated_secret_here
```

### 5. Run the App
```bash
streamlit run main.py
```

### 6. Create the First Admin
On the **Register** tab, enter a username, a password, and your setup token in the **Owner setup token** field. That account becomes the Admin, and the token is disabled.

### 7. Add the AI Key
Log in as the Admin and open **sidebar → AI key**. Paste your OpenAI API key and click **Save key**.

### 8. Add Your Team
Other users register normally and start as **Readers**. As Admin, open **Manage users** to promote trusted users to **Writer** or **Admin**.

---

## Configuration (`.env`)

| Setting | Meaning | Default |
|---|---|---|
| `DB_HOST`, `DB_PORT`, `DB_NAME` | Where MySQL is and which database opens first | `localhost`, `3306` |
| `DB_USER`, `DB_PASSWORD` | Reader account (required) | none |
| `DB_RW_USER`, `DB_RW_PASSWORD` | Writer account. Leave empty to disable data changes | none |
| `DB_ADMIN_USER`, `DB_ADMIN_PASSWORD` | Admin account. Leave empty to disable structure changes | none |
| `QE_SETUP_TOKEN` | Secret for creating the first admin (16+ characters) | none |
| `OPENAI_API_KEY` | Optional. Admins can paste the key inside the app instead | none |
| `QE_ADMIN_USERS` | Comma-separated usernames that are always Admin | none |
| `QE_MODEL` | Which AI model writes the SQL | `gpt-6-luna` |
| `QE_MAX_ROWS` | Maximum rows shown per result | `100` |
| `QE_TIMEOUT_MS` | Time limit for read queries, in milliseconds | `5000` |
| `QE_HIDDEN_TABLES` | Comma-separated tables hidden from the AI and blocked | none |
| `QE_MASTER_KEY` | Secret that encrypts the saved AI key (otherwise `master.key` is used) | file |

---

## Files in This Project

| File | Purpose |
|---|---|
| `main.py` | The whole application |
| `requirements.txt` | Python libraries to install |
| `setup_mysql.sql` | Creates the three MySQL accounts |
| `.env.example` | Template for your private `.env` |
| `.gitignore` | Keeps secrets and local data off GitHub |

Files created while running, and never uploaded: `.env`, `users.db`, `audit_log.jsonl`, `ai_key.enc`, `master.key`.

---

## Handy Command
```bash
python main.py setup
```
Writes fresh `setup_mysql.sql` and `.env.example` files next to `main.py`.
