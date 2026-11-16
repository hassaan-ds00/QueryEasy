# QueryEasy 🔎
**Ask your data. Stay private.**

QueryEasy is a secure, web-based control panel that lets teams interact with **MySQL 8 databases using plain English**. Instead of writing complex SQL syntax, users simply type what they need—and QueryEasy translates, verifies, previews, and executes the request safely.

---

## Why QueryEasy?
Working directly with MySQL databases creates two major bottlenecks for businesses: non-technical staff have to wait on specialists for simple reports, while giving direct database access risks accidental data loss or exposing private records to external AI tools.

**QueryEasy solves both** by combining plain-English AI translation with multi-layer database safety locks.

---

<img width="1353" height="634" alt="Screenshot 2026-11-14 210247" src="https://github.com/user-attachments/assets/92cae661-40d2-4f53-9db1-9f48092782b0" />
<img width="536" height="626" alt="Screenshot 2026-11-14 210302" src="https://github.com/user-attachments/assets/4570e85e-56db-43a5-9468-58b6039448ae" />
<img width="1361" height="641" alt="Screenshot 2026-11-14 210340" src="https://github.com/user-attachments/assets/87e591f2-cb01-47b4-b4cf-7c16fad92c36" />
<img width="817" height="469" alt="Screenshot 2026-11-14 210402" src="https://github.com/user-attachments/assets/2799dd06-9c8c-4237-9f2d-6184d6872471" />
<img width="260" height="407" alt="Screenshot 2026-11-14 210441" src="https://github.com/user-attachments/assets/79772f95-e789-4dbd-933c-cda7e469b1a1" />
<img width="249" height="407" alt="Screenshot 2026-11-14 210457" src="https://github.com/user-attachments/assets/c2c64b03-487d-4267-a201-2714663663ca" />


## Key Features & Security Architecture

### 1. Zero-Data Privacy
* **Schema-Only AI Communication:** Only table names, column names, and foreign keys are sent to the AI—never actual customer rows or financial records.
* **Automatic Sensitive Column Redaction:** Columns matching sensitive patterns (`password`, `secret`, `token`, `cvv`, `ssn`, `cnic`, `iban`, `pin`, `card_number`) and admin-designated hidden tables are automatically stripped from the AI's view and blocked from queries.
* **Bring Your Own Key (BYOK):** Admins paste their OpenAI API key directly inside the sidebar. It is stored encrypted on disk (`ai_key.enc`), never shown again, and never written to logs.

### 2. Three-Tier Role-Based Access Control (RBAC)
Permissions are enforced at both the application level and the MySQL server level using three separate database accounts:
* **Reader (`🟢`):** `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, `USE` (runs via read-only `queryeasy_ro`).
* **Writer (`🟡`):** Reader permissions + `INSERT`, `UPDATE`, `DELETE` (runs via `queryeasy_rw`).
* **Admin (`🔴`):** Writer permissions + `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `RENAME` (runs via `queryeasy_admin`).

### 3. Multi-Layer Guardrails Against Mistakes
* **Undoable Data Changes (`Commit` / `Rollback`):** `INSERT`, `UPDATE`, and `DELETE` run inside an uncommitted transaction first. Users see the exact number of affected rows and have **120 seconds** to click **Commit** or **Rollback** (auto-rolls back on timeout).
* **Structural Confirmation Lock:** Destructive commands (`DROP`, `TRUNCATE`, `ALTER`, `RENAME`) require manually typing `CONFIRM` before execution.
* **AST SQL Validation (`sqlglot`):** Every generated statement is parsed and inspected before execution—blocking stacked queries (`;`), comments, system schemas (`mysql`, `information_schema`), server-freezing functions (`SLEEP`, `BENCHMARK`, `LOAD_FILE`), and unconditioned bulk edits.
* **Account Hardening & Audit Log:** Passwords are stored as salted `scrypt` hashes with brute-force lockouts and automatic session invalidation on password changes. All actions are logged to `audit_log.jsonl` without ever recording result rows.

---
To support my work, please contact on WhatsApp.
[![Chat on WhatsApp](https://shields.io)](https://wa.me/923173563210)




## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
