# Lab: SQL injection attack, querying the database type and version on Oracle

## 1. Vulnerability Discovery & Enumeration (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=Gifts`
* **Vulnerability Type:** Server-Side (SQL Injection - UNION Based)
* **Target Database Infrastructure:** Oracle

### Step 1: Mapping Column Count via Structural Ordering
To execute a successful `UNION` injection, the injected query must contain the exact same number of columns as the developer's original query. I used the `ORDER BY` clause to find the database threshold:
* `category=Gifts' ORDER BY 1--` -> HTTP 200 OK
* `category=Gifts' ORDER BY 2--` -> HTTP 200 OK
* `category=Gifts' ORDER BY 3--` -> HTTP 500 Internal Server Error

**Deduction:** The database query architecture expects exactly **2 columns**. 

### Step 2: Testing Data Type Compatibility
Oracle databases strictly require all `SELECT` queries to contain a `FROM` clause. To test if the column structures accept string/text data types without breaking schema rules, I queried Oracle's built-in dummy table (`DUAL`):
* Payload: `category=Gifts' UNION SELECT 'a', 'b' FROM dual--` -> HTTP 200 OK

**Deduction:** Both columns cleanly support text data payloads.

## 2. Exploitation (The Hack)
* **Payload Used:** `' UNION SELECT banner, NULL FROM v$version--`
* **Full URL Input:** `/filter?category=Gifts'+UNION+SELECT+banner,+NULL+FROM+v$version--`
* **Mechanism:** 
  1. The single quote (`'`) breaks out of the original category filter string wrapper.
  2. The `UNION` clause appends a custom malicious query structure directly onto the backend product layout array.
  3. Consulting database metadata signatures, Oracle houses its software tracking records in the `v$version` table under the `banner` column. 
  4. The payload requests the `banner` string in column one, and a placeholder `NULL` value in column two to fulfill the mandatory 2-column database width constraint.
  5. The comment syntax (`--`) instructs the engine to drop the trailing code sequence (`AND released = 1`), neutralizing logic execution failures.
* **Result:** The Oracle database software version metrics were successfully retrieved and displayed straight inside the public UI text container.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application parses raw client-side HTTP request strings and concatenates them directly into database processing queries.
* **The Correction:** Implement absolute separation of code and data structures using **Prepared Statements (Parameterized Queries)**. 

### Vulnerable Code Example (Conceptual Backend Context)
```php
// Vulnerable: Variable interpolation allows the user input to alter the execution logic
\$query = "SELECT name, description FROM products WHERE category = '" . \$category . "' AND released = 1";
\$result = \$db->query(\$query);
```

### Secure Remediation Example (Parameterized Validation)
```php
// Secure: Pre-compiling the query layout isolates variables as harmless literal strings
\$stmt = \$db->prepare('SELECT name, description FROM products WHERE category = :category AND released = 1');
\$stmt->execute(['category' => \$category]);
\$products = \$stmt->fetchAll();
```
