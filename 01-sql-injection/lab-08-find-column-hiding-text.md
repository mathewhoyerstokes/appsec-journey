# Lab: SQL injection UNION attack, finding a column containing text data

## 1. Vulnerability Discovery & Data Type Mapping (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=xyz`
* **Vulnerability Type:** Server-Side (SQL Injection - Data Type Enumeration)
* **Objective:** Identify which specific column within a 3-column query array cleanly supports string/text values without violating strict database data type boundaries.

### Step 1: Sequential Compatibility Testing via Tester Strings
Using a structural layout baseline of 3 columns (previously mapped via an incremental `ORDER BY` test), I systematically substituted individual `NULL` placeholders with a string literal (`'a'`) to locate the valid insertion target:
* **Testing Slot 1:** `category=xyz' UNION SELECT 'a', NULL, NULL-- ` -> HTTP 500 Internal Server Error
  * *Deduction:* Slot 1 is structurally locked to non-string data types (such as integers or product IDs).
* **Testing Slot 2:** `category=xyz' UNION SELECT NULL, 'a', NULL-- ` -> HTTP 200 OK
  * *Deduction:* Slot 2 cleanly accepts and executes string payloads without throwing database schema mismatch exceptions.
* **Testing Slot 3:** (Skipped as the functional text insertion vector was successfully isolated in Slot 2).

## 2. Exploitation (The Hack)
* **Payload Used:** `' UNION SELECT NULL, 'YOUR_LAB_STRING', NULL-- `
* **Full URL Encoded Input:** `/filter?category=xyz'+UNION+SELECT+NULL,+'YOUR_LAB_STRING',+NULL--+`
* **Mechanism:** 
  1. The trailing single quote (`'`) terminates the original category data context string.
  2. The `UNION` operator instructs the database engine to append a new result layout structure to the output buffer.
  3. The custom data parameters pass a placeholder `NULL` in slots 1 and 3, while placing the required verification token inside the validated text-friendly position (Slot 2).
  4. The comment operator (`-- `) drops trailing database filters to ensure a smooth server processing flow.
* **Result:** The database executed the combined structure cleanly, rendering the specific validation string directly into the application's user interface layer and solving the lab challenge.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application accepts unfiltered client input strings and drops them directly into the executable structural layer of the database query.
* **The Correction:** Implement strict separation of code and data architectures using **Prepared Statements (Parameterized Queries)**.

### Vulnerable Code Example (Conceptual PHP Agency Context)
```php
// Vulnerable: Direct input stitching allows external code strings to alter SQL logical execution
\$category = \$_GET['category'];
\$query = "SELECT id, name, price FROM products WHERE category = '" . \$category . "'";
\$result = \$db->query(\$query);
```


### Secure Remediation Example (Parameterized Validation)
```php
// Secure: Pre-compiling the SQL command string completely neutralizes execution changes
\$category = \$_GET['category'];
\$stmt = \$db->prepare('SELECT id, name, price FROM products WHERE category = :category');
\$stmt->execute(['category' => \$category]);
\$products = \$stmt->fetchAll();
```
