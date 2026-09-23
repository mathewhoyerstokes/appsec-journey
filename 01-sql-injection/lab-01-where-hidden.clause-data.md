# Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

## 1. Vulnerability Discovery (The Analysis)
* **Target Endpoint / Parameter:** `/filter?category=Gifts`
* **Vulnerability Type:** Server-Side (SQL Injection)
* **Observation:** The application filters products by category via a GET parameter. Appending a single quote (`'`) to the category name caused the application to behave erratically or throw a server error, indicating the input was being passed unsanitized into a database query.

## 2. Exploitation (The Hack)
* **Payload Used:** `' OR 1=1--`
* **Full Exploited URL:** `/filter?category=Gifts' OR 1=1--`
* **Mechanism:** The application constructs its SQL query using direct string concatenation. 
  * *Original Query Structure:* `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
  * *Exploited Query Structure:* `SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`
  * The single quote (`'`) breaks out of the input field string literal. The `OR 1=1` forces the query condition to evaluate to true for every single row in the database table. The double dash (`--`) comments out the remainder of the query, stripping away the `AND released = 1` filter.
* **Result:** The system returned and displayed all items in the database table, including hidden, unreleased products.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application treats user-supplied text parameters as executable database command segments.
* **The Correction:** The engineering team must refactor the backend database connector to use **Parameterized Queries (Prepared Statements)** instead of string interpolation.

### Vulnerable Code (Conceptual PHP Backend)
```php
category = _GET['category'];
// Vulnerable: Direct concatenation allows query manipulation
\$query = "SELECT * FROM products WHERE category = '" . \$category . "' AND released = 1";
\$result = db->query(query);
```

### Secure Remediation (PHP PDO)
```php
category = _GET['category'];
// Secure: Database engine compiles query layout prior to variable binding
stmt = db->prepare('SELECT * FROM products WHERE category = :category AND released = 1');
\(stmt->execute(['category' =>\)category]);
products = stmt->fetchAll();
```
