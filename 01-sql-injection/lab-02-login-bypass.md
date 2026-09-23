# Lab: SQL injection vulnerability allowing login bypass

## 1. Vulnerability Discovery (The Analysis)
* **Target Endpoint / Parameter:** `/login` (POST parameters `username` and `password`)
* **Vulnerability Type:** Server-Side (SQL Injection via Authentication Bypass)
* **Observation:** The application processes login verification by querying database credentials supplied via user form input fields without cleaning the parameters.

## 2. Exploitation (The Hack)
* **Payload Used (Username Field):** `administrator'--`
* **Mechanism:** The application looks up matching credentials in a database structure similar to this:
  * *Original Query Structure:* `SELECT * FROM users WHERE username = 'input_user' AND password = 'input_password'`
  * *Exploited Query Structure:* `SELECT * FROM users WHERE username = 'administrator'--' AND password = '...'`
  * Injecting `administrator'--` tricks the database into evaluating the username match for the admin account, while the comment sequence (`--`) tells the database to completely ignore the rest of the command—including the secondary `AND password` check.
* **Result:** Bypassed the login logic entirely, authenticating straight into the application as the `administrator` user without knowing the password.

## 3. Remediation (The Fix)
* **Flawed Concept:** Trusting client form input parameters inside critical server-side authentication queries.
* **The Correction:** Implement **Prepared Statements** for all authentication logic. The database must isolate credential input text so it can never drop the password validation requirements.

### Vulnerable Code (Conceptual Node.js / Express Backend)
```javascript
const { username, password } = req.body;
// Vulnerable: Input injection alters the logic flow of the query string
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.query(query);
```

### Secure Remediation (Node.js pg-pool Parameterized Array)
```javascript
const { username, password } = req.body;
// Secure: Input parameters are encapsulated safely inside an isolated array
const query = 'SELECT * FROM users WHERE username = \$1 AND password = \$2';
db.query(query, [username, password]);
```
