# Lab: Blind SQL injection with conditional responses

## 1. Vulnerability Discovery & Logic Analysis (The Analysis)
* **Target Endpoint / Vector:** `TrackingId` Session Cookie Parameter
* **Vulnerability Type:** Server-Side (Blind SQL Injection - Conditional Responses)
* **Target Database Infrastructure:** Standard Relational Schema (PostgreSQL/MySQL layout)

### Step 1: Establishing a Covert Logical Communication Channel
Because the web application completely suppresses direct database query output strings and verbose error messaging, I analyzed state transitions by injecting binary True/False logical expressions directly into the `TrackingId` cookie context:
* **Baseline Condition:** Valid execution yields a front-end HTML component text string: `"Welcome back"`.
* **Injecting a Logical Truth:** Appending `' AND '1'='1-- ` preserves the true database state. The application processes normally and renders `"Welcome back"`.
* **Injecting a Logical Lie:** Appending `' AND '1'='2-- ` forces the conditional logic array to evaluate to false. The query yields 0 rows, and the `"Welcome back"` text block completely vanishes from the rendered layout source.

**Deduction:** The backend is vulnerable to Blind SQL Injection. I can extract sensitive internal assets byte-by-byte by orchestrating a sequence of automated true-or-false validation questions.

### Step 2: Structural Schema & Target Length Mapping
Using the binary true/false visual feedback loop, I verified target environment assets:
* **Verifying Table/User Existence:** `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a'-- ` -> Yields True (`"Welcome back"` prints), confirming the target user account profile exists in the schema.
* **Verifying Password Length Boundary:** `TrackingId=xyz' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password)=20)='administrator'-- ` -> Yields True, confirming the administrator's credential string length is exactly **20 characters long**.

## 2. Exploitation & Automated Exfiltration (The Hack)
* **The Strategy:** To automate character evaluation across all 20 password string index positions without manual submission latency, I utilized Burp Suite's **Intruder (Cluster Bomb Attack Layout)** to parse sequential characters.
* **The Substring Evaluation Mechanism:**
  ```http
  TrackingId=your_cookie_value' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'-- 
  ```
* **Attack Automation Matrix:**
  * **Payload Set 1 (String Position Index):** Sequential integer numbers from `1` to `20` (step `1`).
  * **Payload Set 2 (Character Match Value):** Simple alphanumeric character array set (`a-z0-9`).
  * **Success Condition Rule (Grep - Match Verification):** Filter matching rule flag configured specifically for the string literal `"Welcome back"`.

* **Result:** Successfully extracted all 20 unique matching output flags to piece together the plaintext administrative verification key, achieving an authentication takeover.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application accepts untrusted client session parameters and resolves them directly within the structural executable block of a backend database query.
* **The Correction:** Completely decouple operational database code logic from runtime data variables by converting the application's data connection functions to use **Prepared Statements (Parameterized Queries)**.

### Vulnerable Code Example (Conceptual Backend Context)
```php
// Vulnerable: Raw tracking parameter concatenation enables logical alteration of query paths
\$tracking_id = \$_COOKIE['TrackingId'];
\$query = "SELECT TrackingId FROM users WHERE TrackingId = '" . \$tracking_id . "'";
\$result = \$db->query(\$query);
```

### Secure Remediation Example (Parameterized Validation)
```php
// Secure: Pre-compiling the query layout forces input to parse strictly as data literals, neutralizing injection
\$tracking_id = \$_COOKIE['TrackingId'];
\$stmt = \$db->prepare('SELECT TrackingId FROM users WHERE TrackingId = :tracking_id');
\$stmt->execute(['tracking_id' => \$tracking_id]);
\$user_session = \$stmt->fetch();
```

