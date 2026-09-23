# Lab: Stored XSS into HTML context with nothing encoded

## 1. Vulnerability Discovery (The Analysis)
* **Target Endpoint / Location:** `/post/comment` (The comment submission form)
* **Vulnerability Type:** Client-Side (Stored Cross-Site Scripting)
* **Observation:** The application allows users to submit comments on blog posts. When a comment is submitted, it is permanently saved to the backend database and rendered publicly on the page. Testing input formatting revealed that HTML brackets (`<` and `>`) were not being encoded or stripped before being appended to the page layout.

## 2. Exploitation (The Hack)
* **Payload Used:** `<script>alert(1)</script>`
* **Mechanism:** 
  1. The payload was submitted through the public "Comment" field.
  2. The server accepted the payload and saved it into the comments table inside the database.
  3. When any user visits this specific blog post, the server fetches the comment text and drops it raw into the HTML response.
  4. The victim’s browser reads the page source, encounters the `<script>` tag, assumes it is a legitimate feature written by the website developers, and executes it.
* **Result:** The JavaScript executed successfully in the context of the session, triggering an `alert(1)` pop-up box.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application blindly trusts stored database content and dynamically reflects it into the document body as raw HTML.
* **The Correction:** The application must implement **Context-Aware Output Encoding** before rendering data inside HTML tags. 

### Vulnerable Code Example (Conceptual PHP/HTML Backend)
```php
// Vulnerable: Outputting raw string data directly from the comments database
echo "<p class='comment-text'>" . \$row['comment_body'] . "</p>";
```

### Secure Remediation Example (PHP Output Encoding)
```php
// Secure: Converting special HTML characters into safe, unexecutable entities
\(safe_comment = htmlspecialchars(\)row['comment_body'], ENT_QUOTES, 'UTF-8');
echo "<p class='comment-text'>" . \$safe_comment . "</p>";
// This turns "<script>" into "&lt;script&gt;", which displays harmlessly as text.
```

### The React Advantage (Why Frontend Roots Save You)
If this application utilized a modern frontend framework like React to map over comments, this vulnerability would be blocked by default:
```javascript
// Secure by default in React:
return <p className="comment-text">{commentBody}</p>; 
// React handles DOM manipulation securely by treating values strictly as strings, neutralizing script parsing.
```
