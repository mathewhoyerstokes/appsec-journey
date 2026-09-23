# Lab: Reflected XSS into HTML context with nothing encoded

## 1. Vulnerability Discovery (The Analysis)
* **Target Endpoint / Parameter:** `/search?search=query`
* **Vulnerability Type:** Client-Side (Reflected Cross-Site Scripting)
* **Observation:** The application accepts user input via the `search` query parameter and reflects it directly back into the HTML body page without any sanitization or output encoding. 

## 2. Exploitation (The Hack)
* **Payload Used:** `<script>alert(1)</script>`
* **Mechanism:** Because the application inputs the raw search term directly into the page source, injecting standard HTML script tags forces the browser to interpret our input text as executable JavaScript code.
* **Result:** The script executes successfully in the user's browser session, triggering a pop-up box (`alert(1)`) and confirming complete execution control.

## 3. Remediation (The Fix)
* **Flawed Concept:** The application blindly trusts user input and injects it straight into the raw DOM context as HTML elements.

* **The Correction (Context-Aware Output Encoding):** 
Before rendering any user-controlled input back into the page, the backend or client framework must safely escape or encode special HTML characters. This transforms potential code characters into safe literal text codes.

### Vulnerable Code Example (Vanilla JS / Server-side HTML generation)
```javascript
// Vulnerable: Dropping raw user text straight into the page layout
document.getElementById('search-results').innerHTML = "You searched for: " + userInput;
```

### Secure Remediation Example (Vanilla JS / Native Context)
```javascript
// Secure: Treating input strictly as safe text content, not HTML instructions
const resultText = document.getElementById('search-results');
resultText.textContent = "You searched for: " + userInput; 
// TextContent automatically encodes characters like < into &lt; and > into &gt;
```

### The React Advantage (Why React is Safe by Default)
If this application were built using modern React components, the input would inherently be treated as raw text strings within JavaScript brackets:
```javascript
// Secure by default in React:
return <div>You searched for: {userInput}</div>; 
// React automatically performs context-aware escaping on strings before rendering them.
```
*Note: In React, this vulnerability would only occur if a developer intentionally bypassed protections by using `dangerouslySetInnerHTML={{__html: userInput}}`.*
