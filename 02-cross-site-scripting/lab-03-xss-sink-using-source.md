# Lab: DOM XSS in document.write sink using source location.search

## 1. Vulnerability Discovery & Source/Sink Analysis
* **Target Vector:** Main Application Search Bar
* **Vulnerability Type:** Client-Side (DOM-Based Cross-Site Scripting)
* **Source:** `location.search` (URL Query Parameters)
* **Sink:** `document.write()`

### Code Review (Vulnerable Context)
By inspecting the client-side source code via browser Developer Tools (`Inspect Element`), I located the following custom tracking script block responsible for processing query parameters:

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?search=' + query + '">');
}
```

**Analysis:** The application extracts data directly from the browser's address bar via `location.search` and uses concatenation to dynamically output the string directly inside an `<img>` tag attribute. Because it lacks validation or contextual output encoding, the execution flow can be manipulated entirely on the client side.

## 2. Exploitation (The Hack)
* **Payload Used:** `"><svg onload=alert(1)>`
* **Mechanism:**
  1. **`"` (Double Quote):** Explicitly breaks out of and terminates the developer's intended `src` attribute tracking parameter wrapper.
  2. **`>` (Greater-Than Bracket):** Breaks the functional logic encapsulation boundary, closing down the initial `<img>` element tag structure.
  3. **`<svg onload=alert(1)>`:** Introduces a standalone, high-privilege vector element directly into the DOM tree. The component triggers its `onload` event vector the exact millisecond the local browser reads it in memory.
* **Result:** The client browser parsed the structural modification, executed the native payload logic loop, and dropped a standalone execution verification pop-up alert box on screen to complete the lab.

## 3. Remediation (The Fix)
* **Flawed Concept:** Trusting raw client-controlled strings and executing them as executable structural code components using unsafe sinks (`document.write`).
* **The Correction:** Avoid using raw injection sinks. Migrate the rendering engine to utilize safe, text-only assignment attributes (like `textContent` or `innerText`) that instruct the rendering layout engine to treat parameters exclusively as text strings, never executable code blocks.

### Vulnerable Code Example (Conceptual Client-Side Context)
```javascript
// Vulnerable: Direct string concatenation allows input to dictate DOM structure
const searchBoxInput = new URLSearchParams(window.location.search).get('search');
document.write('<div>Result: ' + searchBoxInput + '</div>');
```

### Secure Remediation Example (Safe DOM Element Creation)
```javascript
// Secure: Using innerText ensures parameters are parsed strictly as text literals, neutralizing script execution
const searchBoxInput = new URLSearchParams(window.location.search).get('search');
const displayDiv = document.createElement('div');
displayDiv.innerText = 'Result: ' + searchBoxInput;
document.body.appendChild(displayDiv);
```
