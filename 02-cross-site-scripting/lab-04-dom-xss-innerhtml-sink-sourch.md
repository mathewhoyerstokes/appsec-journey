This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an innerHTML assignment, which changes the HTML contents of a div element, using data from location.search.

To solve this lab, perform a cross-site scripting attack that calls the alert function.

Modern web browsers follow the official W3C HTML5 specification, which contains a built-in security rule specifically for innerHTML: Browsers must refuse to execute <script> elements that are inserted dynamically via innerHTML. [1]If you use your browser’s Inspect Element tool to look at the DOM tree after injecting a <script> tag, you will see the script code sitting there perfectly in the HTML, but the browser engine marks it as "dead code" and intentionally skips over its execution block.

because the browser blocks script tags we need to find another way to find another html element.
we can use here inline evernt handlers and by using the img tag this is the easiest way (onerror, onload, onmouseover)

<img src="doesnotexist" /> (we intentially give it a broken path to then cause the onerror event handler to show the alert)

- when the img tag does not find the path it fires the built in safetey function.

<img src"fefwegw" onerror="alert(1)"> (the browser will read the code in these brackets and run it)


# Lab: DOM XSS in innerHTML sink using source location.search

## 1. Vulnerability Discovery & Source/Sink Analysis
* **Target Vector:** Main Application Search Bar
* **Vulnerability Type:** Client-Side (DOM-Based Cross-Site Scripting)
* **Source:** `location.search` (URL Query Parameters)
* **Sink:** `innerHTML`

### Code Review (Vulnerable Context)
By inspecting the client-side JavaScript source code via browser Developer Tools (`Inspect Element`), I identified the following custom script block responsible for processing search queries:

```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
```

**Analysis:** The application extracts data directly from the browser's address bar via `location.search` and assigns the value directly to the `innerHTML` property of a DOM element (`searchMessage`). Because `innerHTML` parses strings directly into HTML elements without validation, this introduces a classic DOM-based XSS injection vector.

### The HTML5 Bypass Strategy
While the `innerHTML` sink accepts HTML, modern browsers strictly adhere to the W3C HTML5 specification, which states that `<script>` elements inserted via `innerHTML` must **not** execute. To bypass this restriction, alternative HTML elements with inline event handlers must be utilized. 

## 2. Exploitation (The Hack)
* **Payload Used:** `<img src=x onerror=alert(1)>`
* **Mechanism:**
  1. **`<img src=x`:** Injects a standard HTML image element, providing an intentionally broken or invalid file path (`x`).
  2. **`onerror=`:** Introduces an inline event handler attribute. Because the browser's rendering engine immediately fails to load the graphic asset from `src=x`, it triggers the error handler safety function.
  3. **`alert(1)>`:** Executes the custom JavaScript payload script block the exact millisecond the browser handles the broken graphic element in memory.
* **Result:** The browser successfully parsed the injected element into the DOM tree, threw a resource error, executed the inline payload script, and dropped the verification pop-up alert box on screen to complete the lab.

## 3. Remediation (The Fix)
* **Flawed Concept:** Trusting client-controlled string inputs and executing them as raw, executable markup code components using unsafe HTML parsing sinks (`innerHTML`).
* **The Correction:** Avoid using sinks that parse string literals as HTML markup. Migrate the rendering logic to utilize safe, text-only properties like `textContent` or `innerText`. These attributes instruct the browser's rendering engine to parse user parameters strictly as string literals, completely neutralizing script execution bugs.

### Vulnerable Code Example (Conceptual Frontend Context)
```javascript
// Vulnerable: Using innerHTML allows user strings to be parsed as executable DOM elements
const searchParam = new URLSearchParams(window.location.search).get('search');
document.getElementById('searchResults').innerHTML = searchParam;
```

### Secure Remediation Example (Safe Data Assignment)
```javascript
// Secure: Using textContent treats the input entirely as text, neutralizing XSS vectors
const searchParam = new URLSearchParams(window.location.search).get('search');
document.getElementById('searchResults').textContent = searchParam;
```





