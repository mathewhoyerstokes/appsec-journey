
This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's $() selector function to auto-scroll to a given post, whose title is passed via the location.hash property.

To solve the lab, deliver an exploit to the victim that calls the print() function in their browser.


# Lab: DOM XSS in jQuery selector sink using a hashchange event

## 1. Vulnerability Discovery & Source/Sink Analysis
* **Target Vector:** URL Hash Parameters / Routing Logic
* **Vulnerability Type:** Client-Side (DOM-Based Cross-Site Scripting - jQuery Framework Variant)
* **Source:** `location.hash` [1]
* **Sink:** jQuery Selector Function (`$()` / `jQuery()`) [1]

### Code Review (Vulnerable Context)
By inspecting the client-side source code via the browser Developer Tools, I located a tracking function bound to the window's hash navigation state:

```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash); // Vulnerable Sink
    element.slideDown();
});
```

**Analysis:** The application registers an asynchronous event listener tracking the window's `hashchange` property. When a hash modification occurs, the literal value of `location.hash` is passed unfiltered directly into the jQuery selector function. In vulnerable legacy versions of jQuery, passing an explicit HTML string structure (e.g., `<tag>`) into the selector forces the engine to dynamically instantiate and execute the HTML component rather than querying an existing node element.

## 2. Exploitation (The Hack)
* **Payload Used:** `#<img src=x onerror=alert(1)>`
* **Delivery Mechanism:** 
  1. The `#` character triggers the window's native hash boundaries.
  2. The input string `<img src=x onerror=alert(1)>` satisfies jQuery's parsing regex for runtime HTML creation.
  3. The image path points to an invalid string variable (`x`), forcing the browser to instantly jump to the `onerror` fallback callback routine execution path.
* **Result:** The vulnerable jQuery framework initialized the node in client memory, parsed the inline event handler, and triggered an execution pop-up alert box on screen to complete the lab.

## 3. Remediation (The Fix)
* **Flawed Concept:** Passing untrusted, user-controlled location hashes directly into multifunctional framework execution sinks like `$()` without validation.
* **The Correction:** Update the application's jQuery dependency framework to a modern version (3.0+) where the selector function strictly queries existing elements and handles raw string instantiation exclusively through explicit, isolated methods like `$.parseHTML()`. Alternatively, sanitize the hash string using a regex checklist to ensure it strictly conforms to an alphanumeric element ID format before querying.

### Vulnerable Code Example (Conceptual Client-Side Context)
```javascript
// Vulnerable: Passing raw hashes directly allows dynamic component synthesis
\$(window).on('hashchange', function() {
    let target = \$(location.hash);
    target.show();
});
```

### Secure Remediation Example (Explicit ID Binding)
```javascript
// Secure: Restricting inputs to a sanitized alphanumeric query string completely neutralizes XSS execution
\$(window).on('hashchange', function() {
    // Sanitize to extract only the alphanumeric ID name string, stripping HTML characters
    let safeId = location.hash.replace(/[^a-zA-Z0-9_-]/g, ''); 
    if (safeId) {
        let target = \$('#' + safeId);
        target.show();
    }
});
```
