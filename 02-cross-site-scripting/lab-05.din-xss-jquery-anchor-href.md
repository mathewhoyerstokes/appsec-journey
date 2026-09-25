This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's $ selector function to find an anchor element, and changes its href attribute using data from location.search.

To solve this lab, make the "back" link alert document.cookie.

- first thing to do is that we know that we have a vunurable backlink is (we need to identify it) in this case it is
the submit feedback form atz the bottom. 

- we need to inspect that backlink with the inspector. we can see the the href="/" meaning the whole site.

<a id="backLink" href="/">Back</a> (how did that href get assigned?)

- reading further through the code we can see that the script tag is maniukating the DOM and assigning the href.

$ sign is jquery and when we have the $ sign 

so what we can do here is write JS directly into the href (you would say that it is bad practice) as a DEV but very useful to know as a hacker 


# Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

## 1. Vulnerability Discovery & Source/Sink Analysis
* **Target Endpoint / Page:** `/feedback`
* **Vulnerability Type:** Client-Side (DOM-Based Cross-Site Scripting via Attribute Injection)
* **Source:** `location.search` (`returnPath` URL parameter)
* **Sink:** jQuery `.attr("href", ...)` method

### Code Review (Vulnerable Context)
By inspecting the client-side JavaScript source layout via browser Developer Tools (`Inspect Element`), I identified the following custom jQuery script block responsible for managing page navigation structures:

```javascript
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

**Analysis:** The application reads parameters directly from the URL query string (`window.location.search`) and maps the user-controlled value into an anchor element's `href` attribute using jQuery's `.attr()` method. Because it lacks validation filters against executable URI schemes, the browser can be forced to execute arbitrary JavaScript payloads if the link is clicked.

## 2. Exploitation (The Hack)
* **Payload Used:** `javascript:alert(document.cookie)`
* **Full URL Input:** `/feedback?returnPath=javascript:alert(document.cookie)`
* **Mechanism:**
  1. **`javascript:` (Pseudo-Protocol):** Rather than breaking out of the attribute quotes with HTML brackets, the payload utilizes the native `javascript:` protocol scheme inside the target `href` anchor tag value.
  2. **`alert(document.cookie)`:** When the user clicks the rendering element link, the browser's native URL parsing engine acts as an execution trigger, executing everything after the colon directly within the session context.
* **Result:** The user clicked the back navigational anchor link, firing the injected JavaScript statement string immediately, popping the session verification box, and completing the lab objective.

## 3. Remediation (The Fix)
* **Flawed Concept:** Trusting unvalidated client-controlled URL string variables and mapping them directly inside high-privilege navigational properties like `href`.
* **The Correction:** Implement strict URI validation checks on all incoming parameters before passing them to configuration methods. Ensure that the input string strictly maps to safe relative layout paths (e.g., starting exclusively with a forward slash `/`) and rejects dangerous protocol headers like `javascript:` or `data:`.

### Vulnerable Code Example (Conceptual jQuery Context)
```javascript
// Vulnerable: Blind attribute assignment allows input to dictate the execution schema
const userUrl = new URLSearchParams(window.location.search).get('returnPath');
\$('#navLink').attr('href', userUrl);
```

### Secure Remediation Example (White-list Pattern Matching)
```javascript
// Secure: Strict regular expression matching guarantees parameters are relative paths, not scripts
const userUrl = new URLSearchParams(window.location.search).get('returnPath');

if (userUrl && userUrl.startsWith('/') && !userUrl.startsWith('//')) {
    \$('#navLink').attr('href', userUrl);
} else {
    \$('#navLink').attr('href', '/'); // Fallback safe route
}
```



