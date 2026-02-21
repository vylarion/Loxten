// Content script for Loxten - monitors page content in real-time
class LoxtenContentScript {
  constructor() {
    this.observers = [];
    this.warningShown = false;
    this.suspiciousElements = [];
    this.trackerCount = 0;

    // Only run on actual web pages
    if (this.shouldRun()) {
      this.init();
    }
  }

  shouldRun() {
    // Don't run on extension pages, chrome pages, etc.
    const url = window.location.href;
    return !url.startsWith('chrome://') &&
      !url.startsWith('chrome-extension://') &&
      !url.startsWith('moz-extension://') &&
      !url.startsWith('about:');
  }

  init() {
    // Set up message listener first
    this.setupMessageListener();

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        this.startMonitoring();
      });
    } else {
      this.startMonitoring();
    }
  }

  startMonitoring() {
    try {
      // Start monitoring page content
      this.setupDOMObserver();
      this.analyzeCurrentPage();
      this.monitorForms();
      this.detectClickjacking();
      this.checkForCryptomining();

      // Send page data to background for AI analysis after a short delay
      setTimeout(() => this.sendPageDataForAI(), 2000);

      console.log('Loxten content script initialized on:', window.location.hostname);
    } catch (error) {
      console.error('Loxten content script error:', error);
    }
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      try {
        switch (message.type) {
          case 'security_warning':
            this.showSecurityWarning(message.analysis);
            break;
          case 'tracker_detected':
            this.handleTrackerDetection(message);
            break;
          case 'suspicious_elements':
            this.highlightSuspiciousElements(message.elements);
            break;
          case 'extract_page_data':
            const pageData = this.extractPageData();
            sendResponse(pageData);
            return true;
        }
        sendResponse({ success: true });
      } catch (error) {
        sendResponse({ error: error.message });
      }
    });
  }

  setupDOMObserver() {
    // Monitor for dynamically added content
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.analyzeNewElement(node);
            }
          });
        }
      });
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });

    this.observers.push(observer);
  }

  analyzeCurrentPage() {
    // Analyze the current page content
    this.checkForPhishingIndicators();
    this.analyzeForms();
    this.checkForSuspiciousScripts();
    this.detectHiddenElements();
  }

  checkForPhishingIndicators() {
    const indicators = [];

    // Check page text for phishing keywords
    const pageText = document.body ? document.body.textContent.toLowerCase() : '';
    const phishingKeywords = [
      'verify your account immediately',
      'account suspended',
      'click here now',
      'limited time offer',
      'confirm your identity',
      'unusual activity detected',
      'urgent action required',
      'winner selected',
      'claim your prize'
    ];

    phishingKeywords.forEach(keyword => {
      if (pageText.includes(keyword)) {
        indicators.push({
          type: 'phishing_language',
          element: 'page_content',
          description: `Suspicious phishing language detected: "${keyword}"`
        });
      }
    });

    // Check for fake login forms
    const loginForms = document.querySelectorAll('form input[type="password"]');
    loginForms.forEach(passwordInput => {
      const form = passwordInput.closest('form');
      if (form) {
        const action = form.getAttribute('action');
        if (action && !action.includes(window.location.hostname)) {
          indicators.push({
            type: 'external_login_form',
            element: form,
            description: 'Login form submits to external domain'
          });
        }
      }
    });

    // Check for fake security badges/logos
    const images = document.querySelectorAll('img');
    const securityKeywords = ['secure', 'verified', 'ssl', 'certificate', 'trust'];
    images.forEach(img => {
      const alt = (img.alt || '').toLowerCase();
      const src = (img.src || '').toLowerCase();

      if (securityKeywords.some(keyword => alt.includes(keyword) || src.includes(keyword))) {
        // Check if it's actually a legitimate security badge
        if (!this.isLegitimateSecurityBadge(img.src)) {
          indicators.push({
            type: 'fake_security_badge',
            element: img,
            description: 'Potentially fake security badge detected'
          });
        }
      }
    });

    if (indicators.length > 0) {
      this.reportSuspiciousContent(indicators);
    }
  }

  isLegitimateSecurityBadge(src) {
    const legitimateDomains = [
      'ssl.com',
      'symantec.com',
      'verisign.com',
      'comodo.com',
      'thawte.com',
      'godaddy.com'
    ];

    try {
      const url = new URL(src, window.location.href);
      return legitimateDomains.some(domain => url.hostname.includes(domain));
    } catch {
      return false;
    }
  }

  analyzeForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      // Check for insecure password forms
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      if (passwordInputs.length > 0) {
        if (window.location.protocol !== 'https:') {
          this.showRealTimeWarning('⚠️ Password form on insecure connection!');
        }

        if (form.method && form.method.toLowerCase() === 'get') {
          this.showRealTimeWarning('⚠️ Password form using insecure GET method!');
        }
      }

      // Check for forms with suspicious hidden inputs
      const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
      hiddenInputs.forEach(input => {
        if (input.value && input.value.length > 200) {
          this.reportSuspiciousContent([{
            type: 'suspicious_hidden_input',
            element: input,
            description: 'Hidden form input with unusually large value'
          }]);
        }
      });
    });
  }

  checkForSuspiciousScripts() {
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      if (script.src) {
        // External script analysis
        try {
          const url = new URL(script.src, window.location.href);
          if (this.isSuspiciousScriptSource(url)) {
            this.reportSuspiciousContent([{
              type: 'suspicious_external_script',
              element: script,
              description: `Suspicious external script: ${url.hostname}`
            }]);
          }
        } catch (e) {
          this.reportSuspiciousContent([{
            type: 'invalid_script_url',
            element: script,
            description: 'Script with invalid URL'
          }]);
        }
      } else if (script.textContent) {
        // Inline script analysis
        if (this.isSuspiciousScriptContent(script.textContent)) {
          this.reportSuspiciousContent([{
            type: 'suspicious_inline_script',
            element: script,
            description: 'Inline script with suspicious content'
          }]);
        }
      }
    });
  }

  isSuspiciousScriptSource(url) {
    // Check for suspicious patterns in script sources
    const suspiciousPatterns = [
      /\d+\.\d+\.\d+\.\d+/, // IP addresses
      /[a-z0-9]{20,}\.com/, // Random long domains
      /bit\.ly|tinyurl|short/, // URL shorteners
      /\.tk$|\.ml$|\.ga$|\.cf$/ // Suspicious TLDs
    ];

    return suspiciousPatterns.some(pattern => pattern.test(url.hostname));
  }

  isSuspiciousScriptContent(content) {
    const suspiciousPatterns = [
      /eval\s*\(/i,
      /document\.write\s*\(/i,
      /innerHTML\s*=.*<script/i,
      /crypto.*mine/i,
      /bitcoin|ethereum|monero/i,
      /keylogger|keypress.*password/i,
      /atob\s*\(/i, // Base64 decoding often used in obfuscation
      /String\.fromCharCode/i // Character code conversion for obfuscation
    ];

    return suspiciousPatterns.some(pattern => pattern.test(content));
  }

  detectHiddenElements() {
    // Look for hidden iframes and divs that might be malicious
    const hiddenElements = document.querySelectorAll('iframe, div, embed, object');
    hiddenElements.forEach(element => {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();

      if ((style.display === 'none' ||
        style.visibility === 'hidden' ||
        style.opacity === '0' ||
        rect.width < 5 ||
        rect.height < 5) &&
        (element.tagName.toLowerCase() === 'iframe' ||
          element.innerHTML.includes('script'))) {

        this.reportSuspiciousContent([{
          type: 'hidden_malicious_element',
          element: element,
          description: `Hidden ${element.tagName.toLowerCase()} element detected`
        }]);
      }
    });
  }

  detectClickjacking() {
    // Check if page is being framed
    if (window.self !== window.top) {
      try {
        // Try to access parent location
        const parentHost = window.parent.location.hostname;
        if (parentHost !== window.location.hostname) {
          this.reportSuspiciousContent([{
            type: 'potential_clickjacking',
            description: 'Page loaded in iframe from different domain'
          }]);
        }
      } catch (e) {
        // Cross-origin error - potentially malicious framing
        this.reportSuspiciousContent([{
          type: 'cross_origin_framing',
          description: 'Page framed by unknown origin - potential clickjacking'
        }]);
      }
    }
  }

  checkForCryptomining() {
    // Look for common cryptomining scripts and indicators
    const miningIndicators = [
      'coinhive',
      'jsecoin',
      'crypto-loot',
      'webminepool',
      'authedmine',
      'coin-have',
      'minero'
    ];

    const pageContent = document.documentElement.outerHTML.toLowerCase();
    miningIndicators.forEach(indicator => {
      if (pageContent.includes(indicator)) {
        this.reportSuspiciousContent([{
          type: 'cryptomining_script',
          description: `Potential cryptomining script detected: ${indicator}`
        }]);
      }
    });

    // Monitor for unusual CPU usage patterns
    this.monitorCPUUsage();
  }

  monitorCPUUsage() {
    let startTime = performance.now();
    let iterations = 0;
    let checkCount = 0;
    const maxChecks = 10;

    const checkCPU = () => {
      iterations++;
      const currentTime = performance.now();

      if (currentTime - startTime > 1000) { // Check every second
        checkCount++;

        // If we can't complete many iterations, CPU might be busy
        if (iterations < 50) {
          this.reportSuspiciousContent([{
            type: 'high_cpu_usage',
            description: 'Unusually high CPU usage - possible cryptomining'
          }]);
          return; // Stop monitoring after detection
        }

        startTime = currentTime;
        iterations = 0;

        // Stop after checking for a reasonable time
        if (checkCount >= maxChecks) {
          return;
        }
      }

      requestAnimationFrame(checkCPU);
    };

    requestAnimationFrame(checkCPU);
  }

  monitorForms() {
    // Monitor form submissions for data exfiltration
    document.addEventListener('submit', (event) => {
      const form = event.target;
      if (form.tagName && form.tagName.toLowerCase() === 'form') {
        this.analyzeFormSubmission(form);
      }
    });
  }

  analyzeFormSubmission(form) {
    const formData = new FormData(form);
    const sensitiveFields = ['password', 'ssn', 'social', 'credit', 'card', 'cvv', 'security', 'pin'];

    let hasSensitiveData = false;
    for (const [key, value] of formData.entries()) {
      const keyLower = key.toLowerCase();
      if (sensitiveFields.some(field => keyLower.includes(field))) {
        hasSensitiveData = true;
        break;
      }
    }

    if (hasSensitiveData) {
      const action = form.action || window.location.href;
      try {
        const actionUrl = new URL(action, window.location.href);

        if (actionUrl.protocol !== 'https:') {
          this.showRealTimeWarning('🚨 Sensitive data being sent over insecure connection!');
        }

        if (actionUrl.hostname !== window.location.hostname) {
          this.showRealTimeWarning('🚨 Sensitive data being sent to external domain!');
        }
      } catch (e) {
        this.showRealTimeWarning('🚨 Form submitting to invalid URL!');
      }
    }
  }

  analyzeNewElement(element) {
    // Analyze dynamically added elements
    if (!element.tagName) return;

    switch (element.tagName.toLowerCase()) {
      case 'script':
        if (element.src && this.isSuspiciousScriptSource(new URL(element.src))) {
          this.reportSuspiciousContent([{
            type: 'dynamic_malicious_script',
            element: element,
            description: 'Suspicious script loaded dynamically'
          }]);
        }
        break;

      case 'iframe':
        const style = window.getComputedStyle(element);
        if (style.display === 'none' ||
          style.visibility === 'hidden' ||
          element.width < 10 ||
          element.height < 10) {
          this.reportSuspiciousContent([{
            type: 'hidden_iframe',
            element: element,
            description: 'Hidden iframe loaded dynamically'
          }]);
        }
        break;
    }
  }

  showSecurityWarning(analysis) {
    if (this.warningShown) return; // Don't show multiple warnings

    this.warningShown = true;
    const modal = this.createWarningModal(analysis);
    document.body.appendChild(modal);
  }

  createWarningModal(analysis) {
    const modal = document.createElement('div');
    modal.id = 'loxten-warning-modal';
    modal.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      height: 100% !important;
      background: rgba(0,0,0,0.9) !important;
      z-index: 999999999 !important;
      display: flex !important;
      justify-content: center !important;
      align-items: center !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      background: white !important;
      padding: 30px !important;
      border-radius: 10px !important;
      max-width: 500px !important;
      text-align: center !important;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important;
      margin: 20px !important;
    `;

    const riskColor = analysis.riskScore >= 80 ? '#dc3545' :
      analysis.riskScore >= 60 ? '#fd7e14' : '#ffc107';

    content.innerHTML = `
      <div style="color: ${riskColor}; font-size: 48px; margin-bottom: 16px;">⚠️</div>
      <h2 style="color: ${riskColor}; margin: 0 0 16px 0; font-size: 24px;">Security Warning</h2>
      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333;"><strong>Risk Score:</strong> ${analysis.riskScore}/100</p>
      <div style="text-align: left; margin: 20px 0; max-height: 200px; overflow-y: auto;">
        ${analysis.threats.map(threat =>
      `<div style="margin: 10px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid ${riskColor};">
            <strong style="color: ${riskColor}; text-transform: uppercase; font-size: 12px;">${threat.type.replace(/_/g, ' ')}</strong><br>
            <span style="color: #555; font-size: 14px;">${threat.description}</span>
          </div>`
    ).join('')}
      </div>
      <div style="margin-top: 30px; display: flex; gap: 10px; justify-content: center;">
        <button id="loxten-continue" style="background: #007bff; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 14px;">Continue Anyway</button>
        <button id="loxten-goback" style="background: #dc3545; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 14px;">Go Back</button>
      </div>
      <div style="margin-top: 20px; font-size: 12px; color: #666;">
        Protected by Loxten Security Extension
      </div>
    `;

    modal.appendChild(content);

    // Event listeners
    content.querySelector('#loxten-continue').addEventListener('click', () => {
      modal.remove();
      this.warningShown = false;
    });

    content.querySelector('#loxten-goback').addEventListener('click', () => {
      history.back();
    });

    return modal;
  }

  showRealTimeWarning(message) {
    // Show brief notification for real-time warnings
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed !important;
      top: 20px !important;
      right: 20px !important;
      background: #dc3545 !important;
      color: white !important;
      padding: 15px 20px !important;
      border-radius: 8px !important;
      z-index: 999999998 !important;
      max-width: 300px !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
      font-size: 14px !important;
      line-height: 1.4 !important;
      animation: slideIn 0.3s ease-out !important;
    `;

    // Add CSS animation
    if (!document.getElementById('loxten-styles')) {
      const style = document.createElement('style');
      style.id = 'loxten-styles';
      style.textContent = `
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      `;
      document.head.appendChild(style);
    }

    notification.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px;">
        <strong>Loxten</strong>
        <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: white; cursor: pointer; font-size: 16px; margin-left: auto;">×</button>
      </div>
      <div style="margin-top: 5px;">${message}</div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove();
      }
    }, 5000);
  }

  handleTrackerDetection(message) {
    this.trackerCount++;
    console.log(`Loxten blocked tracker: ${message.domain}`);
  }

  highlightSuspiciousElements(elements) {
    elements.forEach(elementInfo => {
      if (elementInfo.element && elementInfo.element.parentNode) {
        // Add red border to suspicious elements
        elementInfo.element.style.border = '2px solid red !important';
        elementInfo.element.style.boxShadow = '0 0 10px rgba(255,0,0,0.5) !important';

        // Add warning tooltip
        elementInfo.element.title = `Loxten Warning: ${elementInfo.description}`;
      }
    });
  }

  reportSuspiciousContent(indicators) {
    // Send suspicious content to background script
    chrome.runtime.sendMessage({
      type: 'report_suspicious',
      data: {
        url: window.location.href,
        domain: window.location.hostname,
        indicators: indicators,
        timestamp: Date.now()
      }
    }).catch(() => {
      // Extension context might be invalid
      console.log('Could not report suspicious content - extension context invalid');
    });

    // Log for debugging
    console.log('Loxten detected suspicious content:', indicators);
  }

  /**
   * Extract structured page data for AI analysis.
   * Gathers text, forms, scripts, iframes, and meta tags.
   */
  extractPageData() {
    const data = {
      url: window.location.href,
      title: document.title || '',
      text_content: '',
      forms: [],
      external_scripts: [],
      meta_tags: {},
      has_password_field: false,
      iframes: []
    };

    // Extract visible text (truncated to 4000 chars)
    try {
      const body = document.body;
      if (body) {
        data.text_content = body.innerText.substring(0, 4000);
      }
    } catch (e) {}

    // Extract form info
    try {
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
        const inputs = Array.from(form.querySelectorAll('input')).map(inp => ({
          type: inp.type || 'text',
          name: inp.name || ''
        }));
        data.forms.push({
          action: form.action || '',
          method: form.method || 'get',
          inputs: inputs.slice(0, 20)
        });

        // Check for password fields
        if (inputs.some(i => i.type === 'password')) {
          data.has_password_field = true;
        }
      });
    } catch (e) {}

    // Extract external script sources
    try {
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        if (script.src) data.external_scripts.push(script.src);
      });
      data.external_scripts = data.external_scripts.slice(0, 30);
    } catch (e) {}

    // Extract meta tags
    try {
      const metas = document.querySelectorAll('meta');
      metas.forEach(meta => {
        const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
        const content = meta.getAttribute('content') || '';
        if (name && content) data.meta_tags[name] = content.substring(0, 200);
      });
    } catch (e) {}

    // Extract iframe sources
    try {
      const iframes = document.querySelectorAll('iframe');
      iframes.forEach(iframe => {
        if (iframe.src) data.iframes.push(iframe.src);
      });
      data.iframes = data.iframes.slice(0, 10);
    } catch (e) {}

    return data;
  }

  /**
   * Send page data to background script for AI analysis
   */
  sendPageDataForAI() {
    try {
      const pageData = this.extractPageData();
      chrome.runtime.sendMessage({
        type: 'page_data_for_ai',
        data: pageData
      }).catch(() => {
        // Extension context might be invalid
      });
    } catch (e) {
      // Silently fail
    }
  }

  cleanup() {
    // Clean up observers when page unloads
    this.observers.forEach(observer => {
      observer.disconnect();
    });
    this.observers = [];
  }
}

// Initialize content script
let loxtenContent;
try {
  loxtenContent = new LoxtenContentScript();

  // Cleanup on page unload
  window.addEventListener('beforeunload', () => {
    if (loxtenContent) {
      loxtenContent.cleanup();
    }
  });
} catch (error) {
  console.error('Loxten content script failed to initialize:', error);
}
