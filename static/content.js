// Loxten v2 — Content Script
// Runs on every page: phishing content analysis, form monitoring, link safety preview.

class LoxtenContentScript {
  constructor() {
    this.warningShown = false;
    this.observers = [];
    this.linkTooltip = null;
    this.linkSafetyEnabled = true;
    if (this.shouldRun()) this.init();
  }

  shouldRun() {
    const url = window.location.href;
    return !url.startsWith('chrome://') && !url.startsWith('chrome-extension://') &&
           !url.startsWith('moz-extension://') && !url.startsWith('about:');
  }

  init() {
    this.setupMessageListener();
    this.loadSettings();
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.startMonitoring());
    } else {
      this.startMonitoring();
    }
  }

  async loadSettings() {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'get_settings' });
      if (res) {
        this.linkSafetyEnabled = res.linkSafetyPreview !== false;
      }
    } catch (_) {}
  }

  startMonitoring() {
    try {
      this.analyzeCurrentPage();
      this.monitorForms();
      if (this.linkSafetyEnabled) this.setupLinkSafetyPreview();
      this.setupDOMObserver();
      this.initAnnoyanceBlocker();
    } catch (e) {
      console.error('[Loxten] content script error:', e);
    }
  }

  // ─── Message Handling ───

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((msg, sender, respond) => {
      try {
        if (msg.type === 'security_warning') this.showSecurityWarning(msg.analysis);
        if (msg.type === 'settings_updated') this.onSettingsUpdated(msg.settings);
        respond({ success: true });
      } catch (e) {
        respond({ error: e.message });
      }
    });
  }

  onSettingsUpdated(settings) {
    const wasEnabled = this.linkSafetyEnabled;
    this.linkSafetyEnabled = settings.linkSafetyPreview !== false;
    if (this.linkSafetyEnabled && !wasEnabled) {
      this.setupLinkSafetyPreview();
    } else if (!this.linkSafetyEnabled && wasEnabled) {
      this.disableLinkSafetyPreview();
    }
  }

  disableLinkSafetyPreview() {
    this.hideTooltip();
    document.querySelectorAll('[data-loxten-warning]').forEach(el => {
      el.style.outline = '';
      el.style.outlineOffset = '';
      el.removeAttribute('data-loxten-warning');
    });
  }

  // ─── Page Analysis ───

  analyzeCurrentPage() {
    this.checkForPhishingIndicators();
    this.analyzeForms();
    this.detectHiddenIframes();
  }

  checkForPhishingIndicators() {
    const indicators = [];
    const pageText = document.body ? document.body.textContent.toLowerCase() : '';

    // Phishing urgency language
    const phishingPhrases = [
      'verify your account immediately',
      'account has been suspended',
      'confirm your identity now',
      'unusual activity detected',
      'urgent action required',
      'your account will be closed',
      'click here to restore access',
      'verify your payment method',
    ];
    for (const phrase of phishingPhrases) {
      if (pageText.includes(phrase)) {
        indicators.push({
          type: 'phishing_language',
          description: `Phishing language detected: "${phrase}"`
        });
        break; // one is enough
      }
    }

    // Login forms submitting to external domains
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const hasPassword = form.querySelector('input[type="password"]');
      if (!hasPassword) continue;

      const action = form.getAttribute('action');
      if (action && !action.startsWith('/') && !action.startsWith('#')) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== window.location.hostname) {
            indicators.push({
              type: 'external_login_form',
              description: `Login form submits credentials to external domain: ${actionUrl.hostname}`
            });
          }
        } catch (_) {}
      }

      // formaction override on submit buttons
      const submits = form.querySelectorAll('button[formaction], input[formaction]');
      for (const btn of submits) {
        try {
          const faUrl = new URL(btn.getAttribute('formaction'), window.location.href);
          if (faUrl.hostname !== window.location.hostname) {
            indicators.push({
              type: 'external_login_form',
              description: `Submit button redirects credentials to: ${faUrl.hostname}`
            });
          }
        } catch (_) {}
      }
    }

    if (indicators.length > 0) this.reportSuspicious(indicators);
  }

  analyzeForms() {
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      if (passwordInputs.length === 0) continue;

      // Password over HTTP
      if (window.location.protocol !== 'https:') {
        this.showToast('⚠️ Password form on insecure HTTP connection!');
      }

      // Password via GET method
      if (form.method && form.method.toLowerCase() === 'get') {
        this.showToast('⚠️ Password form using GET method — credentials will appear in URL!');
      }

      // autocomplete="off" on password fields (common phishing trick)
      for (const pw of passwordInputs) {
        if (pw.getAttribute('autocomplete') === 'off') {
          this.reportSuspicious([{
            type: 'suspicious_form',
            description: 'Password field has autocomplete disabled — common on phishing pages'
          }]);
          break;
        }
      }
    }
  }

  detectHiddenIframes() {
    const iframes = document.querySelectorAll('iframe');
    for (const iframe of iframes) {
      const style = window.getComputedStyle(iframe);
      const rect = iframe.getBoundingClientRect();
      if ((style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' ||
           rect.width < 3 || rect.height < 3) && iframe.src) {
        this.reportSuspicious([{
          type: 'hidden_iframe',
          description: `Hidden iframe detected loading: ${new URL(iframe.src, location.href).hostname}`
        }]);
      }
    }
  }

  // ─── Form Submission Monitoring ───

  monitorForms() {
    document.addEventListener('submit', (e) => {
      const form = e.target;
      if (!form || form.tagName?.toLowerCase() !== 'form') return;
      this.analyzeFormSubmission(form);
    });
  }

  analyzeFormSubmission(form) {
    const sensitiveFields = ['password','ssn','social','credit','card','cvv','pin','secret'];
    let hasSensitive = false;

    try {
      const fd = new FormData(form);
      for (const [key] of fd.entries()) {
        if (sensitiveFields.some(f => key.toLowerCase().includes(f))) {
          hasSensitive = true;
          break;
        }
      }
    } catch (_) { return; }

    if (!hasSensitive) return;

    const action = form.action || window.location.href;
    try {
      const actionUrl = new URL(action, window.location.href);
      if (actionUrl.protocol !== 'https:') {
        this.showToast('🚨 Sensitive data being sent over insecure connection!');
      }
      if (actionUrl.hostname !== window.location.hostname) {
        this.showToast('🚨 Sensitive data being sent to external domain: ' + actionUrl.hostname);
      }
    } catch (_) {
      this.showToast('🚨 Form submitting to invalid URL!');
    }
  }

  // ─── Link Safety Preview ───

  setupLinkSafetyPreview() {
    // Highlight deceptive links where visible text looks like a URL but doesn't match href
    this.scanLinksForMismatch();

    // Tooltip on hover showing real destination
    document.addEventListener('mouseover', (e) => {
      const link = e.target.closest('a[href]');
      if (!link) { this.hideTooltip(); return; }
      this.checkLink(link);
    });

    document.addEventListener('mouseout', (e) => {
      const link = e.target.closest('a[href]');
      if (link) this.hideTooltip();
    });
  }

  scanLinksForMismatch() {
    const links = document.querySelectorAll('a[href]');
    for (const link of links) {
      if (this.isDeceptiveLink(link)) {
        link.style.outline = '2px dashed #e74c3c';
        link.style.outlineOffset = '2px';
        link.setAttribute('data-loxten-warning', 'Displayed URL does not match actual destination');
      }
    }
  }

  isDeceptiveLink(link) {
    const text = link.textContent.trim();
    const href = link.getAttribute('href') || '';

    // Skip non-URL text, very short text, or same-page anchors
    if (!text || text.length < 8 || href.startsWith('#') || href.startsWith('javascript:')) return false;

    // Check if text looks like a URL
    const urlPattern = /^https?:\/\/[^\s]+$|^www\.[^\s]+$|^[a-z0-9-]+\.[a-z]{2,}[\/\S]*$/i;
    if (!urlPattern.test(text)) return false;

    // Extract domain from displayed text
    let textDomain;
    try {
      const normalized = text.startsWith('http') ? text : 'https://' + text;
      textDomain = new URL(normalized).hostname.toLowerCase();
    } catch (_) { return false; }

    // Extract domain from actual href
    let hrefDomain;
    try {
      const hrefUrl = new URL(href, window.location.href);
      hrefDomain = hrefUrl.hostname.toLowerCase();
    } catch (_) { return false; }

    // Mismatch = deceptive
    return textDomain !== hrefDomain;
  }

  checkLink(link) {
    const href = link.getAttribute('href') || '';

    // Warn on data: or javascript: URIs
    if (href.startsWith('data:') || href.startsWith('javascript:')) {
      this.showLinkTooltip(link, `⚠️ ${href.split(':')[0]}: URI — may execute code`);
      return;
    }

    // Show warning if deceptive
    if (link.hasAttribute('data-loxten-warning')) {
      try {
        const realDomain = new URL(href, location.href).hostname;
        this.showLinkTooltip(link, `⚠️ Link text doesn't match destination: ${realDomain}`);
      } catch (_) {}
    }
  }

  showLinkTooltip(anchor, text) {
    this.hideTooltip();
    const tip = document.createElement('div');
    tip.id = 'loxten-link-tooltip';
    tip.textContent = text;
    Object.assign(tip.style, {
      position: 'fixed', zIndex: '999999997',
      background: '#1a1a2e', color: '#e74c3c',
      padding: '6px 12px', borderRadius: '6px', fontSize: '12px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      fontWeight: '600', boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
      border: '1px solid #e74c3c33', pointerEvents: 'none',
      maxWidth: '320px', wordBreak: 'break-word',
    });

    const rect = anchor.getBoundingClientRect();
    tip.style.left = Math.min(rect.left, window.innerWidth - 340) + 'px';
    tip.style.top = (rect.bottom + 6) + 'px';

    document.body.appendChild(tip);
    this.linkTooltip = tip;
  }

  hideTooltip() {
    if (this.linkTooltip) { this.linkTooltip.remove(); this.linkTooltip = null; }
  }

  // ─── Annoyance Blocker ───

  async initAnnoyanceBlocker() {
    try {
      const settings = await chrome.runtime.sendMessage({ type: 'get_settings' });
      if (settings && settings.blockAnnoyances) {
        this.applyAnnoyanceBlocker();
      }
    } catch (_) {
      // Extension context may be invalid, skip
    }
  }

  applyAnnoyanceBlocker() {
    // Inject CSS to hide known annoyance elements
    const style = document.createElement('style');
    style.id = 'loxten-annoyance-blocker';
    style.textContent = `
      /* ── Cookie Consent Banners ── */
      #onetrust-consent-sdk,
      #onetrust-banner-sdk,
      .onetrust-pc-dark-filter,
      #CybotCookiebotDialog,
      #CybotCookiebotDialogBodyUnderlay,
      .cc-window,
      .cc-banner,
      .cc-revoke,
      #cookie-notice,
      #cookie-law-info-bar,
      #cookie-consent,
      .cookie-consent,
      .cookie-banner,
      .cookie-popup,
      .cookie-notice,
      .cookie-alert,
      .cookie-warning,
      .cookieConsent,
      .js-cookie-consent,
      [id*="cookie-banner"],
      [id*="cookie-consent"],
      [id*="cookie-notice"],
      [id*="cookieBanner"],
      [id*="gdpr"],
      [class*="cookie-banner"],
      [class*="cookie-consent"],
      [class*="cookie-notice"],
      [class*="cookieBanner"],
      [class*="gdpr-banner"],
      [class*="consent-banner"],
      [class*="CookieConsent"],
      .osano-cm-window,
      .osano-cm-dialog,
      #termly-code-snippet-support,
      .termly-consent-banner,
      .evidon-consent-button,
      .evidon-barrier-page,
      #truste-consent-track,
      .truste_box_overlay,
      .truste_overlay,
      .qc-cmp2-container,
      #qc-cmp2-ui,
      .sp_veil,
      [id*="sp_message_container"],
      .cmp-container,
      /* ── Chat Widgets ── */
      #intercom-container,
      .intercom-lightweight-app,
      .intercom-messenger-frame,
      #drift-widget,
      #drift-frame-controller,
      #drift-frame-chat,
      .drift-conductor-item,
      #hubspot-messages-iframe-container,
      #fc_frame,
      .crisp-client,
      #crisp-chatbox,
      [id*="tidio"],
      .tawk-min-container,
      #tawk-to-chat-widget,
      #zsiq_float,
      .zopim,
      [id*="livechat"],
      [class*="livechat-widget"],
      .fb_dialog,
      .fb-customerchat,
      #beacon-container,
      #HW_badge,
      #HW_badge_cont,
      /* ── Newsletter / Subscription Popups ── */
      [class*="newsletter-popup"],
      [class*="newsletter-modal"],
      [class*="subscribe-popup"],
      [class*="subscribe-modal"],
      [class*="email-popup"],
      [class*="signup-popup"],
      [class*="exit-intent"],
      [class*="exitIntent"],
      [id*="newsletter-popup"],
      [id*="newsletter-modal"],
      [id*="subscribe-popup"],
      [id*="email-popup"],
      /* ── Push Notification Prompts ── */
      [class*="push-notification"],
      [class*="notification-prompt"],
      [class*="web-push"],
      [id*="push-notification"],
      [id*="onesignal"],
      .onesignal-slidedown-container,
      #onesignal-slidedown-container,
      /* ── Overlays / Backdrops from above ── */
      .cookie-overlay,
      .consent-overlay {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
        height: 0 !important;
        overflow: hidden !important;
      }

      /* Fix body scroll lock that consent banners sometimes add */
      body.cookie-modal-open,
      body.modal-open-cookie,
      body.no-scroll-cookie,
      html.sp-message-open {
        overflow: auto !important;
        position: static !important;
      }
    `;

    const inject = () => {
      if (document.head) {
        document.head.appendChild(style);
      } else {
        document.documentElement.appendChild(style);
      }
    };

    if (document.head) {
      inject();
    } else {
      // Head not ready yet — wait for it
      const headObserver = new MutationObserver(() => {
        if (document.head) {
          inject();
          headObserver.disconnect();
        }
      });
      headObserver.observe(document.documentElement, { childList: true });
    }

    // Also remove annoyances that are added dynamically after page load
    this.setupAnnoyanceObserver();
  }

  setupAnnoyanceObserver() {
    const annoyanceSelectors = [
      '#onetrust-consent-sdk', '#CybotCookiebotDialog', '.cc-window',
      '#intercom-container', '.intercom-lightweight-app',
      '#drift-widget', '#drift-frame-controller',
      '#hubspot-messages-iframe-container', '.crisp-client',
      '#tawk-to-chat-widget', '.onesignal-slidedown-container',
      '[id*="sp_message_container"]', '.qc-cmp2-container',
    ];

    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          const el = /** @type {Element} */ (node);
          // Check if the added element itself matches
          for (const sel of annoyanceSelectors) {
            try {
              if (el.matches && el.matches(sel)) {
                el.remove();
                break;
              }
            } catch (_) {}
          }
        }
      }
    });

    observer.observe(document.documentElement, { childList: true, subtree: true });
    this.observers.push(observer);
  }

  // ─── DOM Observer ───

  setupDOMObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.type !== 'childList') continue;
        for (const node of m.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          // Check dynamically added iframes
          if (node.tagName === 'IFRAME') {
            const style = window.getComputedStyle(node);
            if (style.display === 'none' || style.visibility === 'hidden' ||
                node.width < 5 || node.height < 5) {
              this.reportSuspicious([{
                type: 'hidden_iframe',
                description: 'Hidden iframe loaded dynamically'
              }]);
            }
          }
          // Re-scan links in added content
          if (this.linkSafetyEnabled) {
            const links = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
            for (const link of links) {
              if (this.isDeceptiveLink(link)) {
                link.style.outline = '2px dashed #e74c3c';
                link.style.outlineOffset = '2px';
                link.setAttribute('data-loxten-warning', 'Displayed URL does not match actual destination');
              }
            }
          }
        }
      }
    });
    observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
    this.observers.push(observer);
  }

  // ─── Warning UI ───

  showSecurityWarning(analysis) {
    if (this.warningShown) return;
    this.warningShown = true;

    const modal = document.createElement('div');
    modal.id = 'loxten-warning-modal';
    modal.style.cssText = `
      position:fixed!important;top:0!important;left:0!important;width:100%!important;height:100%!important;
      background:rgba(0,0,0,0.92)!important;z-index:999999999!important;display:flex!important;
      justify-content:center!important;align-items:center!important;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;
    `;

    const riskColor = analysis.riskScore >= 80 ? '#dc3545' : analysis.riskScore >= 60 ? '#fd7e14' : '#ffc107';
    const content = document.createElement('div');
    content.style.cssText = `
      background:#111!important;padding:30px!important;border-radius:12px!important;max-width:460px!important;
      text-align:center!important;box-shadow:0 8px 32px rgba(0,0,0,0.6)!important;margin:20px!important;
      border:1px solid ${riskColor}33!important;
    `;
    content.innerHTML = `
      <div style="color:${riskColor};font-size:48px;margin-bottom:16px">⚠️</div>
      <h2 style="color:${riskColor};margin:0 0 8px;font-size:22px;font-weight:700">Security Warning</h2>
      <p style="margin:0 0 20px;font-size:14px;color:#888">Risk Score: <strong style="color:${riskColor}">${analysis.riskScore}/100</strong></p>
      <div style="text-align:left;margin:20px 0;max-height:200px;overflow-y:auto">
        ${analysis.threats.map(t => `
          <div style="margin:8px 0;padding:12px;background:#1a1a1a;border-radius:8px;border-left:3px solid ${riskColor}">
            <strong style="color:${riskColor};font-size:11px;text-transform:uppercase;letter-spacing:0.05em">${t.type.replace(/_/g,' ')}</strong><br>
            <span style="color:#aaa;font-size:13px">${t.description}</span>
          </div>
        `).join('')}
      </div>
      <div style="display:flex;gap:10px;justify-content:center;margin-top:24px">
        <button id="loxten-continue" style="background:#222;color:#ccc;border:1px solid #333;padding:11px 28px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600">Continue Anyway</button>
        <button id="loxten-goback" style="background:${riskColor};color:#fff;border:none;padding:11px 28px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600">Go Back</button>
      </div>
      <p style="margin-top:18px;font-size:11px;color:#555">Protected by Loxten</p>
    `;

    modal.appendChild(content);
    document.body.appendChild(modal);

    content.querySelector('#loxten-continue').addEventListener('click', () => { modal.remove(); this.warningShown = false; });
    content.querySelector('#loxten-goback').addEventListener('click', () => history.back());
  }

  showToast(message) {
    const toast = document.createElement('div');
    toast.style.cssText = `
      position:fixed!important;top:16px!important;right:16px!important;
      background:#1a1a2e!important;color:#e74c3c!important;padding:14px 18px!important;
      border-radius:8px!important;z-index:999999998!important;max-width:340px!important;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif!important;
      box-shadow:0 4px 16px rgba(0,0,0,0.4)!important;font-size:13px!important;
      border:1px solid #e74c3c33!important;line-height:1.4!important;
    `;
    toast.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px">
        <strong style="color:#e8e8e8">Loxten</strong>
        <button onclick="this.closest('div').parentElement.remove()" style="background:none;border:none;color:#888;cursor:pointer;font-size:16px;margin-left:auto">×</button>
      </div>
      <div style="margin-top:6px">${message}</div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 6000);
  }

  // ─── Reporting ───

  reportSuspicious(indicators) {
    chrome.runtime.sendMessage({
      type: 'report_suspicious',
      data: { url: location.href, domain: location.hostname, indicators, timestamp: Date.now() }
    }).catch(() => {});
  }

  // ─── Cleanup ───

  cleanup() {
    this.observers.forEach(o => o.disconnect());
    this.observers = [];
    this.hideTooltip();
  }
}

let loxtenContent;
try {
  loxtenContent = new LoxtenContentScript();
  window.addEventListener('beforeunload', () => { if (loxtenContent) loxtenContent.cleanup(); });
} catch (e) {
  console.error('[Loxten] content script init failed:', e);
}
