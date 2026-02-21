// Background service worker for Loxten Chrome Extension
class LoxtenBackground {
  constructor() {
    // Loxten API backend URL
    this.API_BASE_URL = 'http://localhost:8000';
    this.apiCache = new Map(); // URL -> { result, timestamp }
    this.API_CACHE_TTL = 300000; // 5 minutes

    this.settings = {
      realTimeProtection: true,
      blockMaliciousSites: true,
      blockPhishing: true,
      blockTrackers: true,
      blockCryptominers: true,
      showWarnings: true,
      autoScan: true,
      notificationLevel: 'medium',
      scanFrequency: 'realtime',
      whitelistMode: false
    };

    this.stats = {
      sitesScanned: 0,
      threatsBlocked: 0,
      trackersBlocked: 0,
      malwareDetected: 0,
      phishingBlocked: 0
    };

    // Known malicious domains (in production, load from threat intelligence feeds)
    this.maliciousDomains = new Set([
      'malicious-example.com',
      'phishing-site.net',
      'fake-bank.org',
      'scam-site.biz'
    ]);

    // Known tracker domains
    this.trackerDomains = new Set([
      'google-analytics.com',
      'doubleclick.net',
      'facebook.com',
      'googletagmanager.com',
      'googlesyndication.com',
      'amazon-adsystem.com'
    ]);

    // Phishing keywords and patterns
    this.phishingPatterns = [
      'verify your account immediately',
      'suspended account',
      'click here now',
      'limited time offer',
      'confirm your identity',
      'unusual activity detected',
      'payp4l',
      'micr0soft',
      'g00gle'
    ];

    this.init();
  }

  async init() {
    await this.loadSettings();
    await this.loadStats();
    this.setupEventListeners();
    console.log('Loxten Background Service initialized');
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.sync.get('loxten_settings');
      if (result.loxten_settings) {
        this.settings = { ...this.settings, ...result.loxten_settings };
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async loadStats() {
    try {
      const result = await chrome.storage.local.get('loxten_stats');
      if (result.loxten_stats) {
        this.stats = { ...this.stats, ...result.loxten_stats };
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }

  async saveStats() {
    try {
      await chrome.storage.local.set({ loxten_stats: this.stats });
    } catch (error) {
      console.error('Failed to save stats:', error);
    }
  }

  setupEventListeners() {
    // Listen for navigation events
    chrome.webNavigation.onBeforeNavigate.addListener((details) => {
      if (details.frameId === 0 && this.settings.realTimeProtection) {
        this.analyzeURL(details.url, details.tabId);
      }
    });

    // Listen for web requests to detect trackers
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => this.analyzeRequest(details),
      { urls: ['<all_urls>'] },
      []
    );

    // Handle messages from popup and content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });

    // Handle tab updates — trigger AI analysis
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.updateBadge(tabId);
      }
    });
  }

  /**
   * Call the Loxten FastAPI backend for AI-powered analysis.
   * Falls back gracefully if backend is unreachable.
   */
  async callLoxtenAPI(pageData, tabId) {
    const url = pageData.url;

    // Check cache
    const cached = this.apiCache.get(url);
    if (cached && (Date.now() - cached.timestamp) < this.API_CACHE_TTL) {
      console.log('Loxten AI: using cached result for', url);
      await this.mergeAIResults(tabId, cached.result);
      return cached.result;
    }

    try {
      const response = await fetch(`${this.API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pageData),
        signal: AbortSignal.timeout(15000) // 15s timeout
      });

      if (!response.ok) {
        console.warn('Loxten API returned', response.status);
        return null;
      }

      const result = await response.json();

      // Cache the result
      this.apiCache.set(url, { result, timestamp: Date.now() });

      // Merge AI results into the stored analysis
      await this.mergeAIResults(tabId, result);

      // Show warning if AI detects high risk
      if (result.risk_score >= 60 && this.settings.showWarnings) {
        this.showSecurityWarning(tabId, {
          url: url,
          riskScore: result.risk_score,
          threats: result.threats || [],
          aiSummary: result.ai_summary
        });
      }

      // Update badge
      if (result.threats && result.threats.length > 0) {
        this.updateBadge(tabId, {
          threats: result.threats,
          riskScore: result.risk_score
        });
      }

      console.log('Loxten AI analysis complete:', url, 'risk:', result.risk_score);
      return result;

    } catch (error) {
      // Backend unreachable — fail silently, local analysis still works
      console.log('Loxten API unreachable, using local analysis only:', error.message);
      return null;
    }
  }

  /**
   * Merge AI analysis results into the stored tab analysis
   */
  async mergeAIResults(tabId, aiResult) {
    if (!tabId || !aiResult) return;

    const key = `analysis_${tabId}`;
    try {
      const stored = await chrome.storage.local.get(key);
      const existing = stored[key] || {
        url: aiResult.url,
        domain: '',
        threats: [],
        riskScore: 0,
        trackersBlocked: 0,
        timestamp: Date.now(),
        isSecure: true
      };

      // Merge AI threats with local threats (avoid duplicates by type)
      const existingTypes = new Set(existing.threats.map(t => t.type));
      const newThreats = (aiResult.threats || []).filter(t => !existingTypes.has(t.type));
      existing.threats = [...existing.threats, ...newThreats];

      // Take the higher risk score
      existing.riskScore = Math.max(existing.riskScore, aiResult.risk_score || 0);
      existing.isSecure = existing.riskScore < 30;

      // Store AI-specific fields
      existing.aiSummary = aiResult.ai_summary || '';
      existing.aiAnalyzed = true;
      existing.isPhishing = aiResult.is_phishing || false;
      existing.phishingConfidence = aiResult.phishing_confidence || 0;
      existing.privacyConcerns = aiResult.privacy_concerns || [];
      existing.impersonating = aiResult.impersonating || null;

      await chrome.storage.local.set({ [key]: existing });
    } catch (error) {
      console.error('Failed to merge AI results:', error);
    }
  }

  async analyzeURL(url, tabId) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      // Skip chrome:// and extension:// URLs
      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
        return;
      }

      this.stats.sitesScanned++;

      const analysis = {
        url: url,
        domain: domain,
        threats: [],
        riskScore: 0,
        trackersBlocked: 0,
        timestamp: Date.now(),
        isSecure: true
      };

      // Check against malicious domains
      if (this.maliciousDomains.has(domain)) {
        analysis.threats.push({
          type: 'malicious_domain',
          severity: 'high',
          description: `Known malicious domain: ${domain}`
        });
        analysis.riskScore += 80;
        this.stats.malwareDetected++;
        this.stats.threatsBlocked++;
      }

      // Check for phishing indicators
      const phishingCheck = this.detectPhishing(domain, urlObj);
      if (phishingCheck.isPhishing) {
        analysis.threats.push({
          type: 'phishing',
          severity: 'high',
          description: phishingCheck.reason
        });
        analysis.riskScore += 70;
        this.stats.phishingBlocked++;
        this.stats.threatsBlocked++;
      }

      // Check URL structure for suspicious patterns
      const urlCheck = this.analyzeURLStructure(urlObj);
      if (urlCheck.suspicious) {
        analysis.threats.push({
          type: 'suspicious_url',
          severity: 'medium',
          description: urlCheck.reason
        });
        analysis.riskScore += urlCheck.score;
      }

      // Determine if site is secure
      analysis.isSecure = analysis.riskScore < 30;

      // Store analysis
      await this.storeAnalysis(tabId, analysis);

      // Show warning if high risk and warnings enabled
      if (analysis.riskScore >= 60 && this.settings.showWarnings) {
        this.showSecurityWarning(tabId, analysis);
      }

      // Update badge
      this.updateBadge(tabId, analysis);

      await this.saveStats();

    } catch (error) {
      console.error('URL analysis failed:', error);
    }
  }

  detectPhishing(domain, urlObj) {
    const result = { isPhishing: false, reason: '' };

    // Check for character substitution in common domains
    const commonDomains = ['paypal', 'microsoft', 'google', 'facebook', 'amazon', 'apple'];
    for (const commonDomain of commonDomains) {
      if (domain.includes(commonDomain) && !domain.includes(`${commonDomain}.com`)) {
        // Check for character substitution
        if (this.hasCharacterSubstitution(domain, commonDomain)) {
          result.isPhishing = true;
          result.reason = `Possible phishing attempt targeting ${commonDomain}`;
          break;
        }
      }
    }

    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.cc'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      result.isPhishing = true;
      result.reason = 'Uses suspicious top-level domain often associated with phishing';
    }

    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'short.link'];
    if (shorteners.some(shortener => domain.includes(shortener))) {
      result.isPhishing = true;
      result.reason = 'URL shortener detected - may hide real destination';
    }

    return result;
  }

  hasCharacterSubstitution(domain, target) {
    // Simple character substitution detection
    const substitutions = {
      'o': '0',
      'i': '1',
      'l': '1',
      'e': '3',
      'a': '@',
      's': '$'
    };

    let modifiedTarget = target;
    for (const [char, sub] of Object.entries(substitutions)) {
      modifiedTarget = modifiedTarget.replace(new RegExp(char, 'g'), sub);
      if (domain.includes(modifiedTarget)) {
        return true;
      }
    }
    return false;
  }

  analyzeURLStructure(urlObj) {
    const result = { suspicious: false, reason: '', score: 0 };

    // Check for IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
      result.suspicious = true;
      result.reason = 'Uses IP address instead of domain name';
      result.score = 40;
      return result;
    }

    // Check URL length
    if (urlObj.href.length > 100) {
      result.suspicious = true;
      result.reason = 'Unusually long URL';
      result.score = 20;
    }

    // Check for too many subdomains
    const subdomains = urlObj.hostname.split('.');
    if (subdomains.length > 4) {
      result.suspicious = true;
      result.reason = 'Too many subdomains';
      result.score += 25;
    }

    // Check for suspicious patterns in path
    const suspiciousPathPatterns = [
      /login.*secure/i,
      /verify.*account/i,
      /update.*payment/i,
      /suspended/i
    ];

    if (suspiciousPathPatterns.some(pattern => pattern.test(urlObj.pathname))) {
      result.suspicious = true;
      result.reason = 'Suspicious path pattern detected';
      result.score += 30;
    }

    return result;
  }

  analyzeRequest(details) {
    const url = new URL(details.url);
    const domain = url.hostname.toLowerCase();

    // Check for trackers
    if (this.settings.blockTrackers && (this.trackerDomains.has(domain) || this.isKnownTracker(domain))) {
      this.stats.trackersBlocked++;
      this.saveStats();

      // Notify content script
      if (details.tabId && details.tabId !== -1) {
        chrome.tabs.sendMessage(details.tabId, {
          type: 'tracker_detected',
          trackers: [{ domain: domain, url: details.url }]
        }).catch(() => { }); // Ignore errors if tab is closed
      }

      // Block the request
      return { cancel: true };
    }
  }

  isKnownTracker(domain) {
    const trackerPatterns = [
      /google-analytics/,
      /googletagmanager/,
      /doubleclick/,
      /facebook\.com.*\/tr/,
      /amazon-adsystem/,
      /googlesyndication/,
      /scorecardresearch/,
      /quantserve/
    ];

    return trackerPatterns.some(pattern => pattern.test(domain));
  }

  async showSecurityWarning(tabId, analysis) {
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'security_warning',
        analysis: analysis
      });
    } catch (error) {
      // Tab might be closed or not ready
      console.log('Could not send warning to tab:', error.message);
    }
  }

  updateBadge(tabId, analysis = null) {
    if (analysis && analysis.threats.length > 0) {
      chrome.action.setBadgeText({
        tabId: tabId,
        text: analysis.threats.length.toString()
      });

      const color = analysis.riskScore >= 80 ? '#dc2626' :
        analysis.riskScore >= 60 ? '#ea580c' : '#f59e0b';

      chrome.action.setBadgeBackgroundColor({
        tabId: tabId,
        color: color
      });
    } else {
      chrome.action.setBadgeText({
        tabId: tabId,
        text: ''
      });
    }
  }

  async storeAnalysis(tabId, analysis) {
    const key = `analysis_${tabId}`;
    try {
      await chrome.storage.local.set({ [key]: analysis });
    } catch (error) {
      console.error('Failed to store analysis:', error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'get_analysis':
          const analysis = await this.getStoredAnalysis(sender.tab?.id);
          sendResponse(analysis);
          break;

        case 'force_scan':
          if (sender.tab?.id && sender.tab?.url) {
            await this.analyzeURL(sender.tab.url, sender.tab.id);
            const newAnalysis = await this.getStoredAnalysis(sender.tab.id);
            sendResponse(newAnalysis);
          }
          break;

        case 'settings_updated':
          this.settings = { ...this.settings, ...message.settings };
          sendResponse({ success: true });
          break;

        case 'get_stats':
          sendResponse(this.stats);
          break;

        case 'report_suspicious':
          // Handle suspicious content reports from content script
          console.log('Suspicious content reported:', message.data);
          sendResponse({ success: true });
          break;

        case 'page_data_for_ai':
          // Content script sent page data — call backend AI
          if (message.data && sender.tab?.id) {
            this.callLoxtenAPI(message.data, sender.tab.id)
              .then(result => console.log('AI analysis received for tab', sender.tab.id))
              .catch(err => console.log('AI analysis skipped:', err.message));
          }
          sendResponse({ success: true });
          break;

        case 'get_ai_analysis':
          // Popup requesting AI analysis data
          const aiKey = `analysis_${sender.tab?.id}`;
          const aiResult = await chrome.storage.local.get(aiKey);
          sendResponse(aiResult[aiKey] || null);
          break;

        case 'update_tracker_count':
          if (sender.tab?.id) {
            const key = `analysis_${sender.tab.id}`;
            const result = await chrome.storage.local.get(key);
            if (result[key]) {
              result[key].trackersBlocked = message.count;
              await chrome.storage.local.set({ [key]: result[key] });
            }
          }
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Error handling message:', error);
      sendResponse({ error: error.message });
    }
  }

  async getStoredAnalysis(tabId) {
    if (!tabId) return null;

    const key = `analysis_${tabId}`;
    try {
      const result = await chrome.storage.local.get(key);
      return result[key] || {
        url: 'Unknown',
        domain: 'Unknown',
        threats: [],
        riskScore: 0,
        trackersBlocked: this.stats.trackersBlocked,
        timestamp: Date.now(),
        isSecure: true
      };
    } catch (error) {
      console.error('Failed to get stored analysis:', error);
      return null;
    }
  }
}

// Initialize the background service
const loxten = new LoxtenBackground();