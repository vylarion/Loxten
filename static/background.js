// Loxten v2 — Background Service Worker
// No external APIs. All analysis is local, instant, and practical.

const TRACKER_DOMAINS = [
  // --- Advertising ---
  'doubleclick.net','googlesyndication.com','googleadservices.com','adservice.google.com',
  'pagead2.googlesyndication.com','amazon-adsystem.com','ads.yahoo.com','ads.linkedin.com',
  'adsrvr.org','adnxs.com','criteo.com','criteo.net','outbrain.com','taboola.com',
  'moatads.com','rubiconproject.com','pubmatic.com','openx.net','casalemedia.com',
  'bidswitch.net','smartadserver.com','advertising.com','contextweb.com','lijit.com',
  'media.net','revcontent.com','sharethrough.com','33across.com','indexww.com',
  // --- Analytics / Tracking ---
  'google-analytics.com','analytics.google.com','googletagmanager.com',
  'connect.facebook.net','pixel.facebook.com','bat.bing.com','scorecardresearch.com',
  'quantserve.com','segment.io','segment.com','mixpanel.com','amplitude.com',
  'heapanalytics.com','hotjar.com','mouseflow.com','fullstory.com','luckyorange.com',
  'crazyegg.com','clicktale.net','inspectlet.com','optimizely.com','adobedtm.com',
  'omtrdc.net','demdex.net','everesttech.net','chartbeat.com','parsely.com',
  'newrelic.com','nr-data.net','bugsnag.com','sentry.io',
  // --- Fingerprinting / Beacons ---
  'rlcdn.com','bluekai.com','exelator.com','tapad.com','adsymptotic.com',
  'crwdcntrl.net','eyeota.net','intentiq.com','id5-sync.com','liveintent.com',
  'liveramp.com','dotomi.com','mathtag.com','turn.com','bkrtx.com',
  // --- Social Trackers ---
  'platform.twitter.com','syndication.twitter.com','static.ads-twitter.com',
  'platform.linkedin.com','snap.licdn.com','sc-static.net','scdn.co',
  // --- Other ---
  'branch.io','app.link','adjust.com','appsflyer.com','kochava.com',
  'singular.net','tealiumiq.com','ensighten.com','evidon.com','cookielaw.org'
];

// Top 60 brands for phishing detection (Levenshtein matching)
const TOP_BRANDS = [
  'paypal','microsoft','google','facebook','amazon','apple','netflix','instagram',
  'twitter','linkedin','dropbox','adobe','yahoo','chase','wellsfargo','bankofamerica',
  'citibank','americanexpress','usps','fedex','dhl','ups','walmart','ebay','costco',
  'target','bestbuy','homedepot','lowes','macys','nordstrom','samsung','sony','hp',
  'dell','lenovo','asus','acer','nvidia','intel','oracle','salesforce','slack',
  'zoom','skype','whatsapp','telegram','signal','discord','spotify','steam','epic',
  'roblox','twitch','tiktok','snapchat','pinterest','reddit','github','gitlab'
];

class LoxtenBackground {
  constructor() {
    this.settings = {
      realTimeProtection: true,
      blockPhishing: true,
      blockTrackers: true,
      blockAnnoyances: true,
      linkSafetyPreview: false,
      showWarnings: true,
      autoScan: true,
      notificationLevel: 'medium',
    };
    this.stats = {
      sitesScanned: 0,
      threatsBlocked: 0,
      trackersBlocked: 0,
      phishingBlocked: 0,
    };
    // Per-tab tracker counts and navigation timestamps
    this.tabTrackerCounts = new Map();
    this.tabNavTimestamps = new Map();
    this.init();
  }

  async init() {
    await this.loadSettings();
    await this.loadStats();
    this.setupEventListeners();
    await this.setupTrackerBlocking();
    console.log('[Loxten] Background service v2 ready');
  }

  // ─── Settings / Stats ───

  async loadSettings() {
    try {
      const r = await chrome.storage.sync.get('loxten_settings');
      if (r.loxten_settings) this.settings = { ...this.settings, ...r.loxten_settings };
    } catch (e) { console.error('[Loxten] loadSettings:', e); }
  }

  async loadStats() {
    try {
      const r = await chrome.storage.local.get('loxten_stats');
      if (r.loxten_stats) this.stats = { ...this.stats, ...r.loxten_stats };
    } catch (e) { console.error('[Loxten] loadStats:', e); }
  }

  async saveStats() {
    try { await chrome.storage.local.set({ loxten_stats: this.stats }); }
    catch (e) { console.error('[Loxten] saveStats:', e); }
  }

  // ─── Real Tracker Blocking (declarativeNetRequest) ───

  async setupTrackerBlocking() {
    if (!this.settings.blockTrackers) {
      try { await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: TRACKER_DOMAINS.map((_, i) => i + 1) }); } catch (_) {}
      return;
    }
    const rules = TRACKER_DOMAINS.map((domain, i) => ({
      id: i + 1,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: `||${domain}`,
        resourceTypes: ['script','image','xmlhttprequest','sub_frame','ping','font','stylesheet','media','other'],
      }
    }));
    try {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: rules.map(r => r.id),
        addRules: rules,
      });
      console.log(`[Loxten] Tracker blocking active: ${rules.length} domains`);
    } catch (e) {
      console.error('[Loxten] DNR setup failed:', e);
    }
  }

  // ─── Event Listeners ───

  setupEventListeners() {
    // Analyze URLs on navigation
    chrome.webNavigation.onBeforeNavigate.addListener((details) => {
      if (details.frameId === 0) {
        // Reset per-tab tracker count for new navigation
        this.tabTrackerCounts.set(details.tabId, 0);
        this.tabNavTimestamps.set(details.tabId, Date.now());
        if (this.settings.realTimeProtection) {
          this.analyzeURL(details.url, details.tabId);
        }
      }
    });

    // Capture response headers for security audit
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => this.captureHeaders(details),
      { urls: ['<all_urls>'], types: ['main_frame'] },
      ['responseHeaders']
    );

    // Tracker counting via getMatchedRules (works in both dev and published modes)
    // Popup requests count via getTabTrackerCount which queries the DNR API

    // Messages from popup / content
    chrome.runtime.onMessage.addListener((msg, sender, respond) => {
      this.handleMessage(msg, sender, respond);
      return true;
    });

    // Badge update on tab complete
    chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
      if (info.status === 'complete' && tab.url) this.updateBadge(tabId);
    });

    // Clean up per-tab data when tab is closed
    chrome.tabs.onRemoved.addListener((tabId) => {
      this.tabTrackerCounts.delete(tabId);
      this.tabNavTimestamps.delete(tabId);
      // Clean storage
      chrome.storage.local.remove([`analysis_${tabId}`, `headers_${tabId}`, `domainAge_${tabId}`]).catch(() => {});
    });
  }

  // ─── Header Security Audit ───

  captureHeaders(details) {
    if (!details.responseHeaders) return;
    const headers = {};
    for (const h of details.responseHeaders) {
      headers[h.name.toLowerCase()] = h.value || '';
    }
    const audit = this.auditHeaders(headers);
    // Store per-tab
    const key = `headers_${details.tabId}`;
    chrome.storage.local.set({ [key]: audit }).catch(() => {});
  }

  auditHeaders(headers) {
    const checks = [];
    let score = 0;
    const total = 6;

    // 1. HSTS
    if (headers['strict-transport-security']) {
      checks.push({ name: 'HSTS', status: 'pass', detail: headers['strict-transport-security'] });
      score++;
    } else {
      checks.push({ name: 'HSTS', status: 'fail', detail: 'Missing Strict-Transport-Security header' });
    }

    // 2. CSP
    if (headers['content-security-policy']) {
      checks.push({ name: 'CSP', status: 'pass', detail: 'Content-Security-Policy present' });
      score++;
    } else {
      checks.push({ name: 'CSP', status: 'fail', detail: 'No Content-Security-Policy header' });
    }

    // 3. X-Frame-Options
    if (headers['x-frame-options']) {
      checks.push({ name: 'X-Frame-Options', status: 'pass', detail: headers['x-frame-options'] });
      score++;
    } else {
      checks.push({ name: 'X-Frame-Options', status: 'fail', detail: 'Missing — vulnerable to clickjacking' });
    }

    // 4. X-Content-Type-Options
    if (headers['x-content-type-options']?.toLowerCase() === 'nosniff') {
      checks.push({ name: 'X-Content-Type-Options', status: 'pass', detail: 'nosniff' });
      score++;
    } else {
      checks.push({ name: 'X-Content-Type-Options', status: 'fail', detail: 'Missing nosniff — MIME sniffing possible' });
    }

    // 5. Referrer-Policy
    if (headers['referrer-policy']) {
      checks.push({ name: 'Referrer-Policy', status: 'pass', detail: headers['referrer-policy'] });
      score++;
    } else {
      checks.push({ name: 'Referrer-Policy', status: 'fail', detail: 'Missing — referrer may leak to third parties' });
    }

    // 6. Permissions-Policy
    if (headers['permissions-policy']) {
      checks.push({ name: 'Permissions-Policy', status: 'pass', detail: 'Present' });
      score++;
    } else {
      checks.push({ name: 'Permissions-Policy', status: 'fail', detail: 'Missing — browser features unrestricted' });
    }

    const pct = Math.round((score / total) * 100);
    const grade = pct >= 90 ? 'A+' : pct >= 80 ? 'A' : pct >= 65 ? 'B' : pct >= 50 ? 'C' : pct >= 30 ? 'D' : 'F';

    return { checks, score, total, grade };
  }

  // ─── Whitelist ───

  async isWhitelisted(domain) {
    try {
      const r = await chrome.storage.local.get('loxten_whitelist');
      const list = r.loxten_whitelist || [];
      return list.some(entry => domain === entry.domain || domain.endsWith('.' + entry.domain));
    } catch (_) { return false; }
  }

  // ─── URL Analysis ───

  async analyzeURL(url, tabId) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

      // Skip analysis for whitelisted domains
      if (await this.isWhitelisted(domain)) {
        const clean = { url, domain, threats: [], riskScore: 0, trackersBlocked: 0, timestamp: Date.now(), isSecure: true, whitelisted: true };
        await this.storeAnalysis(tabId, clean);
        this.updateBadge(tabId, clean);
        return;
      }

      this.stats.sitesScanned++;
      const analysis = { url, domain, threats: [], riskScore: 0, trackersBlocked: 0, timestamp: Date.now(), isSecure: true };

      // Phishing detection
      const phish = this.detectPhishing(domain, urlObj);
      if (phish.isPhishing) {
        analysis.threats.push({ type: 'phishing', severity: 'high', description: phish.reason });
        analysis.riskScore += 70;
        this.stats.phishingBlocked++;
        this.stats.threatsBlocked++;
      }

      // URL structure analysis
      const urlCheck = this.analyzeURLStructure(urlObj);
      if (urlCheck.suspicious) {
        analysis.threats.push({ type: 'suspicious_url', severity: urlCheck.severity, description: urlCheck.reason });
        analysis.riskScore += urlCheck.score;
      }

      // Domain age check (RDAP — fire-and-forget, updates analysis async)
      this.checkDomainAge(domain, tabId);

      analysis.riskScore = Math.min(analysis.riskScore, 100);
      analysis.isSecure = analysis.riskScore < 30;

      await this.storeAnalysis(tabId, analysis);
      if (analysis.riskScore >= 60 && this.settings.showWarnings) {
        this.showSecurityWarning(tabId, analysis);
      }
      this.updateBadge(tabId, analysis);
      await this.saveStats();
    } catch (e) {
      console.error('[Loxten] analyzeURL:', e);
    }
  }

  // ─── Phishing Detection (Levenshtein + IDN + combo-squatting) ───

  detectPhishing(domain, urlObj) {
    const result = { isPhishing: false, reason: '' };

    // 1. IDN homograph attack (Punycode)
    if (domain.startsWith('xn--') || /xn--/.test(domain)) {
      result.isPhishing = true;
      result.reason = 'Internationalized domain (Punycode) — may disguise a lookalike domain';
      return result;
    }

    // 2. Extract base domain name (without TLD)
    const domainBase = domain.split('.').slice(0, -1).join('.').replace(/[-_.]/g, '');

    // If this domain IS a known brand, it's legitimate — skip all typosquat checks
    if (TOP_BRANDS.includes(domainBase)) {
      return result;
    }

    // 3. Levenshtein distance against top brands
    for (const brand of TOP_BRANDS) {
      const dist = this.levenshtein(domainBase, brand);
      // Require closer match for shorter names to reduce false positives
      const maxDist = domainBase.length >= 7 ? 2 : 1;
      if (dist > 0 && dist <= maxDist && domainBase.length >= 4) {
        result.isPhishing = true;
        result.reason = `Domain "${domain}" is suspiciously similar to "${brand}" (possible typosquat)`;
        return result;
      }
    }

    // 4. Combo-squatting (brand name + suspicious suffix)
    const suspiciousSuffixes = ['login','secure','verify','account','update','confirm','auth','support','help','service','alert','billing','payment'];
    for (const brand of TOP_BRANDS) {
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.net`) && !domain.endsWith(`${brand}.org`)) {
        for (const suffix of suspiciousSuffixes) {
          if (domain.includes(suffix)) {
            result.isPhishing = true;
            result.reason = `Combo-squatting detected: "${domain}" uses "${brand}" with suspicious keyword "${suffix}"`;
            return result;
          }
        }
      }
    }

    // 5. Suspicious TLDs
    const suspiciousTLDs = ['.tk','.ml','.ga','.cf','.cc','.top','.xyz','.buzz','.club','.info','.work','.click','.loan','.win'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      result.reason = 'Uses a TLD commonly associated with phishing and spam';
      return result;
    }

    return result;
  }

  levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
      }
    }
    return dp[m][n];
  }

  analyzeURLStructure(urlObj) {
    const result = { suspicious: false, reason: '', score: 0, severity: 'medium' };

    // IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
      return { suspicious: true, reason: 'Uses raw IP address instead of a domain name', score: 40, severity: 'medium' };
    }

    // Excessive subdomains (>4 levels)
    const parts = urlObj.hostname.split('.');
    if (parts.length > 4) {
      return { suspicious: true, reason: `Unusual number of subdomains (${parts.length} levels)`, score: 25, severity: 'low' };
    }

    // Suspicious path patterns
    const pathPatterns = [/login.*secure/i, /verify.*account/i, /update.*payment/i, /confirm.*identity/i, /suspended/i];
    if (pathPatterns.some(p => p.test(urlObj.pathname + urlObj.search))) {
      return { suspicious: true, reason: 'URL path contains patterns common in phishing pages', score: 30, severity: 'medium' };
    }

    // @ symbol in URL (credential harvesting trick)
    if (urlObj.href.includes('@') && !urlObj.href.startsWith('mailto:')) {
      return { suspicious: true, reason: 'URL contains @ symbol — may be disguising the real destination', score: 45, severity: 'high' };
    }

    return result;
  }

  // ─── Domain Age (RDAP — free, no API key) ───

  async checkDomainAge(domain, tabId) {
    // Extract registrable domain (last two parts)
    const parts = domain.split('.');
    const regDomain = parts.length >= 2 ? parts.slice(-2).join('.') : domain;

    try {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 5000);

      const resp = await fetch(`https://rdap.org/domain/${regDomain}`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/rdap+json' }
      });

      if (!resp.ok) return;
      const data = await resp.json();

      // Find registration event
      let regDate = null;
      if (data.events) {
        const reg = data.events.find(e => e.eventAction === 'registration');
        if (reg && reg.eventDate) {
          regDate = new Date(reg.eventDate);
        }
      }

      if (regDate) {
        const ageDays = Math.floor((Date.now() - regDate.getTime()) / 86400000);
        const domainAge = { registeredDate: regDate.toISOString().slice(0, 10), ageDays };

        // Store per-tab
        const key = `domainAge_${tabId}`;
        await chrome.storage.local.set({ [key]: domainAge });

        // If domain is very new (<30 days), add it as a threat
        if (ageDays < 30) {
          const aKey = `analysis_${tabId}`;
          const stored = await chrome.storage.local.get(aKey);
          if (stored[aKey]) {
            stored[aKey].threats.push({
              type: 'new_domain',
              severity: ageDays < 7 ? 'high' : 'medium',
              description: `Domain registered only ${ageDays} day${ageDays !== 1 ? 's' : ''} ago — new domains are often used for scams`
            });
            stored[aKey].riskScore = Math.min(stored[aKey].riskScore + (ageDays < 7 ? 35 : 20), 100);
            stored[aKey].isSecure = stored[aKey].riskScore < 30;
            await chrome.storage.local.set({ [aKey]: stored[aKey] });
            this.updateBadge(tabId, stored[aKey]);
          }
        }
      }
    } catch (_) {
      // RDAP lookup failed — not critical, just skip
    }
  }

  // ─── Warning / Badge / Storage ───

  async showSecurityWarning(tabId, analysis) {
    try {
      await chrome.tabs.sendMessage(tabId, { type: 'security_warning', analysis });
    } catch (_) {}
  }

  updateBadge(tabId, analysis = null) {
    if (analysis && analysis.threats.length > 0) {
      chrome.action.setBadgeText({ tabId, text: analysis.threats.length.toString() });
      const color = analysis.riskScore >= 80 ? '#dc2626' : analysis.riskScore >= 60 ? '#ea580c' : '#f59e0b';
      chrome.action.setBadgeBackgroundColor({ tabId, color });
    } else {
      chrome.action.setBadgeText({ tabId, text: '' });
    }
  }

  async storeAnalysis(tabId, analysis) {
    try { await chrome.storage.local.set({ [`analysis_${tabId}`]: analysis }); }
    catch (_) {}
  }

  async handleMessage(msg, sender, respond) {
    try {
      switch (msg.type) {
        case 'get_analysis': {
          const tabId = msg.tabId || sender.tab?.id;
          const a = await this.getStoredAnalysis(tabId);
          if (a && tabId) {
            // Override with whitelisted clean state if domain was added to whitelist
            if (a.domain && await this.isWhitelisted(a.domain)) {
              a.threats = [];
              a.riskScore = 0;
              a.isSecure = true;
              a.whitelisted = true;
            }
            a.trackersBlocked = await this.getTabTrackerCount(tabId);
          }
          respond(a);
          break;
        }
        case 'get_headers': {
          const tabId = msg.tabId || sender.tab?.id;
          const key = `headers_${tabId}`;
          const r = await chrome.storage.local.get(key);
          respond(r[key] || null);
          break;
        }
        case 'get_domain_age': {
          const tabId = msg.tabId || sender.tab?.id;
          const key = `domainAge_${tabId}`;
          const r = await chrome.storage.local.get(key);
          respond(r[key] || null);
          break;
        }
        case 'force_scan': {
          if (sender.tab?.id && sender.tab?.url) {
            await this.analyzeURL(sender.tab.url, sender.tab.id);
            respond(await this.getStoredAnalysis(sender.tab.id));
          }
          break;
        }
        case 'settings_updated': {
          this.settings = { ...this.settings, ...msg.settings };
          await this.setupTrackerBlocking();
          try {
            const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
            for (const tab of tabs) {
              chrome.tabs.sendMessage(tab.id, { type: 'settings_updated', settings: this.settings }).catch(() => {});
            }
          } catch (_) {}
          respond({ success: true });
          break;
        }
        case 'get_stats': {
          respond(this.stats);
          break;
        }
        case 'get_settings': {
          respond(this.settings);
          break;
        }
        default:
          respond({ error: 'Unknown message type' });
      }
    } catch (e) {
      console.error('[Loxten] handleMessage:', e);
      respond({ error: e.message });
    }
  }

  async getStoredAnalysis(tabId) {
    if (!tabId) return null;
    try {
      const r = await chrome.storage.local.get(`analysis_${tabId}`);
      return r[`analysis_${tabId}`] || {
        url: 'Unknown', domain: 'Unknown', threats: [], riskScore: 0,
        trackersBlocked: 0, timestamp: Date.now(), isSecure: true
      };
    } catch (_) { return null; }
  }

  // Get tracker count for a specific tab
  async getTabTrackerCount(tabId) {
    try {
      const navTimestamp = this.tabNavTimestamps.get(tabId) || 0;
      const result = await chrome.declarativeNetRequest.getMatchedRules({
        tabId,
        minTimeStamp: navTimestamp > 0 ? navTimestamp : undefined
      });
      const count = result?.rulesMatchedInfo?.length || 0;
      if (count > 0) {
        this.tabTrackerCounts.set(tabId, count);
      }
      return count;
    } catch (_) {
      return 0;
    }
  }
}

const loxten = new LoxtenBackground();