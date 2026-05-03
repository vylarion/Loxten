# Loxten

A Chrome extension that provides practical, client-side browser security. No external APIs, no backend servers, no data collection. Every check runs locally in your browser, instantly.

## What It Does

### Phishing Detection
Loxten analyzes every URL you visit for phishing indicators using multiple heuristics:

- **Typosquat detection** -- Levenshtein distance matching against 60 major brands (PayPal, Microsoft, Amazon, etc.). Flags domains within 2 character edits of known brands.
- **IDN homograph detection** -- Catches internationalized domains (Punycode) that visually impersonate legitimate sites.
- **Combo-squatting detection** -- Identifies domains that combine a brand name with suspicious keywords like "login", "verify", "secure", or "billing".
- **Suspicious URL structure** -- Flags raw IP addresses, excessive subdomains, credential-harvesting `@` symbols in URLs, and phishing-style path patterns.

### Security Header Auditing
Grades every site from A+ to F based on the presence and configuration of six HTTP security headers:

| Header | What It Protects Against |
|--------|-------------------------|
| Strict-Transport-Security | Protocol downgrade attacks |
| Content-Security-Policy | Cross-site scripting (XSS) |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME-type sniffing |
| Referrer-Policy | Referrer information leakage |
| Permissions-Policy | Unauthorized API access |

### Tracker Blocking
Blocks approximately 90 advertising and tracking domains using Chrome's `declarativeNetRequest` API. This is native MV3 blocking -- requests are intercepted before they leave the browser. Covers major ad networks, analytics platforms, fingerprinting services, and social media trackers.

### Annoyance Blocking
Hides common page annoyances via CSS injection and DOM mutation observers:

- **Cookie consent banners** -- OneTrust, CookieBot, Osano, Termly, TrustArc, Quantcast, and generic cookie popups.
- **Chat widgets** -- Intercom, Drift, HubSpot, Crisp, Tidio, Tawk.to, Zendesk, and Facebook Messenger.
- **Newsletter popups** -- Subscription modals, email capture overlays, and exit-intent popups.
- **Push notification prompts** -- OneSignal slidedowns and generic push notification requests.

Also fixes scroll-lock that some consent banners impose on the page body.

### Domain Age Intelligence
Performs RDAP lookups (free, no API key) to determine when the current domain was registered. Domains less than 30 days old are automatically flagged as a threat, since newly registered domains are disproportionately used for phishing and scams.

### Link Safety Preview
The content script scans all links on every page for deceptive patterns:

- **Mismatched links** -- Links where the displayed text looks like a URL but points to a different domain (e.g., `<a href="evil.com">paypal.com</a>`) are outlined in red.
- **Dangerous URIs** -- Warns on hover over `javascript:` and `data:` links.
- **Dynamic scanning** -- Newly added links are checked via MutationObserver.

### Form Security Monitoring
Monitors forms containing password fields for security issues:

- Warns when credentials are submitted over HTTP.
- Warns when the form action points to an external domain.
- Flags password forms using the GET method (credentials appear in the URL).
- Detects `formaction` attribute overrides on submit buttons.
- Flags `autocomplete="off"` on password fields, which is common on phishing pages.

## Architecture

```
static/
  manifest.json       MV3 manifest with declarativeNetRequest
  background.js       Service worker: URL analysis, header audit, DNR rules, RDAP lookups
  content.js          Content script: page analysis, form monitoring, link preview, annoyance blocking

src/
  lib/
    types.ts          TypeScript interfaces
    Hero.svelte       Main popup shell with tab navigation
    Security.Status   Risk score, threat summary, header grade, domain age
    SiteDetails       Connection info, header audit details, domain intelligence
    ThreatsList       Threat cards with recommendations
    Settings          Protection toggles, whitelist, breach check, statistics
  routes/
    +page.svelte      Popup entry point
```

The popup UI is built with SvelteKit and compiled to static HTML via `sveltekit-adapter-chrome-extension`. The background service worker and content script are vanilla JavaScript -- no bundling, no dependencies.

## Permissions

| Permission | Purpose |
|------------|---------|
| `activeTab` | Access the current tab's URL for analysis |
| `webNavigation` | Trigger analysis on page navigation |
| `storage` | Persist settings, stats, and analysis results |
| `webRequest` | Capture response headers for security auditing |
| `tabs` | Query the active tab from the popup |
| `scripting` | Inject content scripts as needed |
| `declarativeNetRequest` | Block tracker and ad requests |
| `<all_urls>` | Apply analysis and blocking to all websites |

## Build

Prerequisites: Node.js 18+

```
npm install
npm run build
```

The built extension is output to the `build/` directory.

## Install

1. Open `chrome://extensions` in Chrome.
2. Enable "Developer mode" in the top right.
3. Click "Load unpacked" and select the `build/` directory.

## Development

```
npm run dev
```

This starts the Vite dev server for the popup UI. Note that extension APIs (`chrome.*`) will not be available in the browser dev server -- the popup must be tested as a loaded extension.

## Design Decisions

**No external APIs.** Previous versions used VirusTotal and Google Safe Browsing APIs. VirusTotal's free tier is rate-limited to 4 requests per minute and takes minutes to scan new URLs -- useless for real-time browsing. Google Safe Browsing is already built into Chrome natively. Both were removed.

**No backend server.** The previous Python backend existed solely to proxy these API calls. Requiring users to run a local server to use a browser extension is not practical. All analysis now runs client-side.

**Curated blocklists over filter list parsing.** Rather than downloading and parsing multi-megabyte community filter lists (EasyList, EasyPrivacy), Loxten uses a curated list of approximately 90 high-impact tracker domains. This keeps the extension lightweight while blocking the trackers that affect most users.

**CSS-based annoyance blocking.** Cookie banners and chat widgets are hidden via CSS injection rather than element removal. CSS rules apply immediately (before the element renders), while DOM removal requires waiting for the element to be added. A MutationObserver handles elements injected after initial page load.

## License

This project is provided as-is for personal use.
