# Loxtention

A Chrome extension for real-time website security analysis and threat detection with AI-powered anomaly detection.

## Overview

Loxtention is a comprehensive browser security solution that monitors websites for malicious content, phishing attempts, trackers, and security threats. The extension combines local pattern matching with cloud-based threat intelligence APIs to provide multi-layered protection.

## Architecture

### Frontend (Chrome Extension)
- SvelteKit-based popup interface
- Real-time content script monitoring
- Background service worker for threat detection
- Local storage for settings and statistics

### Backend (FastAPI)
- RESTful API for threat analysis
- Integration with multiple threat intelligence sources
- SQLite database for caching and analytics
- Machine learning-based anomaly detection

## Features

### Multi-Source Threat Intelligence
- Google Safe Browsing API integration
- VirusTotal scanning
- PhishTank phishing database
- URLhaus malware URL detection
- OpenPhish community feed
- AI-powered pattern analysis

### Real-Time Security Analysis
- URL structure and pattern analysis
- Domain reputation checking
- Character substitution detection
- Suspicious TLD identification
- Multi-vendor threat verification

### Content Security Monitoring
- Malicious script detection
- Hidden iframe identification
- Clickjacking prevention
- Cryptomining detection
- Form submission analysis
- CPU usage monitoring

### Privacy Protection
- Third-party tracker blocking
- Analytics request filtering
- Privacy-focused browsing statistics
- No data collection without consent

### User Interface
- Clean, minimalistic three-tab interface
- Real-time security scoring system (A+ to F)
- Detailed threat breakdowns
- Customizable protection settings
- Statistics dashboard

## Technology Stack

### Extension
- SvelteKit 2.0
- TypeScript
- Chrome Extension Manifest V3
- Chrome Storage API
- Chrome Web Request API

### Backend
- Python 3.10+
- FastAPI
- SQLite3
- Requests library
- OpenAI API (optional)
- Uvicorn ASGI server

### External APIs
- Google Safe Browsing API
- VirusTotal API
- PhishTank API
- URLhaus API
- OpenPhish feed
- OpenAI GPT-4 (optional)

## Installation

### Extension Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Loxtention.git
cd Loxtention
```

2. Install frontend dependencies:
```bash
npm install
```

3. Build the extension:
```bash
npm run build
```

4. Load in Chrome:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `build` folder

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure API keys in `.env`:
```env
GOOGLE_SAFE_BROWSING_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
PHISHTANK_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here  # Optional
```

5. Run the server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

6. Update extension to use backend:
   - Edit `static/background.js`
   - Set `BACKEND_URL = "http://localhost:8000"`

## API Keys Setup

### Google Safe Browsing API
1. Visit [Google Cloud Console](https://console.cloud.google.com)
2. Create new project
3. Enable Safe Browsing API
4. Create credentials (API Key)
5. Free tier: 10,000 queries per day

### VirusTotal API
1. Register at [VirusTotal](https://www.virustotal.com)
2. Generate API key from account settings
3. Free tier: 4 requests per minute

### PhishTank API
1. Register at [PhishTank](https://www.phishtank.com)
2. Request API key
3. Free community access

### OpenAI API (Optional)
1. Register at [OpenAI](https://platform.openai.com)
2. Generate API key
3. Required for ML-based anomaly detection
4. Pay-per-use pricing

## Project Structure

```
Loxtention/
├── src/
│   ├── lib/
│   │   ├── Hero.svelte              # Main popup component
│   │   ├── SecurityStatus.svelte    # Security analysis display
│   │   ├── ThreatsList.svelte       # Threats breakdown
│   │   ├── Settings.svelte          # User settings
│   │   └── types.ts                 # TypeScript definitions
│   ├── routes/
│   │   ├── +layout.svelte
│   │   ├── +layout.ts
│   │   ├── +page.svelte
│   │   └── +page.ts
│   ├── app.html
│   └── app.css
├── static/
│   ├── background.js                # Service worker
│   ├── content.js                   # Content script
│   ├── manifest.json                # Extension manifest
│   └── icons/
├── backend/
│   ├── main.py                      # FastAPI application
│   ├── requirements.txt             # Python dependencies
│   ├── database.py                  # Database operations
│   └── .env                         # API keys (not in repo)
├── svelte.config.js
├── vite.config.ts
├── tsconfig.json
└── package.json
```

## Security Detection Methods

### URL Analysis
- Pattern matching against known malicious patterns
- Domain age and registration analysis
- SSL certificate validation
- Redirect chain analysis
- IP address usage detection

### Phishing Detection
- Typosquatting identification
- Brand impersonation detection
- Suspicious keyword combinations
- Fake login form analysis
- URL shortener detection
- Character substitution patterns

### Malware Detection
- Script behavior analysis
- Obfuscated code detection
- Known malware signature matching
- Suspicious API usage
- Unauthorized resource access

### Content Security
- Hidden element detection
- Clickjacking attempt identification
- Cross-origin frame analysis
- Form action validation
- Resource integrity checking

## API Endpoints

### POST /api/analyze-url
Comprehensive URL analysis with multi-source verification.

**Request:**
```json
{
  "url": "https://example.com",
  "page_content": "optional page HTML",
  "scripts": ["script1.js", "script2.js"],
  "forms": [{"action": "submit.php", "method": "post"}]
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "is_malicious": false,
  "risk_score": 15,
  "threats": [],
  "sources": ["Google Safe Browsing", "VirusTotal"],
  "timestamp": "2024-01-01T12:00:00"
}
```

### GET /api/threat-intelligence
Retrieve latest threat intelligence data.

### POST /api/report-threat
Submit user-reported threats for community verification.

## Database Schema

```sql
-- URL Analysis Results
CREATE TABLE url_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    risk_score INTEGER,
    threats TEXT,
    timestamp TEXT,
    sources TEXT
);

-- Malicious Domains Cache
CREATE TABLE malicious_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    threat_type TEXT,
    severity INTEGER,
    added_date TIMESTAMP,
    last_verified TIMESTAMP
);

-- Threat Intelligence Feed
CREATE TABLE threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    indicator_type TEXT,
    confidence_score REAL,
    source TEXT,
    last_updated TIMESTAMP
);

-- User Reports
CREATE TABLE threat_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    reported_by TEXT,
    threat_type TEXT,
    description TEXT,
    timestamp TIMESTAMP,
    verified BOOLEAN
);
```

## Configuration

### Extension Permissions
- `activeTab` - Access current tab information
- `webNavigation` - Monitor page navigation events
- `storage` - Store settings and cache data
- `webRequest` - Intercept and analyze network requests
- `tabs` - Access tab information
- `scripting` - Inject content scripts
- `alarms` - Schedule periodic tasks
- `host_permissions: ["<all_urls>"]` - Access all websites

### User Settings
- Real-time protection toggle
- Malicious site blocking level
- Phishing detection sensitivity
- Tracker blocking preferences
- Notification frequency
- Scan mode (real-time/periodic/manual)
- Whitelist management

## Development

### Build Commands

```bash
# Development mode with hot reload
npm run dev

# Production build
npm run build

# Type checking
npm run check

# Format code
npm run format

# Lint code
npm run lint
```

### Backend Development

```bash
# Run with auto-reload
uvicorn main:app --reload

# Run tests
pytest tests/

# Database migrations
python migrate.py
```

### Testing

```bash
# Frontend tests
npm run test

# Backend tests
cd backend
pytest

# Integration tests
npm run test:integration
```

## Rate Limits and Quotas

### Free Tier Limitations
- Google Safe Browsing: 10,000 queries/day
- VirusTotal: 4 requests/minute, 500 requests/day
- PhishTank: Unlimited queries with reasonable use
- URLhaus: Unlimited queries
- OpenPhish: Feed updated hourly

### Optimization Strategies
- Local caching of results (24-hour TTL)
- Request batching where possible
- Priority queue for high-risk URLs
- Background refresh of threat intelligence
- Local fallback for rate limit exceeded

## Privacy and Data Handling

### Data Collection
- URLs analyzed (not stored on server)
- Threat detection results (cached locally)
- User settings (stored in browser)
- Anonymous usage statistics (optional)

### No Data Sharing
- No personal information collected
- No browsing history transmitted
- No third-party analytics
- Optional backend usage only

### User Control
- Full data export capability
- Clear data on demand
- Disable cloud analysis option
- Local-only mode available

## Performance

### Optimization Techniques
- Lazy loading of threat databases
- Web worker for intensive analysis
- Request debouncing
- Efficient caching strategies
- Minimal memory footprint

### Benchmarks
- Popup load time: < 100ms
- URL analysis: < 200ms (cached)
- Backend response: < 500ms (multi-source)
- Memory usage: < 50MB average
- CPU impact: < 2% average

## Contributing

Contributions are welcome. Please follow these guidelines:

### Code Style
- Follow TypeScript/ESLint configuration
- Use Prettier for formatting
- Write descriptive commit messages
- Add tests for new features

### Pull Request Process
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request with description

### Reporting Issues
- Use GitHub Issues
- Include reproduction steps
- Provide browser version
- Attach relevant logs

## Security Considerations

### Extension Security
- Content Security Policy compliance
- Minimal permissions requested
- Secure communication channels
- Input validation and sanitization
- XSS prevention measures

### Backend Security
- API rate limiting
- Request authentication
- SQL injection prevention
- Input validation
- HTTPS enforcement

## Known Limitations

### Current Version
- VirusTotal free tier rate limits
- No real-time DNS analysis
- Limited ML model without OpenAI
- Single-browser support (Chrome only)
- No offline threat database

### Future Improvements
- Enhanced caching mechanisms
- Distributed threat intelligence
- Browser-agnostic architecture
- Offline mode capabilities
- Advanced ML models

## Roadmap

### Version 1.1
- Firefox extension support
- Enhanced UI/UX improvements
- Whitelist/blacklist management
- Export threat reports

### Version 1.2
- Custom ML model training
- Advanced behavioral analysis
- Real-time threat feed subscriptions
- Team collaboration features

### Version 2.0
- Multi-browser support (Edge, Safari)
- Enterprise features
- Advanced analytics dashboard
- Custom rule engine
- API for third-party integration

## License

MIT License

Copyright (c) 2024 Loxtention

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Support

### Getting Help
- GitHub Issues for bug reports
- GitHub Discussions for questions
- Documentation: [docs link]
- Email: support@Loxtention.dev

### Community
- Discord server: [invite link]
- Twitter: @Loxtention
- Blog: [blog link]

## Acknowledgments

- Google Safe Browsing for threat intelligence
- VirusTotal for malware scanning
- PhishTank for phishing database
- OpenPhish for community threat feeds
- SvelteKit framework and community
- Chrome Extensions documentation
- Open source security community

## Disclaimer

Loxtention is a security tool designed to enhance browsing safety. While it provides multiple layers of protection, no security tool can guarantee 100% safety. Users should still exercise caution when browsing unfamiliar websites. The developers are not liable for any damages resulting from the use of this extension.

## Version History

### 1.0.0 (Current)
- Initial release
- Multi-source threat intelligence integration
- Real-time URL analysis
- Content security monitoring
- Basic UI implementation
- Chrome extension support
- FastAPI backend
- SQLite database

---

Built with SvelteKit, FastAPI, and powered by multiple threat intelligence sources.
