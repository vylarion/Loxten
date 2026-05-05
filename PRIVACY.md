# Privacy Policy for Loxten

**Last updated: May 5, 2026**

## Data Collection

Loxten does not collect, store, or transmit any personal data, browsing history, or user information. All processing occurs entirely within the user's browser on the local device.

## Permissions Used

The extension requests the following Chrome permissions and their purposes:

| Permission | Purpose |
|---|---|
| `activeTab` | Read the URL of the currently active tab for security analysis |
| `webNavigation` | Detect page navigation events to trigger security analysis |
| `storage` | Save user settings, whitelist, and statistics locally on the device |
| `webRequest` | Read HTTP response headers to audit security header configuration |
| `tabs` | Query tab information and update badge indicators |
| `declarativeNetRequest` | Block known tracker domains at the network request level |

No permission is used to collect or transmit data.

## External Services

The only external service Loxten communicates with is the public RDAP (Registration Data Access Protocol) service at `rdap.org`. When visiting a website, the extension may send the site's domain name (e.g., `example.com`) to `rdap.org` to look up the domain registration date. This is used solely to determine if a domain was recently registered (a common indicator of phishing sites).

- No personal information is sent.
- Domain names are standard public information available through any WHOIS or RDAP lookup.
- No analytics, tracking, or advertising services are used.

## Data Storage

All user data is stored locally in the browser using `chrome.storage.sync` and `chrome.storage.local`:

- **Settings** (protection toggles, alert level) are synced across Chrome browsers signed in to the same Google Account.
- **Whitelist entries** and **statistics** are stored locally on the device.

Users can delete all stored data at any time via the Loxten Settings panel (Clear Data button).

## Data Sharing

Loxten does not share any data with third parties. No user data is sold, rented, or otherwise transferred.

## Changes to This Policy

If this privacy policy is updated, the version date at the top will be revised.

## Contact

For questions about this privacy policy, open an issue on the Loxten GitHub repository.