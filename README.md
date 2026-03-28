# JSReconRadar

A comprehensive Burp Suite extension for passive reconnaissance of JavaScript files. Detects secrets, API keys, endpoints, sensitive data, and security misconfigurations in HTTP responses in real-time.

Works on **both Burp Suite Community and Professional editions**.

## Features

### Detection (1,600+ patterns)

| Category | Examples | Severity |
|----------|----------|----------|
| **API Keys & Tokens** | AWS, GCP, Azure, Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, Shopify, Firebase, Discord, Telegram, Mapbox, and 30+ more services | HIGH |
| **AI API Keys** | OpenAI, Anthropic, Groq, Replicate, HuggingFace, Cohere, Mistral, Deepseek, Together AI, LangSmith, Pinecone, Voyage AI | HIGH |
| **Private Keys & Credentials** | RSA/DSA/EC/PGP private keys, HTTP Basic Auth, Bearer tokens, JWTs, hardcoded passwords | CRITICAL |
| **Database Connection Strings** | Redis, MongoDB, PostgreSQL, MySQL, AMQP URIs with credentials | CRITICAL |
| **JS Config Secrets** | `key:"value"` patterns in JS objects, escaped JSON-in-JS (`\"key\":\"value\"`), DSN configs, connection strings | CRITICAL/HIGH |
| **API Endpoints** | `/api/*`, `/rest/*`, `/graphql`, `/auth/*`, `/admin/*`, `/internal/*`, `/debug/*`, `/login`, `/logout`, `/token`, `/webhook`, `/ws/*`, and more | INFO |
| **URL/Path Extraction** | Full URLs, relative paths (`/path`, `../path`, `./path`), file references (`.php`, `.jsp`, `.json`, etc.) - LinkFinder-style | INFO |
| **Cloud Infrastructure** | AWS S3, Azure Blob, Google Cloud Storage, CloudFront, DigitalOcean Spaces, Firebase, Oracle Cloud, Alibaba Cloud | MEDIUM |
| **Internal/Dev Domains** | Staging, dev, internal, test, sandbox, preprod, localhost URLs | MEDIUM |
| **IP Addresses** | Internal IPs (10.x, 172.16.x, 192.168.x, 127.x) and external IPs (with octet validation) | MEDIUM/INFO |
| **Security Issues** | DOM XSS sinks (innerHTML, eval, document.write), prototype pollution, open redirects, JSONP callbacks, CORS misconfigurations | MEDIUM |
| **Source Code Disclosure** | Source map URLs, stack traces (Node.js, Python, Java, C#, PHP, Ruby), path disclosure, SQL errors, debug mode | MEDIUM |
| **Encoded Data** | Base64 with smart prefixes (JWT, PHP serialized, Java serialized, XML), hex strings | HIGH/INFO |
| **Email Addresses** | Email addresses found in JS responses | MEDIUM |
| **Sensitive File References** | `.env`, `.sql`, `.key`, `.pem`, `.bak`, `.conf`, `.credentials`, etc. | MEDIUM |
| **Credentials in URLs** | `https://user:pass@host.com` | HIGH |
| **TODO/FIXME Secrets** | Code comments containing TODO/FIXME near password/secret/key/token | HIGH |

### UI & Workflow

<img width="1897" height="895" alt="image" src="https://github.com/user-attachments/assets/f48e1d4d-de02-4584-b034-73c599dd8e92" />

- **Custom Tab** with sortable results table
- **Severity Color Coding** - CRITICAL (red), HIGH (orange), MEDIUM (yellow), INFO (gray)
- **Severity Filter Toggles** - Click to show/hide CRITICAL, HIGH, MEDIUM, INFO
- **Text Search Filter** - Filter results by URL, type, or value
- **Summary Stats** - Live count of findings per severity level
- **Request/Response Viewer** - Pretty/Raw/Hex/Render with auto-populated search box
- **Result Tab** - Formatted match context with JS beautification and search highlighting
- **Right-Click Context Menu** - Copy Value, Copy URL, Send to Repeater, Exclude Domain, Mark as False Positive
- **Save/Load Results** - Persist findings to JSON, reload in future sessions
- **Export CSV** - Export results for reporting
- **Scope Toggle** - Scan all traffic or scope-only
- **Custom Regex Patterns** - Add your own patterns via the Settings tab
- **Status Bar** - Live scanning status with active thread count

### Smart Filtering

- **CDN Domain Skip List** - Automatically skips googleapis.com, cdnjs.cloudflare.com, unpkg.com, jsdelivr.net, and 25+ other CDN/analytics domains
- **JS Library Skip** - Skips jquery, modernizr, gtm, fbevents, angular.min, react.min, etc.
- **Binary/CSS Skip** - Skips images, fonts, CSS, videos, archives
- **Response Size Limit** - Skips responses over 5MB
- **False Positive Filter** - Filters i18n translation keys, code patterns, SRI hashes, placeholder values, noise domains
- **Value-Based Deduplication** - Same secret from multiple JS files shows once with source count
- **Mark as False Positive** - Right-click to permanently mark a value as FP
- **Escaped JSON Support** - Auto-unescapes `\"` in JSON-in-JS strings so all patterns catch secrets in embedded JSON
- **Placeholder Rejection** - Filters `example`, `YOUR_API_KEY`, `XXXX`, `CHANGE_ME`, `fake_`, `dummy`, etc.

### Integration

- **Background Threading** - Non-blocking scanning, pages load instantly
- **Burp Site Map** - Discovered URLs automatically added to Burp's Site Map
- **IScannerCheck** - Also reports findings via Burp Pro's scanner (when available)
- **Excluded Domains** - Runtime domain exclusion via right-click menu

## Installation

### Requirements
- Burp Suite (Community or Professional)
- Jython 2.7 standalone JAR

### Setup

1. Download Jython standalone JAR from [jython.org](https://www.jython.org/download)
2. In Burp Suite: **Extender > Options > Python Environment** > set the Jython JAR path
3. **Extender > Extensions > Add**:
   - Extension Type: **Python**
   - Extension File: **JSReconRadar.py**
4. The **JSReconRadar** tab appears in Burp's main tab bar

## Usage

1. Browse a target website through Burp's proxy
2. Switch to the **JSReconRadar** tab to see findings
3. Use **severity toggles** to focus on CRITICAL/HIGH findings
4. Use the **Search** box to filter by keyword
5. Click any row to view the **Response** with the search term pre-filled
6. Switch to **Result** tab for formatted context with highlighting
7. Right-click rows to **Copy**, **Send to Repeater**, **Exclude Domain**, or **Mark as FP**
8. **Save** results to JSON for future reference
9. **Export CSV** for reporting

## Pattern Sources

Built from and inspired by:
- [SecretFinder](https://github.com/m4ll0k/SecretFinder) by m4ll0k
- [JSAnalyzer](https://github.com/jenish-sojitra/JSAnalyzer) by jenish-sojitra
- [KeyHacks](https://github.com/streaak/keyhacks) by streaak
- [JS Miner](https://github.com/PortSwigger/js-miner) by PortSwigger
- [jsluice](https://github.com/BishopFox/jsluice) by BishopFox
- [LinkFinder](https://github.com/GerbenJav);a/LinkFinder) by Gerben Javado

## Author

**AB2** (Abdou Yelles) - [@ab2pentest](https://github.com/ab2pentest)

## License

This tool is provided for authorized security testing, defensive security, bug bounty, and educational purposes only.
