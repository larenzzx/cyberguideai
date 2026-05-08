# CyberGuide AI

CyberGuide AI is a cybersecurity, networking, Microsoft tools, and IT/helpdesk operations assistant built with Django. It combines an AI guidance chatbot with practical investigation tools for threat intelligence, IOC extraction, and phishing email analysis.

The app is designed for SOC analysts, helpdesk users, IT administrators, and cybersecurity learners who need a focused workspace for investigation and operational guidance.

## Features

### AI Assistant

- Guest chat available without an account
- Authenticated chat with saved conversations
- Cybersecurity concept explanations
- SOC analyst workflow guidance
- Networking troubleshooting support
- Microsoft 365, Entra ID, Intune, Defender, Exchange, SharePoint, and helpdesk guidance
- General best-practice responses without tenant-specific or client-specific instructions

### Threat Intelligence Lookup

Submit one indicator and CyberGuide AI detects the type automatically:

- IP address
- Domain
- URL
- MD5, SHA1, or SHA256 hash

Integrated enrichment sources:

- VirusTotal
- AbuseIPDB
- AlienVault OTX

Results include verdicts, detection data, reputation signals, categories, source-specific stats, and a short investigation summary.

### IOC Extractor

- Extracts indicators from pasted investigation text
- Supports common observables such as IPs, domains, URLs, and hashes
- Can enrich extracted indicators through the threat intelligence workflow
- Helps analysts move from raw text to actionable indicators quickly

### Phishing Analyzer

- Analyzes suspicious email content
- Supports `.eml` drag/drop upload for logged-in users
- Extracts email metadata and indicators
- Sends extracted indicators into threat intelligence enrichment
- Provides analyst-focused findings for phishing review

### User And Access Management

- User registration and login
- Staff/admin user management
- User approval workflow
- Profile page
- Forced password change support for admin-created users
- Custom confirmation modals instead of browser default alerts

### Deployment Support

- SQLite fallback for local development
- PostgreSQL support for production through `DATABASE_URL`
- Render-ready deployment using `gunicorn`, `build.sh`, and `render.yaml`
- WhiteNoise static file serving
- Environment-variable based secret and API key handling

## Tech Stack

- Django 6
- PostgreSQL for production
- SQLite for local development
- Gunicorn
- WhiteNoise
- Tailwind CSS
- DaisyUI-style utility classes and custom dark cybersecurity UI
- Groq API for AI chat
- VirusTotal, AbuseIPDB, and AlienVault OTX for threat intelligence enrichment


## Disclaimer

CyberGuide AI is intended for cybersecurity learning, research, helpdesk operations, and internal security investigation support. Validate findings with authoritative sources and your organization's approved processes before taking action in production environments.
