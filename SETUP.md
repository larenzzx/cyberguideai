# CyberGuide AI - Local Setup Guide

## Prerequisites

- Python 3.10+
- Node.js 18+ for Tailwind CSS compilation
- Groq API key for AI chat: https://console.groq.com/keys
- VirusTotal API key for Threat Intelligence Lookup

## 1. Configure Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Then edit `.env`:

```env
SECRET_KEY=your-secret-key-here
GROQ_API_KEY=your-groq-api-key-here
VIRUSTOTAL_API_KEY=your-virustotal-api-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=
```

Keep `VIRUSTOTAL_API_KEY` server-side only. Do not place it in browser JavaScript, templates, or static files.

## 2. Python Backend Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## 3. Frontend CSS

Run this in a second terminal:

```bash
npm install
npm run watch:css
```

For a one-time production CSS build:

```bash
npm run build:css
```

## 4. Run Locally

Open:

```text
http://127.0.0.1:8000
```

Main features:

- Guest chat: `/`
- Authenticated chat: `/chat/`
- Threat Intelligence Lookup: `/threat-intelligence/`
- User management for staff users: `/users/`

## 5. Threat Intelligence Testing

Use `/threat-intelligence/` and submit one indicator at a time:

- IP address, such as `8.8.8.8`
- Domain, such as `example.com`
- URL, such as `https://example.com/path`
- MD5, SHA1, or SHA256 file hash

Expected behavior:

- Invalid input returns a validation error.
- Missing `VIRUSTOTAL_API_KEY` returns a configuration error.
- VirusTotal rate limits return a rate-limit message.
- Successful lookups show verdict, detection ratio, reputation, categories, last analysis stats, and a short summary.

## 6. Deploy Safely

In your hosting platform, configure these as server-side environment variables:

```env
SECRET_KEY=your-production-secret
GROQ_API_KEY=your-production-groq-key
VIRUSTOTAL_API_KEY=your-production-virustotal-key
DEBUG=False
ALLOWED_HOSTS=your-domain.example
CSRF_TRUSTED_ORIGINS=https://your-domain.example
```

Run the normal deployment commands for your host, including:

```bash
pip install -r requirements.txt
python manage.py migrate
npm install
npm run build:css
python manage.py collectstatic
```

Required packages are already listed in `requirements.txt` and `package.json`. No extra Python package is needed for VirusTotal because the project already uses `httpx`.

## Project Structure

```text
cyberguideai/
├── manage.py
├── package.json
├── requirements.txt
├── .env.example
├── SETUP.md
├── cyberguide/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── chat/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── forms.py
│   └── templates/
└── static/css/
    ├── input.css
    └── output.css
```
