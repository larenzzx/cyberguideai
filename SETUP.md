# CyberGuide AI - Local Setup Guide

## Prerequisites

- Python 3.13 recommended; Python 3.12+ required for Django 6
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
ABUSEIPDB_API_KEY=your-production-abuseipdb-key
OTX_API_KEY=your-production-otx-key
DEBUG=False
ALLOWED_HOSTS=your-domain.example
CSRF_TRUSTED_ORIGINS=https://your-domain.example
DATABASE_URL=postgresql://user:password@host:5432/database
```

Required packages are listed in `requirements.txt` and `package.json`.

## 7. Render Deployment

This repo includes:

- `render.yaml` for a Render web service and PostgreSQL database blueprint
- `build.sh` for installing dependencies, collecting static files, and running migrations
- `.python-version` pinned to Python 3.13.4

Recommended Render settings if configuring manually:

```bash
Build Command: bash build.sh
Start Command: gunicorn cyberguide.wsgi:application
```

Set these environment variables in Render:

```env
DEBUG=False
SECRET_KEY=generate-a-secure-secret
ALLOWED_HOSTS=your-render-service.onrender.com
CSRF_TRUSTED_ORIGINS=https://your-render-service.onrender.com
DATABASE_URL=your-render-postgresql-internal-database-url
GROQ_API_KEY=your-production-groq-key
VIRUSTOTAL_API_KEY=your-production-virustotal-key
ABUSEIPDB_API_KEY=your-production-abuseipdb-key
OTX_API_KEY=your-production-otx-key
```

Render will run:

```bash
pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
```

The app uses PostgreSQL in production when `DATABASE_URL` is set. If `DATABASE_URL` is not set, it falls back to local SQLite.

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
