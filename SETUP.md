# CyberGuide AI Setup Guide

CyberGuide AI is a Django app with a Tailwind CSS frontend. Local development uses SQLite by default. Production on Render uses PostgreSQL through `DATABASE_URL`.

## Prerequisites

- Python 3.13 recommended; Python 3.12+ required for Django 6
- Node.js 18+ for Tailwind CSS compilation
- GitHub repository connected to Render
- Groq API key for AI chat
- VirusTotal API key for Threat Intelligence Lookup
- Optional AbuseIPDB and AlienVault OTX API keys for extra enrichment
- SMTP email account for approval notifications

## Local Setup

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Use values like this for local development:

```env
SECRET_KEY=your-local-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=
GROQ_API_KEY=your-groq-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
OTX_API_KEY=your-otx-api-key
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-app-password
DEFAULT_FROM_EMAIL=CyberGuide AI <your-email@example.com>
```

Do not commit `.env`. Keep API keys server-side only.
For Gmail, use a Google App Password instead of your normal account password.

Install and run the backend:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Compile frontend CSS in a second terminal:

```bash
npm install
npm run watch:css
```

For a one-time CSS build:

```bash
npm run build:css
```

Open:

```text
http://127.0.0.1:8000
```

## Main Routes

- Guest chat: `/`
- Login: `/login/`
- Authenticated chat: `/chat/`
- Threat Intelligence Lookup: `/threat-intelligence/`
- IOC Extractor: `/ioc-extractor/`
- Phishing Analyzer: `/phishing-analyzer/`
- Profile: `/profile/`
- User management: `/users/`

## Threat Intelligence Testing

Use `/threat-intelligence/` and submit one indicator at a time:

- IP address, such as `8.8.8.8`
- Domain, such as `example.com`
- URL, such as `https://example.com/path`
- MD5, SHA1, or SHA256 file hash

Expected behavior:

- Invalid input returns a validation error.
- Missing API keys return configuration errors for the affected source.
- Rate limits return a rate-limit message.
- Successful lookups show verdict, detection ratio or stats, reputation, categories, and a short summary.

## Phishing Analyzer Testing

Use `/phishing-analyzer/`.

Authenticated users can upload `.eml` files through the drag/drop upload area. The analyzer extracts email metadata and indicators, then enriches extracted indicators through the threat intelligence workflow.

## Render Deployment

This repo includes Render-ready deployment files:

- `render.yaml`: optional Render blueprint for a web service and PostgreSQL database
- `build.sh`: installs dependencies, collects static files, runs migrations, and optionally creates a deploy-time admin
- `.python-version`: pins Python to `3.13.4`

If configuring Render manually:

```text
Build Command: bash build.sh
Start Command: gunicorn cyberguide.wsgi:application
Branch: main
```

Create or connect a Render PostgreSQL database, then copy its Internal Database URL.

Add these environment variables individually in Render. Do not paste them as one block.

```env
DEBUG=False
SECRET_KEY=your-production-secret-key
DATABASE_URL=your-render-postgresql-internal-database-url
ALLOWED_HOSTS=cyberguideai.onrender.com,.onrender.com,localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://cyberguideai.onrender.com
GROQ_API_KEY=your-production-groq-key
VIRUSTOTAL_API_KEY=your-production-virustotal-key
ABUSEIPDB_API_KEY=your-production-abuseipdb-key
OTX_API_KEY=your-production-otx-key
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-production-email@example.com
EMAIL_HOST_PASSWORD=your-production-email-app-password
DEFAULT_FROM_EMAIL=CyberGuide AI <your-production-email@example.com>
```

For a different Render URL, replace `cyberguideai.onrender.com` with the exact hostname shown in your Render web service.

Important formatting:

- `ALLOWED_HOSTS` should not include `https://`
- `CSRF_TRUSTED_ORIGINS` should include `https://`
- `DATABASE_URL`, `SECRET_KEY`, and API keys must stay in Render environment variables

Deploy from Render:

```text
Manual Deploy -> Deploy latest commit
```

Render will run:

```bash
pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
python manage.py create_render_superuser
```

The final command is safe. It skips automatically unless the deploy-time superuser variables are present.

## Creating The First Admin On Render

If your Render plan provides Shell access, open:

```text
Render Dashboard -> Web Service -> Shell
```

Then run:

```bash
python manage.py createsuperuser
```

If Shell requires an upgrade, use the deploy-time admin method instead. Add these temporary environment variables:

```env
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_EMAIL=your-email@example.com
DJANGO_SUPERUSER_PASSWORD=your-secure-password
```

Redeploy the latest commit. After you can log in successfully, remove these variables:

```env
DJANGO_SUPERUSER_USERNAME
DJANGO_SUPERUSER_EMAIL
DJANGO_SUPERUSER_PASSWORD
```

Click Save Changes. The admin account remains in PostgreSQL after the variables are removed.

## Render Troubleshooting

If the live site shows `Bad Request (400)`, check `ALLOWED_HOSTS`.

For `https://cyberguideai.onrender.com`, use:

```env
ALLOWED_HOSTS=cyberguideai.onrender.com,.onrender.com,localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://cyberguideai.onrender.com
```

Then save and redeploy.

If Threat Intelligence says an API key is not configured, confirm the key name in Render is exact:

```env
VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY
OTX_API_KEY
```

If AI chat does not respond, confirm:

```env
GROQ_API_KEY
```

If account approval emails are not sent after an admin approves a pending user, confirm:

```env
EMAIL_HOST
EMAIL_PORT
EMAIL_USE_TLS
EMAIL_HOST_USER
EMAIL_HOST_PASSWORD
DEFAULT_FROM_EMAIL
```

For Gmail, the password must be an App Password.

## Updating Production

For Render production updates:

```bash
git add .
git commit -m "Update app"
git push origin main
```

Render should auto-deploy from `main` if Auto Deploy is enabled.

For PythonAnywhere backup production, keep using the separate `pythonanywhere` branch and pull that branch on PythonAnywhere.

## Project Structure

```text
cyberguideai/
|-- manage.py
|-- package.json
|-- requirements.txt
|-- render.yaml
|-- build.sh
|-- .python-version
|-- SETUP.md
|-- cyberguide/
|   |-- settings.py
|   |-- urls.py
|   `-- wsgi.py
|-- chat/
|   |-- management/commands/create_render_superuser.py
|   |-- models.py
|   |-- views.py
|   |-- urls.py
|   |-- forms.py
|   `-- templates/
`-- static/
    |-- css/
    `-- images/
```
