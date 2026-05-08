# CyberGuide AI Setup and PythonAnywhere Deployment Guide

CyberGuide AI is a Django web app with TailwindCSS/DaisyUI styling, Groq-powered AI chat, threat intelligence lookup, IOC extraction, and phishing analysis.

This guide covers:

- Local installation
- Environment variable setup
- Running the app locally
- Deploying on PythonAnywhere
- Updating the PythonAnywhere deployment from the `pythonanywhere` Git branch

## Requirements

- Python 3.10+
- Node.js 18+ for Tailwind CSS builds
- Git
- API keys:
  - `GROQ_API_KEY` for AI chat
  - `VIRUSTOTAL_API_KEY` for VirusTotal lookups
  - `ABUSEIPDB_API_KEY` for AbuseIPDB IP reputation
  - `OTX_API_KEY` for AlienVault OTX enrichment

## Local Setup

Clone the repo:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
```

Create and activate a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install frontend dependencies:

```bash
npm install
```

Create `.env`:

```bash
copy .env.example .env
```

Example local `.env`:

```env
SECRET_KEY=your-local-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=

GROQ_API_KEY=your-groq-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
OTX_API_KEY=your-otx-api-key
```

Do not commit `.env`.

Run migrations:

```bash
python manage.py migrate
```

Create an admin user:

```bash
python manage.py createsuperuser
```

Build CSS:

```bash
npm run build:css
```

Run the app:

```bash
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

## Local Development Commands

Run Django checks:

```bash
python manage.py check
```

Watch CSS during development:

```bash
npm run watch:css
```

Build production CSS:

```bash
npm run build:css
```

## App Routes

- Guest chat: `/`
- Authenticated chat: `/chat/`
- Threat Intelligence Lookup: `/threat-intelligence/`
- IOC Extractor: `/ioc-extractor/`
- Phishing Analyzer: `/phishing-analyzer/`
- User profile: `/profile/`
- User management: `/users/`

## PythonAnywhere Branch Strategy

This branch is intended for the PythonAnywhere deployment:

```text
pythonanywhere
```

Recommended production branch setup:

```text
main             -> Render or future primary production
pythonanywhere   -> PythonAnywhere fallback/legacy production
```

If you update the PythonAnywhere version locally, work on this branch:

```bash
git checkout pythonanywhere
git pull origin pythonanywhere
```

After making changes:

```bash
git add .
git commit -m "Update PythonAnywhere deployment"
git push origin pythonanywhere
```

## First-Time PythonAnywhere Deployment

Open a Bash console on PythonAnywhere.

Clone the repo:

```bash
cd ~
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
```

Switch to the PythonAnywhere branch:

```bash
git fetch origin
git checkout pythonanywhere
git pull origin pythonanywhere
```

Create and activate a virtual environment:

```bash
python3.10 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create `.env` on PythonAnywhere:

```bash
nano .env
```

Example PythonAnywhere `.env`:

```env
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=yourusername.pythonanywhere.com
CSRF_TRUSTED_ORIGINS=https://yourusername.pythonanywhere.com

GROQ_API_KEY=your-production-groq-api-key
VIRUSTOTAL_API_KEY=your-production-virustotal-api-key
ABUSEIPDB_API_KEY=your-production-abuseipdb-api-key
OTX_API_KEY=your-production-otx-api-key
```

Run migrations:

```bash
python manage.py migrate
```

Collect static files:

```bash
python manage.py collectstatic
```

## PythonAnywhere Web App Settings

In the PythonAnywhere dashboard, go to **Web**.

Set the source code directory to your project folder, for example:

```text
/home/yourusername/YOUR_REPO
```

Set the virtualenv path:

```text
/home/yourusername/YOUR_REPO/venv
```

Set static files:

```text
URL: /static/
Directory: /home/yourusername/YOUR_REPO/staticfiles
```

Edit the WSGI file from the PythonAnywhere Web tab.

Use a WSGI configuration like this, adjusting paths:

```python
import os
import sys

project_home = '/home/yourusername/YOUR_REPO'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguide.settings')

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()


OR

import os
import sys

path = '/home/larenzzx/cyberguideai'
if path not in sys.path:
    sys.path.insert(0, path)

os.environ['DJANGO_SETTINGS_MODULE'] = 'cyberguide.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Save the WSGI file.

Click **Reload** on the PythonAnywhere Web tab.

## Updating PythonAnywhere After Pushing Changes

On your local machine:

```bash
git checkout pythonanywhere
git pull origin pythonanywhere

# make changes

npm run build:css
python manage.py check

git add .
git commit -m "Describe the update"
git push origin pythonanywhere
```

On PythonAnywhere:

```bash
cd /home/yourusername/YOUR_REPO
git checkout pythonanywhere
git pull origin pythonanywhere
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic
```

Then go to the PythonAnywhere **Web** tab and click **Reload**.

## When To Run Each Command On PythonAnywhere

Always run after pulling updates:

```bash
git pull origin pythonanywhere
python manage.py collectstatic
```

Run if Python dependencies changed:

```bash
pip install -r requirements.txt
```

Run if models or migrations changed:

```bash
python manage.py migrate
```

Always reload the web app after code changes:

```text
PythonAnywhere Web tab -> Reload
```

## Troubleshooting PythonAnywhere

Check the current Git branch:

```bash
git branch
```

Expected:

```text
* pythonanywhere
  main
```

Check latest Git status:

```bash
git status
```

Check environment variables are loaded:

```bash
python manage.py shell
```

Then:

```python
import os
print(bool(os.environ.get("GROQ_API_KEY")))
print(bool(os.environ.get("VIRUSTOTAL_API_KEY")))
print(bool(os.environ.get("ABUSEIPDB_API_KEY")))
print(bool(os.environ.get("OTX_API_KEY")))
```

If API keys were changed in `.env`, reload the web app.

If static files do not update:

```bash
python manage.py collectstatic
```

Then reload the web app.

If CSS looks old, make sure `static/css/output.css` was rebuilt locally and pushed:

```bash
npm run build:css
git add static/css/output.css
git commit -m "Rebuild CSS"
git push origin pythonanywhere
```

## Security Notes

- Never commit `.env`.
- Keep all API keys server-side.
- Use `DEBUG=False` in production.
- Set `ALLOWED_HOSTS` to the PythonAnywhere hostname.
- Set `CSRF_TRUSTED_ORIGINS` to the HTTPS PythonAnywhere URL.
- Rotate API keys if they are exposed accidentally.

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
└── static/
    ├── css/
    │   ├── input.css
    │   └── output.css
    └── images/
        └── cyberguideai-logo.png
```
