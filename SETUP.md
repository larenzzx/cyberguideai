# CyberGuide AI Setup and Deployment Guide

CyberGuide AI is a Django web app with TailwindCSS/DaisyUI styling, Groq-powered AI chat, threat intelligence lookup, IOC extraction, and phishing analysis. Local development uses SQLite by default. Production on Render uses PostgreSQL, while PythonAnywhere uses SQLite.

This guide covers:
- Local installation
- Environment variable setup
- Running the app locally
- Deploying on PythonAnywhere (SQLite)
- Deploying on Render (PostgreSQL)
- Project Structure

---

## Requirements / Prerequisites

- **Python**: Python 3.10+ (Python 3.12+ recommended; Python 3.13 recommended for Render)
- **Node.js**: Node.js 18+ for Tailwind CSS builds
- **Git**
- **API Keys**:
  - `GROQ_API_KEY` for Groq-powered AI Chat
  - `VIRUSTOTAL_API_KEY` for VirusTotal lookups
  - `ABUSEIPDB_API_KEY` for AbuseIPDB IP reputation lookup (optional/recommended)
  - `OTX_API_KEY` for AlienVault OTX enrichment (optional/recommended)

---

## Local Setup

1. **Clone the repo**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
   cd YOUR_REPO
   ```

2. **Create and activate a virtual environment**:
   - Windows:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     python -m venv venv
     source venv/bin/activate
     ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install frontend dependencies**:
   ```bash
   npm install
   ```

5. **Create your local environment file (`.env`)**:
   - Windows:
     ```bash
     copy .env.example .env
     ```
   - macOS/Linux:
     ```bash
     cp .env.example .env
     ```

6. **Configure `.env`**:
   Open `.env` and fill in your details:
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
   > [!IMPORTANT]
   > Do not commit your `.env` file to source control. Keep your keys secret!

7. **Run migrations**:
   ```bash
   python manage.py migrate
   ```

8. **Create a Django superuser**:
   ```bash
   python manage.py createsuperuser
   ```

9. **Build Tailwind CSS**:
   - For one-time CSS build:
     ```bash
     npm run build:css
     ```
   - To watch CSS changes during development (in a separate terminal window):
     ```bash
     npm run watch:css
     ```

10. **Run the development server**:
    ```bash
    python manage.py runserver
    ```

11. **Open the application in your browser**:
    ```text
    http://127.0.0.1:8000/
    ```

---

## App Routes

- **Guest Chat**: `/` (unauthenticated, rate-limited)
- **Login**: `/login/`
- **Authenticated Chat**: `/chat/` (full chat history, suggestions)
- **Threat Intelligence Lookup**: `/threat-intelligence/` (multi-source IOC lookup)
- **IOC Extractor**: `/ioc-extractor/` (extracts defanged and standard IOCs)
- **Phishing Analyzer**: `/phishing-analyzer/` (upload `.eml` or paste emails for triage)
- **User Profile**: `/profile/`
- **User Management (Admin-only)**: `/users/`

---

## Testing Features

### Threat Intelligence Testing
Use `/threat-intelligence/` and submit one indicator at a time:
- IP address, such as `8.8.8.8`
- Domain, such as `example.com`
- URL, such as `https://example.com/path`
- MD5, SHA1, or SHA256 file hash

**Expected behavior**:
- Invalid input returns a validation error.
- Missing API keys return configuration errors for the affected source.
- Rate limits return a rate-limit message.
- Successful lookups show verdict, detection ratio or stats, reputation, categories, and a short summary.

### Phishing Analyzer Testing
Use `/phishing-analyzer/`.
- Authenticated users can upload `.eml` files through the drag/drop upload area.
- The analyzer extracts email metadata and indicators, then enriches extracted indicators through the threat intelligence workflow.

---

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

---

## PythonAnywhere Deployment

### First-Time PythonAnywhere Deployment
1. **Open a Bash console on PythonAnywhere**.
2. **Clone the repo**:
   ```bash
   cd ~
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
   cd YOUR_REPO
   ```
3. **Switch to the PythonAnywhere branch**:
   ```bash
   git fetch origin
   git checkout pythonanywhere
   git pull origin pythonanywhere
   ```
4. **Create and activate a virtual environment**:
   ```bash
   python3.10 -m venv venv
   source venv/bin/activate
   ```
5. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
6. **Create `.env` on PythonAnywhere**:
   ```bash
   nano .env
   ```
7. **Example PythonAnywhere `.env`**:
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
8. **Run migrations**:
   ```bash
   python manage.py migrate
   ```
9. **Collect static files**:
   ```bash
   python manage.py collectstatic
   ```

### PythonAnywhere Web App Settings
In the PythonAnywhere dashboard, go to the **Web** tab:
1. **Source code directory**: `/home/yourusername/YOUR_REPO`
2. **Virtualenv path**: `/home/yourusername/YOUR_REPO/venv`
3. **Static files**:
   - URL: `/static/`
   - Directory: `/home/yourusername/YOUR_REPO/staticfiles`

4. **WSGI configuration**:
   Edit the WSGI file from the PythonAnywhere Web tab and configure it as follows:
   ```python
   import os
   import sys

   project_home = '/home/yourusername/YOUR_REPO'
   if project_home not in sys.path:
       sys.path.insert(0, project_home)

   os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguide.settings')

   from django.core.wsgi import get_wsgi_application
   application = get_wsgi_application()
   ```

5. **Save the WSGI file** and click **Reload** on the PythonAnywhere Web tab.

### Updating PythonAnywhere After Pushing Changes
On your local machine:
```bash
git checkout pythonanywhere
git pull origin pythonanywhere

# Make your changes
npm run build:css
python manage.py check

git add .
git commit -m "Describe the update"
git push origin pythonanywhere
```

On PythonAnywhere (in your project's Bash console):
```bash
cd /home/yourusername/YOUR_REPO
git checkout pythonanywhere
git pull origin pythonanywhere
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic
```
Go to the PythonAnywhere **Web** tab and click **Reload**.

### When To Run Each Command On PythonAnywhere
- **Always run after pulling updates**:
  ```bash
  git pull origin pythonanywhere
  python manage.py collectstatic
  ```
- **Run if Python dependencies changed**:
  ```bash
  pip install -r requirements.txt
  ```
- **Run if models or database migrations changed**:
  ```bash
  python manage.py migrate
  ```
- **Always reload the web app after code updates**:
  - PythonAnywhere Web tab -> **Reload**

### Troubleshooting PythonAnywhere
- **Check the current Git branch**:
  ```bash
  git branch
  ```
  Expected:
  ```text
  * pythonanywhere
    main
  ```
- **Check latest Git status**:
  ```bash
  git status
  ```
- **Check environment variables are loaded**:
  Run the Django shell:
  ```bash
  python manage.py shell
  ```
  Then execute:
  ```python
  import os
  print(bool(os.environ.get("GROQ_API_KEY")))
  print(bool(os.environ.get("VIRUSTOTAL_API_KEY")))
  print(bool(os.environ.get("ABUSEIPDB_API_KEY")))
  print(bool(os.environ.get("OTX_API_KEY")))
  ```
  If API keys were changed in `.env`, reload the web app.
- **If static files or styles do not update**:
  ```bash
  python manage.py collectstatic
  ```
  If CSS looks old, make sure `static/css/output.css` was rebuilt locally and pushed:
  ```bash
  npm run build:css
  git add static/css/output.css
  git commit -m "Rebuild CSS"
  git push origin pythonanywhere
  ```
  Then reload the web app.

---

## Render Deployment

This repo includes Render-ready deployment files:
- `render.yaml`: Optional Render blueprint for a web service and PostgreSQL database
- `build.sh`: Installs dependencies, collects static files, runs migrations, and optionally creates a deploy-time admin
- `.python-version`: Pins Python to `3.13.4`

### Render Manual Configuration
- **Build Command**: `bash build.sh`
- **Start Command**: `gunicorn cyberguide.wsgi:application`
- **Branch**: `main`

Create or connect a Render PostgreSQL database, then copy its Internal Database URL.

Add these environment variables individually in Render (do not paste them as one block):
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
```

### Creating The First Admin On Render
If your Render plan provides Shell access:
1. Go to **Render Dashboard -> Web Service -> Shell**.
2. Run:
   ```bash
   python manage.py createsuperuser
   ```
If Shell requires an upgrade, use the deploy-time admin method instead by adding these temporary environment variables in Render:
```env
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_EMAIL=your-email@example.com
DJANGO_SUPERUSER_PASSWORD=your-secure-password
```
Redeploy the latest commit. Once you can log in successfully, remove these temporary variables from Render environment settings.

### Render Troubleshooting
- If the live site shows `Bad Request (400)`, check `ALLOWED_HOSTS`.
- If Threat Intelligence says an API key is not configured, confirm the key name in Render is exact.
- If AI chat does not respond, confirm `GROQ_API_KEY`.

---

## Security Notes

- Never commit `.env` or hardcode API keys.
- Keep all API keys server-side.
- Use `DEBUG=False` in production.
- Set `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` correctly.
- Rotate API keys if they are exposed accidentally.

---

## Project Structure

```text
cyberguideai/
├── manage.py
├── package.json
├── requirements.txt
├── render.yaml
├── build.sh
├── .python-version
├── SETUP.md
├── cyberguide/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── chat/
│   ├── management/
│   │   └── commands/
│   │       └── create_render_superuser.py
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── forms.py
│   └── templates/
│       └── chat/
│           ├── conversation.html
│           ├── guest_home.html
│           └── home.html
└── static/
    ├── css/
    │   ├── input.css
    │   └── output.css
    └── images/
        └── cyberguideai-logo.png
```
