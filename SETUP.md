# CyberGuide AI — Local Setup Guide

## Prerequisites
- Python 3.10+
- Node.js 18+ (for Tailwind CSS compilation)
- A free Groq API key (see below)

---

## 1. Get a Free Groq API Key

CyberGuide AI uses **Groq** as its AI provider — it's completely free with no credit card required.

1. Go to **https://console.groq.com/keys**
2. Sign up with a Google or GitHub account
3. Click **"Create API Key"**
4. Copy the key — you'll add it to `.env` in the next step

Groq's free tier gives you 14,400 requests/day and 30 requests/minute.
The model used is `llama-3.3-70b-versatile` (Meta's Llama 3.3, 70B parameters).

---

## 2. Configure Environment Variables

```bash
# Copy the example env file
cp .env.example .env
```

Then edit `.env` and fill in your values:

```
SECRET_KEY=<generate one with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())">
GROQ_API_KEY=gsk_...your_key_here...
DEBUG=True
```

---

## 3. Python Backend Setup

```bash
# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# (Optional) Create an admin account
python manage.py createsuperuser

# Start the development server
python manage.py runserver
```

---

## 4. Frontend CSS (Second Terminal)

Tailwind CSS is compiled via the CLI — run this in a separate terminal:

```bash
npm install
npm run watch:css
```

This watches `static/css/input.css` and compiles to `static/css/output.css` on every save.
For a one-time production build, use `npm run build:css` instead.

---

## 5. Open the App

Navigate to **http://127.0.0.1:8000** — you'll be redirected to the login page.

1. Register a new account
2. Click **"New Conversation"**
3. Start chatting with CyberGuide AI

---

## Project Structure

```
cyberguideai/
├── manage.py               # Django CLI
├── package.json            # npm: Tailwind watch/build scripts
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── SETUP.md                # This file
├── cyberguide/             # Django project package
│   ├── settings.py         # Configuration (SQLite + PostgreSQL-ready)
│   ├── urls.py             # Root URL router
│   └── wsgi.py             # Production WSGI entry point
├── chat/                   # Main application
│   ├── models.py           # Conversation + Message database models
│   ├── views.py            # All views + Groq API integration
│   ├── urls.py             # URL patterns
│   ├── forms.py            # Registration form
│   └── templates/          # HTML templates (DaisyUI night theme)
└── static/css/
    ├── input.css           # Tailwind v4 source
    └── output.css          # Compiled CSS (auto-generated, gitignored)
```

---

## Switching to PostgreSQL Later

In `cyberguide/settings.py`, find the `DATABASES` block.
Comment out the SQLite config and uncomment the PostgreSQL block.
No ORM code needs to change — only the connection settings.
