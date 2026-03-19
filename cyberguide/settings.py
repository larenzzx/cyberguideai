"""
Django settings for CyberGuide AI.

LEARNING NOTE: settings.py is Django's central configuration file.
Think of it as the "blueprint" for your entire project — it tells Django
where to find templates, which apps are installed, how to connect to the
database, and much more.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
# LEARNING: python-dotenv reads key=value pairs from .env and makes them
# available via os.environ. Never hardcode secrets — always use env vars.
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
# LEARNING: Path(__file__) is the path to settings.py itself.
# .resolve().parent.parent walks two directories up to the project root.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# LEARNING: Django uses SECRET_KEY to sign cookies, CSRF tokens, etc.
# It must be unique per environment — never share or commit it.
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-change-me-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
# LEARNING: DEBUG=True shows detailed error pages. Always False in production.
DEBUG = os.environ.get('DEBUG', 'True') == 'True'

# LEARNING: ALLOWED_HOSTS is a security check. Django rejects requests
# from hosts not in this list. In production, add your domain here.
_allowed = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [h.strip() for h in _allowed.split(',') if h.strip()]

# Required in Django 4+ when running behind HTTPS (e.g. PythonAnywhere)
_origins = os.environ.get('CSRF_TRUSTED_ORIGINS', '')
CSRF_TRUSTED_ORIGINS = [o.strip() for o in _origins.split(',') if o.strip()]

# Application definition
# LEARNING: Django apps are modular components. Each one you create or
# install goes here. Django's built-in apps handle auth, admin, sessions, etc.
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',           # User authentication system
    'django.contrib.contenttypes',   # Content type framework
    'django.contrib.sessions',       # Session management
    'django.contrib.messages',       # Flash messages
    'django.contrib.staticfiles',    # Static file serving
    'chat',                          # Our custom chat application
]

# LEARNING: Middleware are functions that process every request/response.
# They run in order on the way in, and in reverse order on the way out.
# Think of them as a pipeline that every HTTP request passes through.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Serves static files in production
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',   # CSRF protection
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'chat.middleware.ForcePasswordChangeMiddleware',  # Redirect on first login if password must change
]

ROOT_URLCONF = 'cyberguide.urls'

# LEARNING: Templates tell Django where to find HTML files and which
# template engine to use. We use Django's built-in engine with Jinja-like
# syntax (actually Django Template Language, DTL).
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'chat' / 'templates'],  # Global template directory
        'APP_DIRS': True,  # Also look for templates inside each app's /templates/ folder
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',     # Adds {{ user }} to all templates
                'django.contrib.messages.context_processors.messages',  # Adds messages to templates
            ],
        },
    },
]

WSGI_APPLICATION = 'cyberguide.wsgi.application'

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
# LEARNING: Django supports multiple databases via its ORM (Object-Relational
# Mapper). SQLite is a file-based database — perfect for development.
# PostgreSQL is a production-grade database for when you scale.
#
# MIGRATION GUIDE: When you're ready to switch to PostgreSQL, comment out
# the SQLite block below and uncomment the PostgreSQL block. That's it —
# your Django ORM code stays the same because it's database-agnostic.
# =============================================================================

# ACTIVE: SQLite (development)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# READY TO SWAP: PostgreSQL (production)
# To migrate to PostgreSQL:
# 1. Install psycopg2: pip install psycopg2-binary
# 2. Comment out the SQLite block above
# 3. Uncomment the block below and fill in your credentials
#
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': os.environ.get('DB_NAME', 'cyberguide'),
#         'USER': os.environ.get('DB_USER', 'postgres'),
#         'PASSWORD': os.environ.get('DB_PASSWORD', ''),
#         'HOST': os.environ.get('DB_HOST', 'localhost'),
#         'PORT': os.environ.get('DB_PORT', '5432'),
#     }
# }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# =============================================================================
# STATIC FILES CONFIGURATION
# =============================================================================
# LEARNING: "Static files" are CSS, JavaScript, images — files that don't
# change per-request. In development, Django serves them automatically.
# In production, collectstatic gathers them all into STATIC_ROOT for serving.
# =============================================================================

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']  # Where your source static files live
STATIC_ROOT = BASE_DIR / 'staticfiles'    # Where collectstatic deposits everything

# WhiteNoise: serve static files efficiently in production without a CDN
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# AUTHENTICATION SETTINGS
# =============================================================================
# LEARNING: Django's built-in auth system handles login/logout/registration.
# LOGIN_URL tells @login_required where to redirect unauthenticated users.
# LOGIN_REDIRECT_URL is where users land after a successful login.
# =============================================================================

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/chat/'
LOGOUT_REDIRECT_URL = '/login/'

# =============================================================================
# AI PROVIDER CONFIGURATION — GROQ
# =============================================================================
# LEARNING: We load the API key from the environment — never hardcode it.
# The view reads it directly via os.environ.get('GROQ_API_KEY').
# Get a free API key (no credit card) at: https://console.groq.com/keys
# =============================================================================

GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
