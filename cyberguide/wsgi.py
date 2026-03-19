"""
WSGI config for CyberGuide AI project.

LEARNING: WSGI (Web Server Gateway Interface) is the standard interface
between Python web apps and web servers. When you deploy to production
(PythonAnywhere, Heroku, etc.), the server calls this file to start your app.
Think of it as the "entry point" that connects your Django code to the web.

It exposes the WSGI callable as a module-level variable named 'application'.
For more information on this file, see:
https://docs.djangoproject.com/en/4.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguide.settings')

application = get_wsgi_application()
