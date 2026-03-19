"""
CyberGuide AI URL Configuration

LEARNING: urls.py is the router of your Django app. When a request comes in,
Django looks through these URL patterns top-to-bottom until it finds a match,
then calls the associated view function. Think of it like a phone directory
that maps addresses (URLs) to handlers (views).

The main urls.py typically includes other apps' urls.py files via include().
This keeps URL configuration modular and organized.
"""

from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    # Django admin — auto-generated database management interface
    path('admin/', admin.site.urls),

    # Include all chat app URLs (chat/, auth/, etc.)
    # LEARNING: include() is like delegating — "anything starting with
    # these prefixes, let the chat app's urls.py handle it"
    path('', include('chat.urls')),
]
