"""
Chat App URL Patterns

LEARNING: Each app has its own urls.py to keep routing modular.
The main cyberguide/urls.py includes this file via include().
URL patterns are matched top-to-bottom — the first match wins.

URL parameters like <int:conversation_id> are captured and passed
as keyword arguments to the view function.
"""

from django.urls import path
from django.views.generic import RedirectView
from . import views

urlpatterns = [
    # Root: redirect to /chat/ — the @login_required on chat_home handles
    # unauthenticated users by redirecting them to /login/ automatically.
    # LEARNING: RedirectView is a Django class-based view for simple redirects.
    # permanent=False sends HTTP 302 (Temporary Redirect).
    path('', RedirectView.as_view(url='/chat/', permanent=False), name='root'),

    # Authentication
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Chat — all protected by @login_required in the view
    path('chat/', views.chat_home, name='chat_home'),
    path('chat/new/', views.new_conversation, name='new_conversation'),

    # <int:conversation_id> — Django captures this integer from the URL
    # and passes it to the view as conversation_id parameter
    path('chat/<int:conversation_id>/', views.conversation_detail, name='conversation_detail'),
    path('chat/<int:conversation_id>/send/', views.send_message, name='send_message'),
    path('chat/<int:conversation_id>/delete/', views.delete_conversation, name='delete_conversation'),
]
