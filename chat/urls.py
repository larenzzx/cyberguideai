from django.urls import path
from . import views

urlpatterns = [
    # Root — guest landing / redirect to /chat/ if logged in
    path('', views.guest_landing, name='root'),

    # Authentication
    path('register/', views.register_view, name='register'),
    path('register/pending/', views.register_pending, name='register_pending'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Guest (no login required)
    path('guest/send/', views.guest_send, name='guest_send'),

    # Threat intelligence (available to guests and authenticated users)
    path('threat-intelligence/', views.threat_intelligence, name='threat_intelligence'),
    path('threat-intelligence/lookup/', views.threat_intelligence_lookup, name='threat_intelligence_lookup'),
    path('ioc-extractor/', views.ioc_extractor, name='ioc_extractor'),
    path('ioc-extractor/extract/', views.ioc_extract, name='ioc_extract'),
    path('ioc-extractor/enrich/', views.ioc_enrich, name='ioc_enrich'),
    path('ioc-extractor/summary/', views.ioc_summary, name='ioc_summary'),
    path('phishing-analyzer/', views.phishing_analyzer, name='phishing_analyzer'),
    path('phishing-analyzer/analyze/', views.phishing_analyze, name='phishing_analyze'),
    path('phishing-analyzer/upload-eml/', views.phishing_upload_eml, name='phishing_upload_eml'),

    # Chat (login required)
    path('chat/', views.chat_home, name='chat_home'),
    path('chat/new/', views.new_conversation, name='new_conversation'),
    path('chat/<int:conversation_id>/', views.conversation_detail, name='conversation_detail'),
    path('chat/<int:conversation_id>/send/', views.send_message, name='send_message'),
    path('chat/<int:conversation_id>/delete/', views.delete_conversation, name='delete_conversation'),

    # Forced password change (first login with auto-generated password)
    path('change-password-required/', views.forced_password_change, name='forced_password_change'),

    # User profile
    path('profile/', views.profile_view, name='profile'),

    # Admin: user management
    path('users/', views.admin_user_list, name='admin_user_list'),
    path('users/create/', views.admin_create_user, name='admin_create_user'),
    path('users/<int:user_id>/edit/', views.admin_edit_user, name='admin_edit_user'),
    path('users/<int:user_id>/delete/', views.admin_delete_user, name='admin_delete_user'),
    path('users/<int:user_id>/approve/', views.admin_approve_user, name='admin_approve_user'),
]
