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
