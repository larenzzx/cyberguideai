from django.contrib import admin
from .models import Conversation, Message

# Register models with Django admin for easy database management
# LEARNING: Registering models here makes them available at /admin/
# so you can view, edit, and delete records through a browser interface.

@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'created_at']
    list_filter = ['user', 'created_at']
    search_fields = ['title', 'user__username']


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['role', 'conversation', 'timestamp']
    list_filter = ['role', 'timestamp']
    search_fields = ['content', 'conversation__title']
