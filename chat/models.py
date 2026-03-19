"""
Chat Models

LEARNING: Models are Python classes that map to database tables.
Django's ORM (Object-Relational Mapper) handles SQL automatically —
you write Python, it writes SQL. This means you can switch from SQLite
to PostgreSQL without changing a single line of model code.

Each class = one database table.
Each class attribute = one database column.
"""

from django.db import models
from django.contrib.auth.models import User


class Conversation(models.Model):
    """
    Represents a single chat session between a user and CyberGuide AI.

    LEARNING: ForeignKey creates a many-to-one relationship.
    Many conversations can belong to one user.
    on_delete=models.CASCADE means: if the user is deleted, delete all
    their conversations too (cascading delete).
    """

    # The user who owns this conversation
    # LEARNING: Django's built-in User model handles auth for us.
    # We just reference it with a ForeignKey.
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='conversations'  # user.conversations.all() to get all convos
    )

    # Auto-generated from the first 6 words of the first message
    # blank=True means the field can be empty in forms
    # default='' means the DB column defaults to empty string
    title = models.CharField(max_length=200, default='New Conversation', blank=True)

    # auto_now_add=True: automatically set to now when the record is first created
    # LEARNING: This is read-only — you can never change it after creation.
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Default ordering: newest conversations first
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username}: {self.title}"

    def generate_title(self, first_message):
        """Generate a title from the first 6 words of the first message."""
        words = first_message.strip().split()[:6]
        title = ' '.join(words)
        # Truncate if too long and add ellipsis
        if len(first_message.split()) > 6:
            title += '...'
        self.title = title
        self.save()


class Message(models.Model):
    """
    Represents a single message in a conversation.

    LEARNING: Messages belong to a Conversation (ForeignKey).
    The role field tracks whether the message is from the user or the AI.
    This mirrors the Anthropic API's message format exactly —
    the API expects an array of {role, content} objects.
    """

    # Role choices: matches Anthropic API's expected format
    ROLE_USER = 'user'
    ROLE_ASSISTANT = 'assistant'
    ROLE_CHOICES = [
        (ROLE_USER, 'User'),
        (ROLE_ASSISTANT, 'Assistant'),
    ]

    # Which conversation this message belongs to
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name='messages'  # conversation.messages.all() to get all messages
    )

    # Who sent this message: 'user' or 'assistant'
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    # The actual message text
    # LEARNING: TextField is for long text (no max length).
    # CharField is for short text (requires max_length).
    content = models.TextField()

    # When this message was sent
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Messages ordered chronologically within a conversation
        ordering = ['timestamp']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}..."
