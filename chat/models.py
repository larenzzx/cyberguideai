from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class Conversation(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='conversations'
    )
    title = models.CharField(max_length=200, default='New Conversation', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username}: {self.title}"

    def generate_title(self, first_message):
        words = first_message.strip().split()[:6]
        title = ' '.join(words)
        if len(first_message.split()) > 6:
            title += '...'
        self.title = title
        self.save()


class Message(models.Model):
    ROLE_USER = 'user'
    ROLE_ASSISTANT = 'assistant'
    ROLE_CHOICES = [
        (ROLE_USER, 'User'),
        (ROLE_ASSISTANT, 'Assistant'),
    ]

    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name='messages'
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}..."


class UserProfile(models.Model):
    """
    Extends Django's built-in User model with extra fields.
    Linked one-to-one: every User has exactly one UserProfile.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    # When True, user is redirected to change their password before anything else.
    # Set to True by admin when creating an account with an auto-generated password.
    must_change_password = models.BooleanField(default=False)

    def __str__(self):
        return f"Profile: {self.user.username}"


# Auto-create a UserProfile whenever a new User is saved.
@receiver(post_save, sender=User)
def ensure_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
