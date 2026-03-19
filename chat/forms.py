"""
Chat Forms

LEARNING: Django forms handle two things:
1. Rendering HTML form fields
2. Validating and cleaning submitted data

Using forms instead of raw HTML gives you built-in CSRF protection,
field validation, and error messages for free.
"""

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm


class RegisterForm(UserCreationForm):
    """
    Registration form that extends Django's built-in UserCreationForm.

    LEARNING: UserCreationForm already includes username, password, and
    password confirmation. We add email as a required field.

    class Meta tells Django which model this form is for and which fields
    to include. Django auto-generates the form fields from the model.
    """

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'input input-bordered w-full',
            'placeholder': 'your@email.com'
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add DaisyUI classes to all form fields
        self.fields['username'].widget.attrs.update({
            'class': 'input input-bordered w-full',
            'placeholder': 'Choose a username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'input input-bordered w-full',
            'placeholder': 'Create a password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'input input-bordered w-full',
            'placeholder': 'Confirm your password'
        })

    def save(self, commit=True):
        """Override save to also store the email address."""
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user
