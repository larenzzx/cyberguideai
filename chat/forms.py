from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm as DjangoPasswordChangeForm


class RegisterForm(UserCreationForm):
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
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


class AdminCreateUserForm(forms.Form):
    first_name = forms.CharField(
        max_length=150, required=False,
        widget=forms.TextInput(attrs={
            'class': 'input input-bordered w-full',
            'placeholder': 'First name'
        })
    )
    last_name = forms.CharField(
        max_length=150, required=False,
        widget=forms.TextInput(attrs={
            'class': 'input input-bordered w-full',
            'placeholder': 'Last name'
        })
    )
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'input input-bordered w-full',
            'placeholder': 'username (no spaces)'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'input input-bordered w-full',
            'placeholder': 'user@company.com'
        })
    )
    is_admin = forms.BooleanField(
        required=False,
        label='Grant admin privileges (can manage users)'
    )

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('This username is already taken.')
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('An account with this email already exists.')
        return email


class AdminEditUserForm(forms.ModelForm):
    is_admin = forms.BooleanField(
        required=False,
        label='Admin role (can manage users)'
    )
    new_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'input input-bordered w-full',
            'placeholder': 'Leave blank to keep current password'
        }),
        label='Reset password'
    )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['first_name', 'last_name', 'username', 'email']:
            self.fields[field_name].widget.attrs.update({
                'class': 'input input-bordered w-full'
            })
        self.fields['first_name'].required = False
        self.fields['last_name'].required = False


class ProfileEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['first_name', 'last_name', 'email']:
            self.fields[field_name].widget.attrs.update({
                'class': 'input input-bordered w-full'
            })
        self.fields['first_name'].required = False
        self.fields['last_name'].required = False


class StyledPasswordChangeForm(DjangoPasswordChangeForm):
    """Django's PasswordChangeForm with DaisyUI input classes applied."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        placeholders = {
            'old_password': 'Current password',
            'new_password1': 'New password',
            'new_password2': 'Confirm new password',
        }
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'input input-bordered w-full',
                'placeholder': placeholders.get(field_name, '')
            })
