import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Create or update a superuser from DJANGO_SUPERUSER_* environment variables.'

    def handle(self, *args, **options):
        username = os.environ.get('DJANGO_SUPERUSER_USERNAME', '').strip()
        email = os.environ.get('DJANGO_SUPERUSER_EMAIL', '').strip()
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', '')

        if not username or not email or not password:
            self.stdout.write(
                'Skipping superuser creation because DJANGO_SUPERUSER_USERNAME, '
                'DJANGO_SUPERUSER_EMAIL, or DJANGO_SUPERUSER_PASSWORD is missing.'
            )
            return

        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'is_staff': True,
                'is_superuser': True,
            },
        )

        changed = created
        if user.email != email:
            user.email = email
            changed = True
        if not user.is_staff:
            user.is_staff = True
            changed = True
        if not user.is_superuser:
            user.is_superuser = True
            changed = True
        user.set_password(password)
        changed = True

        if changed:
            user.save()

        status = 'Created' if created else 'Verified'
        self.stdout.write(self.style.SUCCESS(f'{status} superuser "{username}".'))
