import json
import os
import base64
import ipaddress
import re
import secrets
import string
from functools import wraps
from urllib.parse import urlparse

import groq
import httpx

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.db.models import Count
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from dotenv import dotenv_values

from .models import Conversation, Message
from .forms import (
    RegisterForm,
    AdminCreateUserForm, AdminEditUserForm,
    ProfileEditForm, StyledPasswordChangeForm,
)

# =============================================================================
# CYBERGUIDE AI SYSTEM PROMPT
# =============================================================================

SYSTEM_PROMPT = """
You are CyberGuide AI, a cybersecurity, networking, Microsoft tools, and IT/helpdesk operations assistant for general professional guidance.

Core scope:
- Cybersecurity concepts, security operations, SOC workflows, incident triage, threat hunting, phishing analysis, vulnerability management, and defensive best practices.
- Networking fundamentals, DNS, DHCP, routing, firewalls, VPNs, wireless, packet-flow reasoning, and troubleshooting.
- Microsoft 365 ecosystem guidance for Entra ID, Microsoft 365 Admin Center, Intune, Microsoft Defender, Exchange Online, SharePoint, OneDrive, and related admin portals.
- IT/helpdesk troubleshooting, endpoint support, identity access issues, email issues, device management, and operational runbooks.

Strict privacy and tenant-safety rules:
- Never include or invent client names, company names, tenant names, internal group names, internal workflows, tenant-specific configurations, or organization-specific procedures.
- Never recommend specific license assignments, group assignments, tenant policies, internal distribution lists, department mappings, or client-specific exception processes.
- For Microsoft-related tasks, provide general best-practice steps only. If a decision depends on licensing, roles, group membership, policy names, geography, or tenant design, tell the user to confirm it with their organization's administrator or documented policy.
- Do not claim access to the user's tenant, logs, mailboxes, devices, or security tools. Ask for sanitized details when needed.
- If the user provides sensitive data, encourage redaction of secrets, tokens, private keys, passwords, personal data, tenant IDs, and internal hostnames unless they are essential and safe to share.

Response style:
- Use clear markdown with short sections, numbered steps for procedures, and bullets for checks or options.
- Bold important warnings, verdicts, portal names, and key actions.
- Prefer practical, general steps that an analyst or helpdesk technician can adapt safely.
- For phishing analysis, classify as **PHISHING**, **SUSPICIOUS**, or **LIKELY LEGITIMATE** and explain the observable indicators.
- For security investigations, include immediate containment, evidence collection, validation, remediation, and follow-up hardening where relevant.
- Never fabricate security facts, detections, CVEs, vendor behavior, or tool output. State uncertainty clearly.
"""
# =============================================================================
# HELPERS
# =============================================================================

def staff_required(view_func):
    """Decorator: requires authenticated + is_staff. Redirects accordingly."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(f'/login/?next={request.path}')
        if not request.user.is_staff:
            messages.error(request, 'Access denied. Admin privileges required.')
            return redirect('/chat/')
        return view_func(request, *args, **kwargs)
    return _wrapped


def _generate_password(length=14):
    """Generate a secure random password meeting complexity requirements."""
    chars = string.ascii_letters + string.digits + '!@#$%'
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        if (any(c.isupper() for c in pwd)
                and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)):
            return pwd


def _get_virustotal_api_key():
    api_key = os.environ.get('VIRUSTOTAL_API_KEY') or getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if api_key:
        return api_key.strip()

    env_path = settings.BASE_DIR / '.env'
    if env_path.exists():
        return (dotenv_values(env_path).get('VIRUSTOTAL_API_KEY') or '').strip()

    return ''


_HASH_PATTERNS = {
    'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
}
_DOMAIN_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$'
)


def _detect_indicator(indicator):
    value = indicator.strip()
    if not value:
        return None, None

    for hash_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(value):
            return 'file_hash', value.lower()

    try:
        ipaddress.ip_address(value)
        return 'ip_address', value
    except ValueError:
        pass

    parsed = urlparse(value)
    if parsed.scheme in {'http', 'https'} and parsed.netloc:
        return 'url', value

    normalized = value.rstrip('.').lower()
    if _DOMAIN_PATTERN.match(normalized):
        return 'domain', normalized

    return None, None


def _virustotal_url(indicator_type, value):
    if indicator_type == 'file_hash':
        return f'https://www.virustotal.com/api/v3/files/{value}'
    if indicator_type == 'ip_address':
        return f'https://www.virustotal.com/api/v3/ip_addresses/{value}'
    if indicator_type == 'domain':
        return f'https://www.virustotal.com/api/v3/domains/{value}'
    if indicator_type == 'url':
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
        return f'https://www.virustotal.com/api/v3/urls/{url_id}'
    return None


def _summarize_virustotal_result(indicator_type, value, payload):
    data = payload.get('data') or {}
    attrs = data.get('attributes') or {}
    stats = attrs.get('last_analysis_stats') or {}
    malicious = int(stats.get('malicious') or 0)
    suspicious = int(stats.get('suspicious') or 0)
    harmless = int(stats.get('harmless') or 0)
    undetected = int(stats.get('undetected') or 0)
    timeout = int(stats.get('timeout') or 0)
    total = sum(int(v or 0) for v in stats.values())

    if malicious > 0:
        verdict = 'Malicious'
    elif suspicious > 0:
        verdict = 'Suspicious'
    elif harmless > 0 and malicious == 0 and suspicious == 0:
        verdict = 'Clean'
    else:
        verdict = 'Unknown'

    categories = attrs.get('categories') or {}
    if isinstance(categories, dict):
        category_values = sorted({str(v) for v in categories.values() if v})
    else:
        category_values = []

    bad_count = malicious + suspicious
    if verdict == 'Malicious':
        explanation = f'{bad_count} engine(s) flagged this indicator as malicious or suspicious.'
    elif verdict == 'Suspicious':
        explanation = f'{bad_count} engine(s) reported suspicious activity, but no malicious consensus is present.'
    elif verdict == 'Clean':
        explanation = 'No engines flagged this indicator as malicious or suspicious in the last analysis.'
    else:
        explanation = 'VirusTotal has limited or no conclusive analysis for this indicator.'

    return {
        'indicator': value,
        'indicator_type': indicator_type,
        'verdict': verdict,
        'detection_ratio': f'{bad_count}/{total}' if total else '0/0',
        'reputation': attrs.get('reputation'),
        'categories': category_values[:8],
        'last_analysis_stats': {
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'timeout': timeout,
        },
        'summary': explanation,
    }


# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================

def register_view(request):
    if request.user.is_authenticated:
        return redirect('/chat/')

    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Requires admin approval before first login
            user.save()
            return redirect('/register/pending/')

    return render(request, 'auth/register.html', {'form': form})


def register_pending(request):
    """Shown after self-registration while waiting for admin approval."""
    return render(request, 'auth/register_pending.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('/chat/')

    if request.GET.get('goodbye'):
        messages.success(request, 'You have been logged out successfully.')

    account_pending = False
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            next_url = request.GET.get('next', '/chat/')
            return redirect(next_url)
        else:
            # Detect pending-approval: correct credentials but account is inactive
            username = request.POST.get('username', '')
            password = request.POST.get('password', '')
            try:
                pending_user = User.objects.get(username=username, is_active=False)
                if pending_user.check_password(password):
                    account_pending = True
            except User.DoesNotExist:
                pass
    else:
        form = AuthenticationForm()

    return render(request, 'auth/login.html', {'form': form, 'account_pending': account_pending})


def logout_view(request):
    logout(request)
    return redirect('/login/?goodbye=1')


# =============================================================================
# CHAT VIEWS
# =============================================================================

def guest_landing(request):
    """Root landing page — guests get the chat UI, logged-in users go to /chat/."""
    if request.user.is_authenticated:
        return redirect('/chat/')
    return render(request, 'chat/guest_home.html')


def threat_intelligence(request):
    """Standalone threat intelligence lookup page for guests and users."""
    context = {}
    if request.user.is_authenticated:
        context['conversations'] = Conversation.objects.filter(user=request.user)
    return render(request, 'threat_intel/lookup.html', context)


@require_POST
def threat_intelligence_lookup(request):
    """Server-side VirusTotal lookup. The API key never reaches the browser."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    indicator = str(data.get('indicator', '')).strip()
    indicator_type, normalized = _detect_indicator(indicator)
    if not indicator_type:
        return JsonResponse({
            'error': 'Invalid indicator. Enter an IP address, domain, URL, MD5, SHA1, or SHA256 hash.'
        }, status=400)

    api_key = _get_virustotal_api_key()
    if not api_key:
        return JsonResponse({
            'error': 'VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in your .env file.'
        }, status=500)

    vt_url = _virustotal_url(indicator_type, normalized)
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(vt_url, headers={
                'x-apikey': api_key,
                'accept': 'application/json',
            })

        if response.status_code == 401:
            return JsonResponse({'error': 'Invalid VirusTotal API key.'}, status=401)
        if response.status_code == 404:
            return JsonResponse({
                'result': {
                    'indicator': normalized,
                    'indicator_type': indicator_type,
                    'verdict': 'Unknown',
                    'detection_ratio': '0/0',
                    'reputation': None,
                    'categories': [],
                    'last_analysis_stats': {
                        'malicious': 0,
                        'suspicious': 0,
                        'harmless': 0,
                        'undetected': 0,
                        'timeout': 0,
                    },
                    'summary': 'VirusTotal does not have a report for this indicator.',
                }
            })
        if response.status_code == 429:
            return JsonResponse({
                'error': 'VirusTotal rate limit reached. Please wait and try again.'
            }, status=429)
        if response.status_code >= 400:
            return JsonResponse({
                'error': 'VirusTotal lookup failed. Please try again later.'
            }, status=502)

        return JsonResponse({
            'result': _summarize_virustotal_result(
                indicator_type,
                normalized,
                response.json()
            )
        })

    except httpx.TimeoutException:
        return JsonResponse({'error': 'VirusTotal request timed out.'}, status=504)
    except httpx.RequestError:
        return JsonResponse({'error': 'Could not connect to VirusTotal.'}, status=503)


@require_POST
def guest_send(request):
    """Guest chat endpoint — no login required, no DB writes."""
    try:
        data = json.loads(request.body)
        raw_messages = data.get('messages', [])

        valid_roles = {'user', 'assistant'}
        messages_for_api = [
            {'role': m['role'], 'content': str(m['content'])}
            for m in raw_messages[-10:]
            if isinstance(m, dict) and m.get('role') in valid_roles and m.get('content')
        ]

        if not messages_for_api:
            return JsonResponse({'error': 'No messages provided.'}, status=400)

        api_key = os.environ.get('GROQ_API_KEY', '')
        if not api_key:
            return JsonResponse({
                'error': 'API key not configured. Please set GROQ_API_KEY in your .env file.'
            }, status=500)

        client = groq.Groq(api_key=api_key)
        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            max_tokens=2048,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                *messages_for_api
            ]
        )

        assistant_text = response.choices[0].message.content or \
            'I encountered an issue generating a response. Please try again.'
        return JsonResponse({'response': assistant_text, 'error': None})

    except groq.AuthenticationError:
        return JsonResponse({
            'error': 'Invalid API key. Please check your GROQ_API_KEY in .env.'
        }, status=401)

    except groq.RateLimitError:
        return JsonResponse({
            'error': 'CyberGuide AI is currently busy. Please wait a moment and try again.',
            'rate_limited': True
        }, status=429)

    except groq.APIConnectionError:
        return JsonResponse({
            'error': 'Could not connect to the AI service. Please check your internet connection.'
        }, status=503)

    except groq.APIStatusError as e:
        return JsonResponse({'error': f'AI service error: {e.message}'}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    except Exception:
        return JsonResponse({
            'error': 'An unexpected error occurred. Please try again.'
        }, status=500)


@login_required
def chat_home(request):
    conversations = Conversation.objects.filter(user=request.user)
    return render(request, 'chat/home.html', {'conversations': conversations})


@login_required
def new_conversation(request):
    conversation = Conversation.objects.create(
        user=request.user,
        title='New Conversation'
    )
    prompt = request.GET.get('prompt', '').strip()
    if prompt:
        request.session['autofill_prompt'] = prompt
    return redirect(f'/chat/{conversation.id}/')


@login_required
def conversation_detail(request, conversation_id):
    conversation = get_object_or_404(
        Conversation,
        id=conversation_id,
        user=request.user
    )
    msgs = conversation.messages.all()
    conversations = Conversation.objects.filter(user=request.user)
    autofill = request.session.pop('autofill_prompt', '')

    return render(request, 'chat/conversation.html', {
        'conversation': conversation,
        'messages': msgs,
        'conversations': conversations,
        'autofill': autofill,
    })


@login_required
@require_POST
def send_message(request, conversation_id):
    try:
        data = json.loads(request.body)
        user_message_text = data.get('message', '').strip()

        if not user_message_text:
            return JsonResponse({'error': 'Message cannot be empty.'}, status=400)

        conversation = get_object_or_404(
            Conversation,
            id=conversation_id,
            user=request.user
        )

        Message.objects.create(
            conversation=conversation,
            role=Message.ROLE_USER,
            content=user_message_text
        )

        if conversation.title == 'New Conversation':
            conversation.generate_title(user_message_text)

        all_messages = conversation.messages.order_by('-timestamp')[:10]
        messages_for_api = [
            {'role': msg.role, 'content': msg.content}
            for msg in reversed(list(all_messages))
        ]

        api_key = os.environ.get('GROQ_API_KEY', '')
        if not api_key:
            return JsonResponse({
                'error': 'API key not configured. Please set GROQ_API_KEY in your .env file.'
            }, status=500)

        client = groq.Groq(api_key=api_key)

        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            max_tokens=2048,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                *messages_for_api
            ]
        )

        assistant_text = response.choices[0].message.content or \
            'I encountered an issue generating a response. Please try again.'

        Message.objects.create(
            conversation=conversation,
            role=Message.ROLE_ASSISTANT,
            content=assistant_text
        )

        return JsonResponse({'response': assistant_text, 'error': None})

    except groq.AuthenticationError:
        return JsonResponse({
            'error': 'Invalid API key. Please check your GROQ_API_KEY in .env.'
        }, status=401)

    except groq.RateLimitError:
        return JsonResponse({
            'error': 'CyberGuide AI is currently busy. Please wait a moment and try again.',
            'rate_limited': True
        }, status=429)

    except groq.APIConnectionError:
        return JsonResponse({
            'error': 'Could not connect to the AI service. Please check your internet connection.'
        }, status=503)

    except groq.APIStatusError as e:
        return JsonResponse({'error': f'AI service error: {e.message}'}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    except Exception:
        return JsonResponse({
            'error': 'An unexpected error occurred. Please try again.'
        }, status=500)


@login_required
@require_POST
def delete_conversation(request, conversation_id):
    conversation = get_object_or_404(
        Conversation,
        id=conversation_id,
        user=request.user
    )
    conversation.delete()
    messages.success(request, 'Conversation deleted.')
    return redirect('/chat/')


# =============================================================================
# ADMIN: USER MANAGEMENT
# =============================================================================

@staff_required
def admin_user_list(request):
    conversations = Conversation.objects.filter(user=request.user)
    users = User.objects.filter(is_active=True).annotate(
        conversation_count=Count('conversations', distinct=True)
    ).order_by('-date_joined')
    pending_users = User.objects.filter(is_active=False).order_by('date_joined')
    return render(request, 'admin/user_list.html', {
        'conversations': conversations,
        'users': users,
        'pending_users': pending_users,
    })


@staff_required
@require_POST
def admin_approve_user(request, user_id):
    user = get_object_or_404(User, id=user_id, is_active=False)
    user.is_active = True
    user.save()
    messages.success(request, f"Account for '{user.username}' has been approved. They can now sign in.")
    return redirect('/users/')


@staff_required
def admin_create_user(request):
    conversations = Conversation.objects.filter(user=request.user)
    generated_password = None
    created_user = None
    form = AdminCreateUserForm()

    if request.method == 'POST':
        form = AdminCreateUserForm(request.POST)
        if form.is_valid():
            password = _generate_password()
            user = User.objects.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=password,
                first_name=form.cleaned_data['first_name'],
                last_name=form.cleaned_data['last_name'],
            )
            user.is_staff = form.cleaned_data['is_admin']
            user.save()
            # Flag this user to change their password on first login
            user.profile.must_change_password = True
            user.profile.save()
            generated_password = password
            created_user = user
            form = AdminCreateUserForm()  # Reset for another creation

    return render(request, 'admin/create_user.html', {
        'conversations': conversations,
        'form': form,
        'generated_password': generated_password,
        'created_user': created_user,
    })


@staff_required
def admin_edit_user(request, user_id):
    conversations = Conversation.objects.filter(user=request.user)
    target_user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        form = AdminEditUserForm(request.POST, instance=target_user)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_staff = form.cleaned_data['is_admin']
            new_password = form.cleaned_data.get('new_password', '').strip()
            if new_password:
                user.set_password(new_password)
            user.save()
            messages.success(request, f'User "{user.username}" updated successfully.')
            return redirect('/users/')
    else:
        form = AdminEditUserForm(
            instance=target_user,
            initial={'is_admin': target_user.is_staff}
        )

    return render(request, 'admin/edit_user.html', {
        'conversations': conversations,
        'form': form,
        'target_user': target_user,
    })


@staff_required
@require_POST
def admin_delete_user(request, user_id):
    target_user = get_object_or_404(User, id=user_id)
    if target_user == request.user:
        messages.error(request, 'You cannot delete your own account.')
    else:
        username = target_user.username
        target_user.delete()
        messages.success(request, f'User "{username}" has been deleted.')
    return redirect('/users/')


# =============================================================================
# USER PROFILE
# =============================================================================

@login_required
def profile_view(request):
    conversations = Conversation.objects.filter(user=request.user)
    form = ProfileEditForm(instance=request.user)
    pw_form = StyledPasswordChangeForm(request.user)

    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'edit_profile':
            form = ProfileEditForm(request.POST, instance=request.user)
            if form.is_valid():
                form.save()
                messages.success(request, 'Profile updated successfully.')
                return redirect('/profile/')

        elif action == 'change_password':
            pw_form = StyledPasswordChangeForm(request.user, request.POST)
            if pw_form.is_valid():
                user = pw_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, 'Password changed successfully.')
                return redirect('/profile/')

    conversation_count = Conversation.objects.filter(user=request.user).count()

    return render(request, 'profile/profile.html', {
        'conversations': conversations,
        'form': form,
        'pw_form': pw_form,
        'conversation_count': conversation_count,
    })


# =============================================================================
# FORCED PASSWORD CHANGE (FIRST LOGIN)
# =============================================================================

@login_required
def forced_password_change(request):
    """
    Shown to users whose account was created by an admin with an
    auto-generated password. They must set a new password before
    they can access anything else in the app.
    """
    # If the flag is not set, they don't belong here
    try:
        if not request.user.profile.must_change_password:
            return redirect('/chat/')
    except Exception:
        return redirect('/chat/')

    pw_form = StyledPasswordChangeForm(request.user)

    if request.method == 'POST':
        pw_form = StyledPasswordChangeForm(request.user, request.POST)
        if pw_form.is_valid():
            user = pw_form.save()
            update_session_auth_hash(request, user)
            # Clear the flag — they've changed their password
            user.profile.must_change_password = False
            user.profile.save()
            messages.success(request, 'Password updated successfully. Welcome to CyberGuide AI!')
            return redirect('/chat/')

    return render(request, 'auth/change_password_required.html', {'pw_form': pw_form})
