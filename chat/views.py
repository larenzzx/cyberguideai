"""
Chat Views

LEARNING: Views are the "controllers" of Django. They receive an HTTP request,
do some work (query the DB, call an API, process a form), and return an
HTTP response. Think of them as functions that handle the business logic.

The request/response lifecycle:
  Browser → URL router → View function → Template renderer → Browser
"""

import json
import os
import groq

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from .models import Conversation, Message
from .forms import RegisterForm

# =============================================================================
# THE CYBERGUIDE AI SYSTEM PROMPT
# =============================================================================
# LEARNING: A system prompt is the "personality card" you hand to the AI
# before the conversation starts. It sets the role, expertise, tone, and
# behavior of the AI. Every single API call includes this prompt —
# the AI "reads" it fresh on every request because the API is stateless.
# =============================================================================

SYSTEM_PROMPT = """
You are CyberGuide AI, an expert cybersecurity assistant specialized in helping IT professionals, SOC analysts, and security engineers. You have deep knowledge in the following areas:

## CYBERSECURITY EXPERTISE
- Threat analysis: phishing, email impersonation, BEC (Business Email Compromise), social engineering
- SOC operations: alert triage, incident response, threat hunting
- Security frameworks: NIST, MITRE ATT&CK, Zero Trust
- Vulnerability management and risk assessment
- Network security, endpoint protection, SIEM tools

## MICROSOFT SECURITY & M365 ECOSYSTEM

### Microsoft Entra ID (formerly Azure AD)
- User and group management
- Conditional Access policies
- MFA configuration
- App registrations and enterprise apps
- Role assignments (Global Admin, Security Admin, etc.)
- Identity Protection

### Microsoft Intune
- Device enrollment (Windows, iOS, Android, macOS)
- Compliance policies and configuration profiles
- App deployment and management
- Windows Autopilot
- Cloud PC / Windows 365 provisioning
- Intune groups and dynamic membership rules

### Microsoft Defender Suite
- Defender for Endpoint (MDE): onboarding, alerts, threat & vulnerability management
- Defender for Identity
- Defender for Office 365 (anti-phishing, safe links, safe attachments)
- Defender for Cloud Apps (CASB)
- Microsoft Sentinel (SIEM/SOAR)
- Security score and recommendations

### Exchange Online
- Mailbox management and permissions
- Transport rules and mail flow
- Anti-spam and anti-phishing policies
- DKIM, DMARC, SPF configuration
- eDiscovery and compliance

### SharePoint Online & OneDrive
- Site and library management
- Permission levels and sharing settings
- Data loss prevention (DLP) policies
- Sensitivity labels

### Windows 365 / Cloud PC
- Provisioning policies and network connections
- Azure network integration
- CPC provisioning troubleshooting
- License assignment (Windows 365 Enterprise)

---

## PROVISIONING A NEW USER WITH A VIRTUAL MACHINE (CLOUD PC)

This is the exact internal workflow to follow when asked to provision a new user and set up their Cloud PC/VM. Follow these steps precisely.

### STEP 1 — Create the User in Microsoft 365 Admin Center
Portal: https://admin.microsoft.com
Role Required: User Administrator or Global Administrator

1. Go to Microsoft 365 Admin Center → Users → Active users
2. Click "Add a user"
3. Fill in the basics:
   - First name, Last name, Display name
   - Username (UPN format: firstname.lastname@domain.com)
   - Password settings:
     • Let Microsoft auto-generate a password
     • Keep "Require this user to change their password when they first sign in" enabled
4. Click Next

### STEP 2 — Assign Product Licenses
1. Set Usage location = United States (required before any license can be assigned)
2. Toggle ON:
   - Office 365 E3
   - Windows 365 Enterprise (4 vCPU, 16 GB, 128 GB or 256 GB) OR (16 vCPU, 64 GB, 512 GB) — based on the request

3. IF NO LICENSES ARE AVAILABLE:

   SCENARIO A — Email states the new hire will take over someone's device or licenses:

   A1: Remove the old employee from device-related groups in Entra ID
   - Portal: https://entra.microsoft.com
   - Entra Admin Center → Entra ID → Users → All users
   - Search for the old user → Open → Go to Groups
   - Find "new_cloud_pc" → Remove from group

   A2: Remove licenses from the old user
   - Portal: https://admin.microsoft.com
   - Users → Active users → search for the old user
   - Open → Licenses and Apps
   - Turn OFF: Microsoft 365 / Office 365 E3 and Windows 365 Enterprise
   - Click Save changes — licenses are now free for reassignment

   A3: Assign the freed licenses to the new user, then click Next

   SCENARIO B — Email does NOT specify a takeover AND no licenses are available:

   B1: Identify an inactive user
   - Portal: https://entra.microsoft.com
   - Entra Admin Center → Groups → All groups
   - Search for and open "Inactive Users" group
   - Choose a user who is no longer active
   - Open that user → Groups → Remove from: new_cloud_pc
   - Removing from new_cloud_pc will deprovision their Cloud PC

   B2: Remove licenses from the inactive user
   - Microsoft 365 Admin Center → Active Users → search for inactive user
   - Open → Licenses and Apps
   - Remove: M365 / O365 E3 and Windows 365 Enterprise → Save changes

   B3: Assign the newly freed licenses to the new user

### STEP 3 — Optional Settings
Fill in ONLY if explicitly provided in the request email:
- Job title, Department, Office/Location, Mobile phone number

Click Next → Finish adding

### STEP 4 — Handle Credentials After Account Creation
1. Screenshot the generated credentials
2. Send credentials in TWO SEPARATE emails:
   - Email 1: Username only
   - Email 2: Password only — screenshot showing ONLY the password value, no labels or extra info visible
3. Include the Cloud PC sign-in link: https://windows.cloud.microsoft/

### STEP 5 — Add the User to Required Groups in Entra ID
Portal: https://entra.microsoft.com

1. Groups → All groups → search for each required group
2. Open group → Members → Add members → search for new user → Select

ALWAYS add to:
- new_cloud_pc → this triggers Intune to start provisioning the Cloud PC/VM

ALSO add based on the request email:
- Policy Exception – TrendMicro
- Policy Exception – GEO-Fencing (if location is outside India or the US)
- Any other department or security groups mentioned in the request

### STEP 6 — Verify Cloud PC Deprovisioning (When Repurposing a Cloud PC)
Portal: https://intune.microsoft.com

1. Intune Admin Center → Devices → Windows 365 → All Cloud PCs
2. Find the old user's Cloud PC → check Status column → should show "In grace period"
3. Click the Cloud PC entry → Select "Deprovision now"
   - This accelerates the release so the new user's Cloud PC provisions faster

### STEP 7 — Monitor New User's Cloud PC Provisioning
1. Intune → Devices → Windows 365 → All Cloud PCs
2. Search for the new user
3. Status:
   - "Provisioning" → still being built (wait 15–30 minutes)
   - "Provisioned" → Cloud PC is ready for use

---

## PHISHING & EMAIL ANALYSIS
When a user asks to analyze an email for phishing or impersonation:
1. Ask them to paste headers, sender address, subject, and body
2. Analyze for:
   - Sender domain spoofing or lookalike domains
   - Mismatched Reply-To addresses
   - Urgency or fear-based language
   - Suspicious links or attachments
   - Failed SPF/DKIM/DMARC (if headers provided)
   - Impersonation of executives, vendors, or trusted brands
3. Verdict: PHISHING / SUSPICIOUS / LIKELY LEGITIMATE
4. Explain reasoning with specific indicators
5. Recommend next steps (report to Microsoft, block sender, submit to Defender)

## RESPONSE STYLE
- Direct, clear, and structured
- Numbered steps for all procedures
- Bullet points for lists
- **Bold** for important terms and verdicts
- ⚠️ WARNING for security risks
- For provisioning, always follow the exact workflow above in sequence
- When no license is available, always ask "Does the request email mention taking over someone's device?" to determine Scenario A vs B
- Never fabricate security information
"""


# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================

def register_view(request):
    """
    User registration view.

    LEARNING: Django's pattern for form views:
    - GET request → show the empty form
    - POST request → validate submitted data
      - Valid → save and redirect
      - Invalid → re-render form with error messages
    """
    if request.user.is_authenticated:
        return redirect('/chat/')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Log the user in immediately after registration
            login(request, user)
            return redirect('/chat/')
    else:
        form = RegisterForm()

    return render(request, 'auth/register.html', {'form': form})


def login_view(request):
    """
    User login view using Django's built-in AuthenticationForm.

    LEARNING: AuthenticationForm validates username + password and
    returns the authenticated user object if credentials are correct.
    """
    if request.user.is_authenticated:
        return redirect('/chat/')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            # Redirect to the 'next' parameter if it exists (set by @login_required)
            next_url = request.GET.get('next', '/chat/')
            return redirect(next_url)
    else:
        form = AuthenticationForm()

    return render(request, 'auth/login.html', {'form': form})


def logout_view(request):
    """Log out the current user and redirect to login page."""
    logout(request)
    return redirect('/login/')


# =============================================================================
# CHAT VIEWS
# =============================================================================

@login_required
def chat_home(request):
    """
    Chat home page: lists all conversations for the current user.

    LEARNING: @login_required is a decorator that checks if the user is
    authenticated. If not, it redirects to LOGIN_URL (set in settings.py).
    It's like a bouncer at the door — no ticket, no entry.

    The filter(user=request.user) ensures users only see their own conversations.
    This is critical for data privacy.
    """
    conversations = Conversation.objects.filter(user=request.user)
    return render(request, 'chat/home.html', {'conversations': conversations})


@login_required
def new_conversation(request):
    """
    Create a new empty conversation and redirect to it.

    LEARNING: We create the conversation first (empty), then redirect to its
    detail page. The title will be set when the first message is sent.
    """
    conversation = Conversation.objects.create(
        user=request.user,
        title='New Conversation'
    )
    return redirect(f'/chat/{conversation.id}/')


@login_required
def conversation_detail(request, conversation_id):
    """
    Load and display a conversation with all its messages.

    LEARNING: get_object_or_404 is a Django shortcut that:
    - Tries to find the object matching the given criteria
    - Returns it if found
    - Returns a 404 HTTP error page if not found

    We also filter by user to prevent users from accessing other users' chats
    (security: always filter by the logged-in user when accessing user data).
    """
    conversation = get_object_or_404(
        Conversation,
        id=conversation_id,
        user=request.user  # Security check: own conversations only
    )
    messages = conversation.messages.all()
    all_conversations = Conversation.objects.filter(user=request.user)

    return render(request, 'chat/conversation.html', {
        'conversation': conversation,
        'messages': messages,
        'all_conversations': all_conversations,
    })


@login_required
@require_POST
def send_message(request, conversation_id):
    """
    Handle sending a message to the AI and returning the response.

    AI PROVIDER: Groq (https://console.groq.com)
    MODEL: llama-3.3-70b-versatile (Meta's Llama 3.3, 70B parameters)
    WHY GROQ:
      - Completely free tier, no credit card required
      - OpenAI-compatible API format — messages array uses the same
        role/content structure we already build, so integration is minimal
      - llama-3.3-70b-versatile is a top-tier open-source model,
        excellent for technical cybersecurity content
      - Very fast inference (Groq's custom LPU chips)
      - api.groq.com is reachable from PythonAnywhere free tier

    LEARNING: This is an AJAX endpoint — it returns JSON instead of HTML.
    The browser's JavaScript fetch() calls this URL, sends a message,
    and receives a JSON response without reloading the page.

    Why we send the FULL history every time:
    The Groq API (like all LLM APIs) is STATELESS — no memory between requests.
    Each call is independent. To give the AI "memory" of the conversation,
    we must send ALL previous messages on every single request.
    This is exactly how all LLM chat apps work under the hood.

    CSRF protection: The @require_POST decorator + csrftoken header in fetch()
    ensures only legitimate requests from our site can call this endpoint.
    """
    try:
        # Parse the JSON body sent by JavaScript's fetch()
        data = json.loads(request.body)
        user_message_text = data.get('message', '').strip()

        if not user_message_text:
            return JsonResponse({'error': 'Message cannot be empty.'}, status=400)

        # Get the conversation (security: verify it belongs to this user)
        conversation = get_object_or_404(
            Conversation,
            id=conversation_id,
            user=request.user
        )

        # STEP 1: Save the user's message to the database
        # We save it before calling the API so it persists even if the API fails
        Message.objects.create(
            conversation=conversation,
            role=Message.ROLE_USER,
            content=user_message_text
        )

        # STEP 2: Auto-generate title from first message (if still default)
        if conversation.title == 'New Conversation':
            conversation.generate_title(user_message_text)

        # STEP 3: Build the FULL message history for this conversation
        # LEARNING: We query ALL messages in order and format them for the API.
        # This is the "stateless by design" pattern — we reconstruct context
        # from the database on every request.
        all_messages = conversation.messages.all().order_by('timestamp')
        messages_for_api = [
            {
                'role': msg.role,
                'content': msg.content
            }
            for msg in all_messages
        ]

        # STEP 4: Call the Groq API
        # LEARNING: We initialize the client fresh per request. In a high-traffic
        # app you'd share a client instance, but this is fine for our scale.
        api_key = os.environ.get('GROQ_API_KEY', '')
        if not api_key:
            return JsonResponse({
                'error': 'API key not configured. Please set GROQ_API_KEY in your .env file.'
            }, status=500)

        client = groq.Groq(api_key=api_key)

        # Make the API call with the full conversation history.
        # LEARNING: Groq uses OpenAI-compatible format. The system prompt goes
        # as the first message with role "system". The rest of the conversation
        # history follows in order. max_tokens caps the response length.
        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            max_tokens=2048,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                *messages_for_api   # Spreads the existing history list after system
            ]
        )

        # Extract the text from the response.
        # LEARNING: Groq's response mirrors OpenAI's structure.
        # choices[0].message.content is the assistant's reply text.
        assistant_text = response.choices[0].message.content or \
            'I encountered an issue generating a response. Please try again.'

        # STEP 5: Save Claude's response to the database
        Message.objects.create(
            conversation=conversation,
            role=Message.ROLE_ASSISTANT,
            content=assistant_text
        )

        # STEP 6: Return the response as JSON to the browser
        return JsonResponse({
            'response': assistant_text,
            'error': None
        })

    except groq.AuthenticationError:
        return JsonResponse({
            'error': 'Invalid API key. Please check your GROQ_API_KEY in .env.'
        }, status=401)

    except groq.RateLimitError:
        return JsonResponse({
            'error': 'Rate limit reached. Please wait a moment and try again.'
        }, status=429)

    except groq.APIConnectionError:
        return JsonResponse({
            'error': 'Could not connect to the AI service. Please check your internet connection.'
        }, status=503)

    except groq.APIStatusError as e:
        return JsonResponse({
            'error': f'AI service error: {e.message}'
        }, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    except Exception as e:
        return JsonResponse({
            'error': 'An unexpected error occurred. Please try again.'
        }, status=500)


@login_required
@require_POST
def delete_conversation(request, conversation_id):
    """
    Delete a conversation and all its messages.

    LEARNING: Deleting the Conversation automatically deletes all associated
    Messages because of on_delete=CASCADE on the Message model's ForeignKey.
    Django handles this in a single database transaction.
    """
    conversation = get_object_or_404(
        Conversation,
        id=conversation_id,
        user=request.user
    )
    conversation.delete()
    return redirect('/chat/')
