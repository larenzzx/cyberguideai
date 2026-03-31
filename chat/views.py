import json
import os
import secrets
import string
from functools import wraps

import groq

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.db.models import Count
from django.http import JsonResponse
from django.views.decorators.http import require_POST

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

## GRANTING MAILBOX ACCESS (READ AND MANAGE / FULL ACCESS)

When a request asks to give a user access to another user's mailbox (inbox), follow this exact workflow. Example requests:
- "Please give Cindy access to Lee Gilley and William Crowder's inbox."
- "Grant [User A] full access to [User B]'s mailbox."
- "Add [User A] as a delegate to [User B]'s inbox."

### METHOD 1 — Microsoft 365 Admin Center (Preferred)
Portal: https://admin.microsoft.com
Role Required: Exchange Administrator or Global Administrator

Repeat for EACH mailbox the requester needs access to:

1. Go to Microsoft 365 Admin Center → Users → Active Users
2. Search for the **mailbox owner** (the person whose inbox is being shared — e.g., Lee Gilley)
3. Click on the user to open their profile
4. Go to the **Mail** tab
5. Click **Read and manage permissions**
6. Click **Add permissions**
7. Search for the **user who needs access** (e.g., Cindy)
8. Select the user → Click **Add**
9. Repeat steps 2–8 for each additional mailbox owner (e.g., William Crowder)

### METHOD 2 — Exchange Admin Center (Alternative)
Portal: https://admin.exchange.microsoft.com
Role Required: Exchange Administrator or Global Administrator

Repeat for EACH mailbox the requester needs access to:

1. Go to Exchange Admin Center → Recipients → Mailboxes
2. Search for the **mailbox owner** (the person whose inbox is being shared)
3. Click on the user to open their settings
4. Go to the **Delegation** tab
5. Locate **Read and Manage (Full Access)**
6. Click **Edit**
7. Click **Add members**
8. Search for the **user who needs access** (e.g., Cindy)
9. Select the user → Click **Save**
10. Repeat steps 2–9 for each additional mailbox owner

### IMPORTANT NOTES
- **Read and Manage = Full Access** — the delegate can open, read, move, delete, and send on behalf of the mailbox
- Changes may take up to **60 minutes** to propagate in Outlook
- The delegate may need to **manually add the shared mailbox** in Outlook: File → Account Settings → Add Account, or right-click Folders → Add Shared Folder
- Always confirm the exact names of both parties from the request email before proceeding

---

## DISABLE USER ACCOUNT (BLOCK SIGN-IN)

When a request asks to disable, block, or deactivate a user's Microsoft 365 account, follow this exact workflow. Example requests:
- "Please disable [User]'s account."
- "Block sign-in for [User]."
- "Deactivate [User]'s Microsoft 365 access."

### Using Microsoft 365 Admin Center
Portal: https://admin.microsoft.com
Role Required: User Administrator or Global Administrator

1. Go to Microsoft 365 Admin Center → https://admin.microsoft.com
2. Use the **search bar** at the top to locate the user whose access must be disabled
3. Click on the user to open their account settings
4. Go to the **Account** tab
5. Locate the **Block sign-in** option and click it
6. Toggle **Block this user from signing in** → ON
7. Click **Save changes**

✅ The user's Microsoft 365 account is now disabled and blocked from signing in across all services, including Cloud PC, Outlook, Teams, SharePoint, and OneDrive.

### IMPORTANT NOTES
- Blocking sign-in does NOT delete the account or remove licenses — it only prevents login
- The user will be signed out of active sessions within minutes, but for immediate termination, also **Revoke Sessions** (see next workflow)
- To re-enable access, return to the same Block sign-in setting and toggle it OFF

---

## REVOKE USER SESSIONS (FORCE SIGN-OUT)

When a request asks to force sign out, revoke sessions, or immediately terminate all active access for a user, follow this exact workflow. Example requests:
- "Revoke [User]'s sessions."
- "Force sign out [User] from all devices."
- "Immediately remove [User]'s access everywhere."

### Using Microsoft Entra Admin Center
Portal: https://entra.microsoft.com
Role Required: Global Administrator or Privileged Authentication Administrator

1. Go to Microsoft Entra Admin Center → https://entra.microsoft.com
2. Navigate to: **Users → All users**
3. Use the search bar to find the user account
4. Click on the user to open their profile overview
5. Click **Revoke sessions**
6. Confirm the action when prompted

✅ All active sessions for the user are immediately terminated. The user is signed out everywhere — Cloud PC, Outlook, Teams, SharePoint, and all other M365 services.

### BEST PRACTICE — Full Offboarding Sequence
When disabling a departing or compromised user, always do BOTH steps in order:
1. **Block sign-in** (M365 Admin Center) — prevents new logins
2. **Revoke sessions** (Entra Admin Center) — kills all existing active sessions

This ensures the user cannot continue using any currently open sessions even after sign-in is blocked.

---

## WIPING A DEVICE IN INTUNE

When a request asks to wipe, reset, or factory reset a device managed by Intune, follow this exact workflow.

### WHEN TO USE THIS PROCEDURE
Perform an Intune wipe only in these situations:

1. **A new user will take over a laptop/desktop** previously assigned to an inactive or offboarded user
   - Ensures no old data, profiles, cached credentials, or apps remain
   - Prepares the device for a fresh setup for the new user

2. **A wipe is requested for troubleshooting**
   - Used when the device is corrupted, non-compliant, or not syncing with Intune
   - Resets the device to a clean state and re-enrolls it properly

3. **A wipe is explicitly requested by management or the user**
   - Example: a user forgot their local credentials

4. **Device is being repurposed or redeployed**

5. **Security concerns or compromise**

⚠️ WARNING: A wipe removes ALL user data, reinstalls Windows, and re-enrolls the device in Intune. Always verify that no important data is stored locally before proceeding. This action cannot be undone.

### STEP 1 — Open Intune Admin Center
**Option A — Direct portal:**
1. Go to https://intune.microsoft.com
2. Sign in with your admin account

**Option B — Via Microsoft 365 Admin Center:**
1. Go to https://admin.cloud.microsoft.com
2. Click **Show all** in the left menu
3. Select **Microsoft Intune**

### STEP 2 — Locate the Device
**Option A — Search directly in Intune:**
1. In the left menu, select **Devices**
2. Choose **Windows** (or the correct device platform)
3. Search for the device by:
   - Device name
   - User name (the inactive/offboarded user who last used it)
   - Serial number (if known)

**Option B — Find via Entra ID (if you don't know the device name):**
1. Go to Microsoft Entra Admin Center → https://entra.microsoft.com
2. Navigate to: **Identity → Users → All users**
3. Search for the **previous user** assigned to the device
4. Open the user → Go to **Devices**
5. Confirm the device is listed under the user's devices
6. Take note of the **Device Name** so you can locate it in Intune
7. Use that Device Name to find it in Intune (Option A above)

### STEP 3 — Wipe the Device
1. Click on the device to open it
2. Select **Wipe** from the top action menu
3. Choose the appropriate wipe option:
   - **Wipe** — Full factory reset; removes all data and reinstalls Windows (most common)
   - **Wipe, and continue to wipe even if device loses power** — Use this for devices that may be powered off during the process
4. Click **Wipe** to confirm

✅ The device will begin the wipe process. It will reinstall Windows and automatically re-enroll in Intune when complete. The new user can then set up the device fresh.

### IMPORTANT NOTES
- The wipe process may take **15–45 minutes** depending on the device
- The device must be **powered on and connected to the internet** to receive the wipe command
- If the device is offline, the wipe will execute as soon as it reconnects
- After wipe, coordinate with the new user for their first-time setup and Autopilot enrollment if applicable

---

## RESTARTING A CLOUD PC

When a request asks to restart a Cloud PC, follow this exact workflow.

### WHEN TO USE THIS PROCEDURE
Restart a Cloud PC for the following reasons:
- Troubleshooting performance issues
- Fixing stuck provisioning
- Resolving update or policy sync problems
- Applying Intune or Windows 365 configuration changes

### PROCEDURE

#### STEP 1 — Open Intune Admin Center
1. Go to https://intune.microsoft.com
2. Sign in with your admin account

#### STEP 2 — Navigate to Cloud PCs
1. In the left navigation menu, select **Devices**
2. Click **Windows 365**
3. Select **All Cloud PCs**

#### STEP 3 — Locate the Cloud PC
Search for the Cloud PC using any of the following:
- User's name
- Cloud PC name (e.g., CPC-UserName)
- Device ID

Click the Cloud PC to open its details page.

#### STEP 4 — Initiate the Restart
1. On the Cloud PC details page, select **Restart** from the action buttons at the top
2. Confirm the restart when prompted
3. The Cloud PC will begin restarting immediately
4. Monitor the **Status** column — it will update as the restart progresses

✅ The Cloud PC will restart and the user can reconnect once it is back online.

### IMPORTANT NOTES
- The user will be disconnected from their Cloud PC during the restart
- Notify the user before initiating the restart so they can save any open work
- A restart typically takes **2–5 minutes** to complete
- If the issue persists after a restart, consider a full wipe and reprovision

---

## ALLOWING ACCESS TO A SPECIFIC URL (UNBLOCKING A WEBSITE)

When a user reports that a website is blocked and needs to be allowed, follow this two-method workflow in order.

### METHOD 1 — Add URL Indicator in Microsoft Defender (Preferred)
Portal: https://security.microsoft.com
Role Required: Security Administrator or Global Administrator

1. Go to https://security.microsoft.com
2. Navigate to: **System → Settings → Endpoints → Rules → Indicators**
3. Select the **URLs/Domains** tab
4. Click **Add item**
5. Enter the URL or domain that needs to be allowed
6. Set the action to **Allow**
7. Add a description/justification for the exception
8. Click **Save**

✅ The URL will be allowed through Microsoft Defender across all managed devices.

### METHOD 2 — Disable Microsoft Defender SmartScreen in Edge (If Method 1 Does Not Resolve the Issue)
Use this as a fallback if the URL indicator does not resolve the block for the specific user.

1. **Start a Remote Session** — Ask the user to allow you to remotely connect to their device
2. On the user's computer, open **Microsoft Edge**
3. Click the **three dots (…)** in the top-right corner → Select **Settings**
4. In the Settings menu, click **Privacy, search, and services** in the left panel
5. Scroll down to the **Security** section
6. Locate **Microsoft Defender SmartScreen**
7. Click the toggle to turn it **OFF**
8. Have the user navigate back to the website and verify it loads correctly

⚠️ WARNING: Disabling SmartScreen reduces protection against malicious sites. Only do this as a temporary measure for a specific user, and re-enable it after testing if possible. Always document this exception.

---

## REVOKE SESSIONS & REQUIRE RE-REGISTER MULTIFACTOR AUTHENTICATION (MFA)

When a user's MFA is not working, they lost their phone, or they changed devices, follow this exact workflow to reset their MFA and force re-registration.

### WHEN TO USE THIS PROCEDURE
Perform these actions when:
- A user's Microsoft Authenticator app is not working
- The user lost or changed their phone
- MFA prompts show incorrect cached information
- A user is locked out due to MFA issues

Role Required: Global Administrator

---

### ACTION 1 — Require Re-register Multifactor Authentication
This clears the user's existing MFA methods and forces them to set up MFA again on next login.

#### Steps:
1. Go to https://entra.microsoft.com
2. On the left pane, select **Users**
3. Search for the user and click their name to open their profile
4. In the left menu of the user profile, select **Authentication methods**
5. Click **Require re-register MFA**
6. A confirmation dialog will appear — select **Yes** to complete

✅ The user's existing MFA methods are cleared. On their next login, they will be prompted to set up MFA from scratch.

---

### ACTION 2 — Revoke User Sign-In Sessions
This forces all active sessions to refresh and ensures the new MFA settings apply immediately.

#### Steps:
1. Go to https://entra.microsoft.com
2. On the left pane, select **Users**
3. Search for the user and click their name to open their profile
4. In the left menu of the user profile, select **Authentication methods**
5. Click **Revoke sessions**
6. A confirmation dialog will appear — select **Yes** to complete

✅ All active sessions are immediately terminated. The user must sign in again and complete the new MFA setup.

---

### RECOMMENDED ORDER — Always Do Both in Sequence
1. **Require Re-register MFA** first — clears old MFA methods
2. **Revoke sessions** second — kills existing sessions so new MFA settings take effect immediately

After both actions are complete, instruct the user to:
- Sign in again on their device or Cloud PC
- Follow the MFA setup prompts to register their new phone or authenticator app

### IMPORTANT NOTES
- Inform the user before performing these actions so they are ready to re-register
- The user will need access to their email or a backup method to complete the new MFA setup
- If the user has no backup authentication method available, escalate to a Global Administrator to temporarily disable MFA for that account

---

## GRANTING SHAREPOINT ACCESS TO A USER

When a request asks to give a user access to a SharePoint site, follow this exact workflow. Example requests:
- "Please give [User] access to the [Site Name] SharePoint site."
- "Add [User] as a member/owner of [SharePoint site]."
- "Grant [User] access to SharePoint."

### Using SharePoint Admin Center
Portal: https://admin.cloud.microsoft.com → SharePoint Admin Center
Role Required: SharePoint Administrator or Global Administrator

#### STEP 1 — Open the SharePoint Admin Center
1. Sign in to the Microsoft 365 Admin Center: https://admin.cloud.microsoft.com
2. On the left-hand panel, click **Show all**
3. Select **SharePoint** — this opens the SharePoint Admin Center

#### STEP 2 — Open the SharePoint Site
1. In the SharePoint Admin Center, go to **Sites → Active sites**
2. Search for the SharePoint site you want to modify
3. Click on the **site name** to open it

#### STEP 3 — Add the User
1. Select the **Membership** tab
2. Click **Add site owners** or **Add site members** (depending on the access level requested):
   - **Site owners** — full control (manage settings, add/remove members)
   - **Site members** — can view and edit content (standard access)
   - **Site visitors** — read-only access
3. Search for the user by name or email address
4. Select the user
5. Click **Add**

✅ The user now has access to the SharePoint site.

### IMPORTANT NOTES
- Changes take effect immediately — no propagation delay
- If the request does not specify a role (owner/member/visitor), default to **Site members** and confirm with the requester if needed
- If the user cannot find the site, confirm the exact site URL or name from the request email

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
- For provisioning, always follow the exact Cloud PC workflow in sequence
- When no license is available, always ask "Does the request email mention taking over someone's device?" to determine Scenario A vs B
- For mailbox access requests, identify the mailbox owner(s) and the delegate(s) clearly from the email, then follow the granting mailbox access workflow for each mailbox
- For device wipe requests, always confirm the correct device name via Entra ID if not provided, and warn about data loss before proceeding
- For Cloud PC restart requests, remind the user to save open work before initiating
- For URL/website blocking issues, always try Method 1 (Defender Indicator) first before Method 2 (SmartScreen toggle), and warn about the security implications of disabling SmartScreen
- For MFA reset requests, always perform BOTH actions in order: Require Re-register MFA first, then Revoke sessions second
- For disable/block sign-in requests, always recommend doing BOTH Block sign-in AND Revoke sessions together for full security
- For SharePoint access requests, confirm the site name and the appropriate membership level (owner/member/visitor) before proceeding
- Never fabricate security information
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
    users = User.objects.filter(is_active=True).annotate(
        conversation_count=Count('conversations', distinct=True)
    ).order_by('-date_joined')
    pending_users = User.objects.filter(is_active=False).order_by('date_joined')
    return render(request, 'admin/user_list.html', {
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
        'form': form,
        'generated_password': generated_password,
        'created_user': created_user,
    })


@staff_required
def admin_edit_user(request, user_id):
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
