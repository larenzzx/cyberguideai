import json
import os
import base64
from email import policy
from email.parser import BytesParser
import hashlib
import ipaddress
import re
import secrets
import string
from functools import wraps
from urllib.parse import quote, urlparse

import groq
import httpx

from django.conf import settings
from django.core.cache import cache
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.db.models import Count
from django.http import JsonResponse
from django.utils import timezone
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

MAX_EML_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_PHISHING_EXTERNAL_LOOKUPS = 40

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


def _get_env_secret(name):
    api_key = os.environ.get(name) or getattr(settings, name, '')
    if api_key:
        return api_key.strip()

    env_path = settings.BASE_DIR / '.env'
    if env_path.exists():
        return (dotenv_values(env_path).get(name) or '').strip()

    return ''


def _get_virustotal_api_key():
    return _get_env_secret('VIRUSTOTAL_API_KEY')


_HASH_PATTERNS = {
    'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
}
_HASH_EXTRACT_PATTERNS = {
    'md5': re.compile(r'(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])'),
    'sha1': re.compile(r'(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])'),
    'sha256': re.compile(r'(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])'),
}
_DOMAIN_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$'
)
_EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b')
_URL_PATTERN = re.compile(r'\b(?:hxxps?|https?)://[^\s<>"\')]+', re.IGNORECASE)
_IPV4_CANDIDATE_PATTERN = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
_DOMAIN_CANDIDATE_PATTERN = re.compile(
    r'(?<![@\w.-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![\w.-])'
)
GUEST_CHAT_DAILY_LIMIT = 5
GUEST_TI_DAILY_LIMIT = 3
GUEST_PHISHING_DAILY_LIMIT = 3
GUEST_LIMIT_MESSAGE = 'Guest limit reached. Please log in with an approved account to continue using full CyberGuide AI features.'
LOGIN_REQUIRED_SOC_MESSAGE = 'Sign in with an approved account to enrich indicators and unlock full SOC investigation features.'


def _daily_session_count(request, key):
    today = timezone.localdate().isoformat()
    usage = request.session.get(key)
    if not isinstance(usage, dict) or usage.get('date') != today:
        usage = {'date': today, 'count': 0}
        request.session[key] = usage
    return usage


def _consume_guest_limit(request, key, limit):
    if request.user.is_authenticated:
        return True, 0, limit

    usage = _daily_session_count(request, key)
    if int(usage.get('count') or 0) >= limit:
        return False, 0, limit

    usage['count'] = int(usage.get('count') or 0) + 1
    request.session[key] = usage
    request.session.modified = True
    return True, max(0, limit - usage['count']), limit


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

    try:
        parsed = urlparse(value)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme in {'http', 'https'} and parsed.netloc:
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


def _source_result(name, key, status, verdict='Unknown', metrics=None, summary=''):
    return {
        'name': name,
        'key': key,
        'status': status,
        'verdict': verdict,
        'metrics': metrics or [],
        'summary': summary,
    }


def _metric(label, value):
    if value is None or value == '':
        value = 'Not reported'
    return {'label': label, 'value': str(value)}


def _handle_source_response(response, source_name, source_key):
    if response.status_code in {401, 403}:
        return _source_result(
            source_name,
            source_key,
            'Error',
            summary=f'{source_name} rejected the configured API key.',
        )
    if response.status_code == 429:
        return _source_result(
            source_name,
            source_key,
            'Error',
            summary=f'{source_name} rate limit reached. Try again later.',
        )
    if response.status_code >= 400:
        return _source_result(
            source_name,
            source_key,
            'Error',
            summary=f'{source_name} lookup failed with HTTP {response.status_code}.',
        )
    return None


def _virustotal_source(client, indicator_type, value):
    api_key = _get_virustotal_api_key()
    if not api_key:
        return _source_result(
            'VirusTotal',
            'virustotal',
            'Error',
            summary='VIRUSTOTAL_API_KEY is not configured.',
        )

    response = client.get(_virustotal_url(indicator_type, value), headers={
        'x-apikey': api_key,
        'accept': 'application/json',
    })
    if response.status_code == 404:
        return _source_result(
            'VirusTotal',
            'virustotal',
            'Clean',
            'Unknown',
            [_metric('Detection Ratio', '0/0'), _metric('Reputation', None)],
            'VirusTotal does not have a report for this indicator.',
        )
    handled = _handle_source_response(response, 'VirusTotal', 'virustotal')
    if handled:
        return handled

    result = _summarize_virustotal_result(indicator_type, value, response.json())
    status = 'Found' if result['verdict'] in {'Malicious', 'Suspicious'} else 'Clean'
    stats = result['last_analysis_stats']
    metrics = [
        _metric('Detection Ratio', result['detection_ratio']),
        _metric('Reputation', result['reputation']),
        _metric('Malicious', stats.get('malicious', 0)),
        _metric('Suspicious', stats.get('suspicious', 0)),
        _metric('Categories', ', '.join(result['categories']) if result['categories'] else None),
    ]
    return _source_result('VirusTotal', 'virustotal', status, result['verdict'], metrics, result['summary'])


def _abuseipdb_verdict(score, reports):
    if score >= 75 and reports > 0:
        return 'Malicious'
    if score >= 25 or reports >= 3:
        return 'Suspicious'
    if score == 0 and reports == 0:
        return 'Clean'
    return 'Unknown'


def _abuseipdb_source(client, indicator_type, value):
    if indicator_type != 'ip_address':
        return _source_result(
            'AbuseIPDB',
            'abuseipdb',
            'Not applicable',
            summary='AbuseIPDB is used for IP address indicators only.',
        )

    api_key = _get_env_secret('ABUSEIPDB_API_KEY')
    if not api_key:
        return _source_result(
            'AbuseIPDB',
            'abuseipdb',
            'Error',
            summary='ABUSEIPDB_API_KEY is not configured.',
        )

    response = client.get(
        'https://api.abuseipdb.com/api/v2/check',
        headers={'Key': api_key, 'Accept': 'application/json'},
        params={'ipAddress': value, 'maxAgeInDays': '90'},
    )
    handled = _handle_source_response(response, 'AbuseIPDB', 'abuseipdb')
    if handled:
        return handled

    data = (response.json().get('data') or {})
    score = int(data.get('abuseConfidenceScore') or 0)
    reports = int(data.get('totalReports') or 0)
    verdict = _abuseipdb_verdict(score, reports)
    status = 'Found' if verdict in {'Malicious', 'Suspicious'} else 'Clean'
    metrics = [
        _metric('Abuse Confidence', f'{score}/100'),
        _metric('Total Reports', reports),
        _metric('Country Code', data.get('countryCode')),
        _metric('ISP', data.get('isp')),
        _metric('Usage Type', data.get('usageType')),
        _metric('Last Reported', data.get('lastReportedAt')),
    ]
    summary = (
        f'AbuseIPDB reports an abuse confidence score of {score}/100 with {reports} report(s) '
        'in the last 90 days.'
    )
    return _source_result('AbuseIPDB', 'abuseipdb', status, verdict, metrics, summary)


def _otx_indicator_path(indicator_type, value):
    if indicator_type == 'ip_address':
        version = ipaddress.ip_address(value).version
        otx_type = 'IPv6' if version == 6 else 'IPv4'
        return f'{otx_type}/{quote(value, safe="")}/general'
    if indicator_type == 'domain':
        return f'domain/{quote(value, safe="")}/general'
    if indicator_type == 'url':
        return f'url/{quote(value, safe="")}/general'
    if indicator_type == 'file_hash':
        return f'file/{quote(value, safe="")}/general'
    return None


def _otx_source(client, indicator_type, value):
    api_key = _get_env_secret('OTX_API_KEY')
    if not api_key:
        return _source_result(
            'AlienVault OTX',
            'otx',
            'Error',
            summary='OTX_API_KEY is not configured.',
        )

    path = _otx_indicator_path(indicator_type, value)
    if not path:
        return _source_result(
            'AlienVault OTX',
            'otx',
            'Not applicable',
            summary='OTX does not support this indicator type in the current lookup.',
        )

    response = client.get(
        f'https://otx.alienvault.com/api/v1/indicators/{path}',
        headers={'X-OTX-API-KEY': api_key, 'Accept': 'application/json'},
    )
    if response.status_code == 404:
        return _source_result(
            'AlienVault OTX',
            'otx',
            'Clean',
            'Unknown',
            [_metric('Pulse Count', 0)],
            'OTX does not have a general indicator record for this value.',
        )
    handled = _handle_source_response(response, 'AlienVault OTX', 'otx')
    if handled:
        return handled

    payload = response.json()
    pulse_info = payload.get('pulse_info') or {}
    pulses = pulse_info.get('pulses') or []
    pulse_count = int(pulse_info.get('count') or len(pulses) or 0)
    reputation = payload.get('reputation') or payload.get('threat_score') or payload.get('validation')
    threat_names = []
    for pulse in pulses[:5]:
        name = pulse.get('name')
        if name:
            threat_names.append(str(name))

    if pulse_count >= 5:
        verdict = 'Malicious'
    elif pulse_count > 0 or reputation:
        verdict = 'Suspicious'
    else:
        verdict = 'Clean'

    metrics = [
        _metric('Pulse Count', pulse_count),
        _metric('Reputation', reputation),
        _metric('Indicator Type', payload.get('type_title') or payload.get('type')),
        _metric('Related Threats', ', '.join(threat_names) if threat_names else None),
    ]
    status = 'Found' if verdict in {'Malicious', 'Suspicious'} else 'Clean'
    if threat_names:
        summary = f'OTX has {pulse_count} related pulse(s), including {", ".join(threat_names[:3])}.'
    elif pulse_count:
        summary = f'OTX has {pulse_count} related pulse(s) for this indicator.'
    else:
        summary = 'OTX did not return related threat pulses for this indicator.'
    return _source_result('AlienVault OTX', 'otx', status, verdict, metrics, summary)


def _metric_value(source, label):
    for item in source.get('metrics', []):
        if item.get('label') == label:
            return item.get('value')
    return None


def _parse_int(value):
    if value is None:
        return 0
    match = re.search(r'-?\d+', str(value))
    return int(match.group(0)) if match else 0


def _combined_verdict(indicator_type, sources):
    risk = 0
    reasons = []
    working_sources = [s for s in sources if s['status'] in {'Found', 'Clean'}]

    vt = next((s for s in sources if s['key'] == 'virustotal'), None)
    if vt and vt['status'] in {'Found', 'Clean'}:
        ratio = _metric_value(vt, 'Detection Ratio') or '0/0'
        bad = _parse_int(ratio.split('/')[0])
        risk = max(risk, min(80, bad * 8))
        if bad:
            reasons.append(f'VirusTotal has {bad} malicious or suspicious detection(s)')
        elif vt['verdict'] == 'Clean':
            reasons.append('VirusTotal did not report malicious detections')

    abuse = next((s for s in sources if s['key'] == 'abuseipdb'), None)
    if abuse and abuse['status'] in {'Found', 'Clean'}:
        score = _parse_int(_metric_value(abuse, 'Abuse Confidence'))
        reports = _parse_int(_metric_value(abuse, 'Total Reports'))
        risk = max(risk, score)
        if score or reports:
            reasons.append(f'AbuseIPDB shows {score}/100 confidence with {reports} report(s)')
        elif indicator_type == 'ip_address':
            reasons.append('AbuseIPDB shows no recent abuse reports')

    otx = next((s for s in sources if s['key'] == 'otx'), None)
    if otx and otx['status'] in {'Found', 'Clean'}:
        pulse_count = _parse_int(_metric_value(otx, 'Pulse Count'))
        if pulse_count >= 10:
            risk = max(risk, 85)
        elif pulse_count >= 5:
            risk = max(risk, 70)
        elif pulse_count > 0:
            risk = max(risk, 45)
        if pulse_count:
            reasons.append(f'OTX links this indicator to {pulse_count} threat pulse(s)')
        elif otx['verdict'] == 'Clean':
            reasons.append('OTX did not return related threat pulses')

    if not working_sources:
        verdict = 'Unknown'
        risk = 0
        explanation = 'No configured source returned usable threat intelligence for this lookup.'
        action = 'Configure at least one threat intelligence API key, then run the lookup again.'
    elif risk >= 85:
        verdict = 'Highly Malicious'
        explanation = ', '.join(reasons) + '. Treat this as a high-confidence threat signal.'
        action = 'Escalate immediately, search related logs, contain affected assets, and block the indicator if policy allows.'
    elif risk >= 65:
        verdict = 'Malicious'
        explanation = ', '.join(reasons) + '. Multiple signals indicate malicious activity.'
        action = 'Investigate related alerts and telemetry, scope exposure, and prepare blocking or containment.'
    elif risk >= 35:
        verdict = 'Suspicious'
        explanation = ', '.join(reasons) + '. The indicator has suspicious signals but needs local validation.'
        action = 'Correlate with proxy, DNS, endpoint, identity, and firewall logs before containment.'
    elif all(s['verdict'] == 'Clean' for s in working_sources):
        verdict = 'Clean'
        explanation = ', '.join(reasons) + '. No source returned a malicious signal.'
        action = 'No immediate containment based only on public intelligence; continue normal monitoring.'
    else:
        verdict = 'Unknown'
        explanation = ', '.join(reasons) or 'The sources returned limited or inconclusive intelligence.'
        action = 'Use internal telemetry and analyst review before making a containment decision.'

    return {
        'verdict': verdict,
        'risk_score': max(0, min(100, risk)),
        'explanation': explanation,
        'recommended_action': action,
    }


def _build_threat_intel_result(indicator):
    indicator_type, normalized = _detect_indicator(indicator)
    if not indicator_type:
        return None

    sources = []
    with httpx.Client(timeout=15.0) as client:
        source_meta = {
            _virustotal_source: ('VirusTotal', 'virustotal'),
            _abuseipdb_source: ('AbuseIPDB', 'abuseipdb'),
            _otx_source: ('AlienVault OTX', 'otx'),
        }
        for lookup in (_virustotal_source, _abuseipdb_source, _otx_source):
            try:
                sources.append(lookup(client, indicator_type, normalized))
            except httpx.TimeoutException:
                source_name, source_key = source_meta[lookup]
                sources.append(_source_result(
                    source_name,
                    source_key,
                    'Error',
                    summary=f'{source_name} request timed out.',
                ))
            except (httpx.RequestError, ValueError, KeyError):
                source_name, source_key = source_meta[lookup]
                sources.append(_source_result(
                    source_name,
                    source_key,
                    'Error',
                    summary=f'{source_name} lookup could not be completed.',
                ))

    return {
        'indicator': normalized,
        'indicator_type': indicator_type,
        'combined': _combined_verdict(indicator_type, sources),
        'sources': sources,
    }


def _email_address_threat_intel_result(email_address):
    sources = [
        _source_result('VirusTotal', 'virustotal', 'Not applicable', summary='Email address enrichment is not supported by this lookup.'),
        _source_result('AbuseIPDB', 'abuseipdb', 'Not applicable', summary='AbuseIPDB is used for IP address indicators only.'),
        _source_result('AlienVault OTX', 'otx', 'Not applicable', summary='OTX email address enrichment is not enabled in this workspace.'),
    ]
    return {
        'indicator': email_address,
        'indicator_type': 'email_address',
        'combined': _combined_verdict('email_address', sources),
        'sources': sources,
    }


def _lookup_error_threat_intel_result(indicator, indicator_type, summary):
    sources = [
        _source_result('VirusTotal', 'virustotal', 'Error', summary=summary),
        _source_result('AbuseIPDB', 'abuseipdb', 'Error', summary=summary),
        _source_result('AlienVault OTX', 'otx', 'Error', summary=summary),
    ]
    return {
        'indicator': indicator,
        'indicator_type': indicator_type,
        'combined': _combined_verdict(indicator_type, sources),
        'sources': sources,
    }


def _not_analyzed_threat_intel_result(indicator, indicator_type):
    sources = [
        _source_result('VirusTotal', 'virustotal', 'Not analyzed', summary='Lookup skipped to avoid excessive external requests from one email.'),
        _source_result('AbuseIPDB', 'abuseipdb', 'Not analyzed', summary='Lookup skipped to avoid excessive external requests from one email.'),
        _source_result('AlienVault OTX', 'otx', 'Not analyzed', summary='Lookup skipped to avoid excessive external requests from one email.'),
    ]
    return {
        'indicator': indicator,
        'indicator_type': indicator_type,
        'combined': _combined_verdict(indicator_type, sources),
        'sources': sources,
    }


def _normalize_obfuscated_url(value):
    normalized = re.sub(r'^hxxp', 'http', value, flags=re.IGNORECASE)
    normalized = normalized.replace('[.]', '.').replace('(.)', '.')
    return normalized.strip().rstrip('.,;:')


def _normalize_obfuscated_domain(value):
    return value.replace('[.]', '.').replace('(.)', '.').strip().rstrip('.,;:')


def _clean_indicator_token(value):
    return value.strip().strip('\'"<>[](){}').rstrip('.,;:')


def _add_ioc(groups, seen, indicator_type, value, subtype=None):
    cleaned = _clean_indicator_token(value)
    if not cleaned:
        return
    key_value = cleaned.lower()
    key = (indicator_type, key_value)
    if key in seen:
        return
    seen.add(key)
    groups[indicator_type].append({
        'type': indicator_type,
        'subtype': subtype or indicator_type,
        'value': cleaned,
        'lookup_value': _normalize_obfuscated_url(cleaned) if indicator_type == 'urls' else cleaned,
    })


def _extract_iocs(raw_text):
    groups = {
        'ip_addresses': [],
        'domains': [],
        'urls': [],
        'email_addresses': [],
        'hashes': [],
    }
    seen = set()
    text = raw_text or ''

    occupied_spans = []
    for match in _URL_PATTERN.finditer(text):
        value = _clean_indicator_token(match.group(0))
        normalized = _normalize_obfuscated_url(value)
        if _detect_indicator(normalized)[0] == 'url':
            _add_ioc(groups, seen, 'urls', value, 'url')
            occupied_spans.append(match.span())

    for match in _EMAIL_PATTERN.finditer(text):
        email = _clean_indicator_token(match.group(0)).lower()
        _add_ioc(groups, seen, 'email_addresses', email, 'email')
        occupied_spans.append(match.span())

    for hash_type, pattern in _HASH_EXTRACT_PATTERNS.items():
        for match in pattern.finditer(text):
            _add_ioc(groups, seen, 'hashes', match.group(0).lower(), hash_type.upper())

    for match in _IPV4_CANDIDATE_PATTERN.finditer(text):
        value = match.group(0)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        _add_ioc(groups, seen, 'ip_addresses', value, 'IPv4')

    def in_occupied_span(start, end):
        return any(start >= span_start and end <= span_end for span_start, span_end in occupied_spans)

    for match in _DOMAIN_CANDIDATE_PATTERN.finditer(text):
        start, end = match.span()
        if in_occupied_span(start, end):
            continue
        domain = _clean_indicator_token(match.group(0)).lower().rstrip('.')
        if _DOMAIN_PATTERN.match(domain):
            _add_ioc(groups, seen, 'domains', domain, 'domain')

    defanged_domain_pattern = re.compile(
        r'(?<![@\w.-])(?:[A-Za-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\)))+[A-Za-z]{2,63}(?![\w.-])'
    )
    for match in defanged_domain_pattern.finditer(text):
        start, end = match.span()
        if in_occupied_span(start, end):
            continue
        domain = _normalize_obfuscated_domain(_clean_indicator_token(match.group(0)).lower())
        if _DOMAIN_PATTERN.match(domain):
            _add_ioc(groups, seen, 'domains', domain, 'domain')

    return {
        'groups': groups,
        'total': sum(len(items) for items in groups.values()),
    }


def _summarize_investigation(enriched_results):
    analyzed = [item for item in enriched_results if item.get('combined')]
    if not analyzed:
        return 'No enriched indicators are available yet. Extract indicators and analyze them to generate an investigation summary.'

    verdict_counts = {}
    for item in analyzed:
        verdict = item['combined'].get('verdict', 'Unknown')
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    high_risk = [
        item for item in analyzed
        if item['combined'].get('verdict') in {'Highly Malicious', 'Malicious'}
    ]
    suspicious = [item for item in analyzed if item['combined'].get('verdict') == 'Suspicious']
    clean = [item for item in analyzed if item['combined'].get('verdict') == 'Clean']

    parts = [f'The submitted content contains {len(analyzed)} enriched indicator(s).']
    if high_risk:
        parts.append(f'{len(high_risk)} indicator(s) were assessed as malicious or highly malicious.')
    if suspicious:
        parts.append(f'{len(suspicious)} indicator(s) were assessed as suspicious.')
    if clean and not high_risk and not suspicious:
        parts.append('The analyzed indicators did not return malicious public threat intelligence signals.')
    if high_risk:
        parts.append('Prioritize containment review, log scoping, and blocking decisions according to policy.')
    elif suspicious:
        parts.append('Correlate these indicators with internal telemetry before containment.')
    else:
        parts.append('Continue monitoring and validate with local logs if the alert context remains concerning.')

    return ' '.join(parts)


_PHISHING_LANGUAGE_PATTERNS = [
    ('Urgency', r'\b(urgent|immediate action|act now|verify immediately|click here now|within 24 hours|final notice)\b'),
    ('Fear or Suspension Threat', r'\b(account (?:will be )?(?:disabled|suspended|locked)|service will be terminated|security alert|unusual activity)\b'),
    ('Credential Request', r'\b(verify your account|confirm your password|login to verify|validate your credentials|password expires?)\b'),
    ('Payment or Invoice Lure', r'\b(invoice|payment overdue|wire transfer|billing issue|refund pending|purchase order|remittance)\b'),
    ('Attachment or Link Call-to-Action', r'\b(open the attachment|download the file|review document|click the link|secure message)\b'),
    ('Impersonation Language', r'\b(help desk|it support|mailbox team|security team|administrator|microsoft 365 team)\b'),
]

_BRAND_PATTERNS = [
    ('Microsoft', r'\b(microsoft|office 365|m365|outlook|onedrive|sharepoint|teams|azure)\b'),
    ('Google', r'\b(google|gmail|workspace|drive)\b'),
    ('PayPal', r'\b(paypal)\b'),
    ('Banking', r'\b(bank|chase|wells fargo|citibank|bank of america|capital one)\b'),
    ('Delivery', r'\b(fedex|ups|dhl|usps|delivery notice|shipment)\b'),
    ('DocuSign', r'\b(docusign|e-signature|electronic signature)\b'),
]


def _detect_phishing_language(text):
    findings = []
    for label, pattern in _PHISHING_LANGUAGE_PATTERNS:
        matches = []
        for match in re.finditer(pattern, text, re.IGNORECASE):
            phrase = match.group(0).strip()
            if phrase.lower() not in {item.lower() for item in matches}:
                matches.append(phrase)
        if matches:
            findings.append({
                'category': label,
                'matches': matches[:6],
                'severity': 'High' if label in {'Fear or Suspension Threat', 'Credential Request'} else 'Medium',
            })
    return findings


def _detect_brand_impersonation(text):
    brands = []
    for brand, pattern in _BRAND_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            brands.append(brand)
    return brands


def _email_structure_findings(text, extracted):
    findings = []
    lowered = text.lower()
    url_count = len(extracted['groups'].get('urls', []))
    email_count = len(extracted['groups'].get('email_addresses', []))
    if url_count:
        findings.append({'label': 'External link present', 'detail': f'{url_count} URL(s) detected in the message.'})
    if email_count >= 2:
        findings.append({'label': 'Multiple email addresses', 'detail': f'{email_count} email address(es) detected in the content.'})
    if 'reply-to:' in lowered and 'from:' in lowered:
        findings.append({'label': 'Header fields present', 'detail': 'Raw header fields are present; compare From, Reply-To, and Return-Path manually.'})
    if re.search(r'<a\s+href=', text, re.IGNORECASE):
        findings.append({'label': 'HTML link markup', 'detail': 'HTML anchor tags were detected; verify displayed link text against destination URLs.'})
    return findings


def _phishing_actions(verdict, enriched_results, language_findings, brands):
    actions = []
    if verdict in {'Highly Suspicious', 'Likely Phishing'}:
        actions.extend([
            'Quarantine or remove the message from affected mailboxes.',
            'Block malicious sender, URL, domain, or IP indicators according to policy.',
            'Search mail and proxy logs for other users who received or clicked the message.',
        ])
    elif verdict == 'Suspicious':
        actions.extend([
            'Do not click links or open attachments until validation is complete.',
            'Correlate extracted indicators with email gateway, proxy, DNS, and endpoint logs.',
        ])
    else:
        actions.append('No immediate containment based only on this analysis; continue validation if the report context is concerning.')

    if any(item.get('combined', {}).get('verdict') in {'Highly Malicious', 'Malicious'} for item in enriched_results):
        actions.append('Prioritize investigation of indicators with malicious threat intelligence verdicts.')
    if any(finding['category'] == 'Credential Request' for finding in language_findings):
        actions.append('If credentials may have been submitted, reset the affected password and review sign-in logs.')
    if brands:
        actions.append('Validate the message against the claimed brand or internal service through a trusted channel.')
    return actions[:6]


def _score_phishing_analysis(language_findings, brands, extracted, enriched_results):
    score = 0
    score += min(35, len(language_findings) * 9)
    if any(item['severity'] == 'High' for item in language_findings):
        score += 12
    score += min(18, len(brands) * 6)

    groups = extracted.get('groups') or {}
    if groups.get('urls'):
        score += 12
    if groups.get('domains'):
        score += 6
    if groups.get('ip_addresses'):
        score += 5
    if groups.get('email_addresses'):
        score += 4

    for result in enriched_results:
        verdict = (result.get('combined') or {}).get('verdict')
        risk = int((result.get('combined') or {}).get('risk_score') or 0)
        if verdict == 'Highly Malicious':
            score += 30
        elif verdict == 'Malicious':
            score += 24
        elif verdict == 'Suspicious':
            score += 14
        else:
            score += min(10, risk // 10)

    score = max(0, min(100, score))
    if score >= 85:
        verdict = 'Highly Suspicious'
        severity = 'Critical'
    elif score >= 65:
        verdict = 'Likely Phishing'
        severity = 'High'
    elif score >= 35:
        verdict = 'Suspicious'
        severity = 'Medium'
    elif score > 0:
        verdict = 'Low Risk'
        severity = 'Low'
    elif extracted.get('total'):
        verdict = 'Unknown'
        severity = 'Unknown'
    else:
        verdict = 'Clean'
        severity = 'Informational'
    return score, verdict, severity


def _summarize_phishing_analysis(verdict, score, language_findings, brands, extracted, enriched_results):
    parts = [f'This message is assessed as {verdict.lower()} with a phishing probability score of {score}/100.']
    if language_findings:
        categories = ', '.join(finding['category'].lower() for finding in language_findings[:3])
        parts.append(f'Observed phishing language includes {categories}.')
    if brands:
        parts.append(f'The content references possible brand impersonation targets: {", ".join(brands[:4])}.')
    if extracted.get('total'):
        parts.append(f'{extracted["total"]} indicator(s) were extracted for investigation.')
    malicious = [
        item for item in enriched_results
        if (item.get('combined') or {}).get('verdict') in {'Highly Malicious', 'Malicious'}
    ]
    suspicious = [
        item for item in enriched_results
        if (item.get('combined') or {}).get('verdict') == 'Suspicious'
    ]
    if malicious:
        parts.append(f'{len(malicious)} enriched indicator(s) returned malicious threat intelligence.')
    elif suspicious:
        parts.append(f'{len(suspicious)} enriched indicator(s) returned suspicious threat intelligence.')
    elif enriched_results:
        parts.append('No enriched indicator returned a malicious public threat intelligence verdict.')
    return ' '.join(parts)


def _enrich_extracted_for_phishing(extracted, full_enrichment):
    if not full_enrichment:
        return []

    candidates = []
    for group_key in ('ip_addresses', 'domains', 'urls', 'hashes', 'email_addresses'):
        for item in extracted['groups'].get(group_key, []):
            value = item.get('value') or ''
            lookup_value = item.get('lookup_value') or value
            if group_key == 'email_addresses' and _EMAIL_PATTERN.fullmatch(value):
                candidates.append({
                    'indicator': value.lower(),
                    'indicator_type': 'email_address',
                    'lookup_value': value.lower(),
                    'external_lookup': False,
                })
                continue

            indicator_type, normalized = _detect_indicator(lookup_value)
            if indicator_type:
                candidates.append({
                    'indicator': normalized,
                    'indicator_type': indicator_type,
                    'lookup_value': normalized,
                    'external_lookup': True,
                })

    enriched = []
    seen = set()
    external_count = 0
    for candidate in candidates:
        indicator = candidate['indicator']
        if (candidate['indicator_type'], indicator) in seen:
            continue
        seen.add((candidate['indicator_type'], indicator))

        if not candidate['external_lookup']:
            enriched.append(_email_address_threat_intel_result(indicator))
            continue

        if external_count >= MAX_PHISHING_EXTERNAL_LOOKUPS:
            enriched.append(_not_analyzed_threat_intel_result(indicator, candidate['indicator_type']))
            continue

        external_count += 1
        cache_key = 'phishing-enrich:' + hashlib.sha256(indicator.encode()).hexdigest()
        cached = cache.get(cache_key)
        if cached:
            enriched.append(cached)
            continue
        try:
            result = _build_threat_intel_result(indicator)
        except (httpx.TimeoutException, httpx.RequestError):
            result = _lookup_error_threat_intel_result(
                indicator,
                candidate['indicator_type'],
                'Threat intelligence lookup could not be completed because an external source connection failed.',
            )
        if result:
            cache.set(cache_key, result, 600)
            enriched.append(result)
    return enriched


def _analyze_phishing_email(text, full_enrichment=True):
    extracted = _extract_iocs(text)
    language_findings = _detect_phishing_language(text)
    brands = _detect_brand_impersonation(text)
    structure_findings = _email_structure_findings(text, extracted)
    enriched = _enrich_extracted_for_phishing(extracted, full_enrichment)
    score, verdict, severity = _score_phishing_analysis(language_findings, brands, extracted, enriched)
    summary = _summarize_phishing_analysis(verdict, score, language_findings, brands, extracted, enriched)
    actions = _phishing_actions(verdict, enriched, language_findings, brands)
    return {
        'verdict': verdict,
        'severity': severity,
        'risk_score': score,
        'summary': summary,
        'recommended_actions': actions,
        'language_findings': language_findings,
        'brand_impersonation': brands,
        'structure_findings': structure_findings,
        'extracted': extracted,
        'enriched_indicators': enriched,
        'full_enrichment': full_enrichment,
    }


def _part_text(part):
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b''
        charset = part.get_content_charset() or 'utf-8'
        content = payload.decode(charset, errors='replace')

    if part.get_content_type() == 'text/html':
        content = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', content)
        content = re.sub(r'(?s)<[^>]+>', ' ', content)
        content = re.sub(r'\s+', ' ', content)
    return str(content).strip()


def _parse_eml_upload(uploaded_file):
    name = uploaded_file.name or 'uploaded-email.eml'
    lower_name = name.lower()
    if not lower_name.endswith('.eml'):
        raise ValueError('Upload a valid .eml file.')

    data = uploaded_file.read(MAX_EML_UPLOAD_BYTES + 1)
    if len(data) > MAX_EML_UPLOAD_BYTES:
        raise ValueError('The .eml file is too large. Upload a file 2 MB or smaller.')
    if not data.strip():
        raise ValueError('The uploaded .eml file is empty.')

    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        raise ValueError('Could not parse the .eml file.') from exc

    header_names = [
        'From', 'To', 'Cc', 'Bcc', 'Reply-To', 'Return-Path', 'Subject',
        'Date', 'Message-ID', 'Authentication-Results', 'Received-SPF',
        'DKIM-Signature', 'ARC-Authentication-Results',
    ]
    lines = ['Uploaded .eml file parsed server-side.', '', 'Selected Headers:']
    for header in header_names:
        values = message.get_all(header, [])
        for value in values[:5]:
            lines.append(f'{header}: {value}')

    received_headers = message.get_all('Received', [])
    if received_headers:
        lines.extend(['', 'Received Chain:'])
        for received in received_headers[:12]:
            lines.append(f'Received: {received}')

    body_parts = []
    attachments = []
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True) or b''
            if disposition == 'attachment' or filename:
                attachments.append({
                    'filename': filename or '(unnamed attachment)',
                    'content_type': content_type,
                    'size': len(payload),
                })
                continue
            if content_type in {'text/plain', 'text/html'}:
                text = _part_text(part)
                if text:
                    body_parts.append(text)
    else:
        body_text = _part_text(message)
        if body_text:
            body_parts.append(body_text)

    lines.extend(['', 'Message Body:'])
    lines.append('\n\n--- MIME PART ---\n\n'.join(body_parts)[:50000] or '(No readable text body found.)')

    if attachments:
        lines.extend(['', 'Attachments:'])
        for attachment in attachments[:20]:
            safe_filename = re.sub(r'[.@]', '_', attachment['filename'])
            lines.append(
                f"- {safe_filename} | {attachment['content_type']} | {attachment['size']} bytes"
            )

    parsed_text = '\n'.join(lines).strip()
    if not parsed_text:
        raise ValueError('No readable email content was found in the .eml file.')
    return parsed_text


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
    return render(request, 'chat/guest_home.html', {'guest_chat_limit': GUEST_CHAT_DAILY_LIMIT})


def threat_intelligence(request):
    """Standalone threat intelligence lookup page for guests and users."""
    context = {
        'guest_ti_limit': GUEST_TI_DAILY_LIMIT,
        'is_guest_preview': not request.user.is_authenticated,
    }
    if request.user.is_authenticated:
        context['conversations'] = Conversation.objects.filter(user=request.user)
    return render(request, 'threat_intel/lookup.html', context)


def ioc_extractor(request):
    """SOC investigation workspace for extracting and enriching IOCs."""
    context = {
        'is_guest_preview': not request.user.is_authenticated,
    }
    if request.user.is_authenticated:
        context['conversations'] = Conversation.objects.filter(user=request.user)
    return render(request, 'ioc_extractor/workspace.html', context)


def phishing_analyzer(request):
    """Dedicated phishing email investigation workspace."""
    context = {
        'is_guest_preview': not request.user.is_authenticated,
        'guest_phishing_limit': GUEST_PHISHING_DAILY_LIMIT,
    }
    if request.user.is_authenticated:
        context['conversations'] = Conversation.objects.filter(user=request.user)
    return render(request, 'phishing_analyzer/workspace.html', context)


@require_POST
def phishing_analyze(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    email_text = str(data.get('email', ''))
    if not email_text.strip():
        return JsonResponse({'error': 'Paste suspicious email content or headers first.'}, status=400)
    if len(email_text) > 75000:
        return JsonResponse({'error': 'Input is too large. Paste 75,000 characters or fewer.'}, status=400)

    allowed, remaining, limit = _consume_guest_limit(request, 'guest_phishing_usage', GUEST_PHISHING_DAILY_LIMIT)
    if not allowed:
        return JsonResponse({
            'error': GUEST_LIMIT_MESSAGE,
            'guest_limit_reached': True,
            'limit': limit,
            'remaining': remaining,
        }, status=429)

    result = _analyze_phishing_email(email_text, full_enrichment=request.user.is_authenticated)
    return JsonResponse({
        'result': result,
        'guest_usage': None if request.user.is_authenticated else {
            'limit': limit,
            'remaining': remaining,
        },
    })


@login_required
@require_POST
def phishing_upload_eml(request):
    uploaded_file = request.FILES.get('eml_file')
    if not uploaded_file:
        return JsonResponse({'error': 'Upload a .eml file first.'}, status=400)

    try:
        email_text = _parse_eml_upload(uploaded_file)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    if len(email_text) > 75000:
        email_text = email_text[:75000]

    result = _analyze_phishing_email(email_text, full_enrichment=True)
    return JsonResponse({
        'filename': uploaded_file.name,
        'email_text': email_text,
        'result': result,
    })


@require_POST
def ioc_extract(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    raw_text = str(data.get('text', ''))
    if not raw_text.strip():
        return JsonResponse({'error': 'Paste alert, log, email, or investigation text first.'}, status=400)
    if len(raw_text) > 75000:
        return JsonResponse({'error': 'Input is too large. Paste 75,000 characters or fewer.'}, status=400)

    return JsonResponse({'result': _extract_iocs(raw_text)})


@require_POST
def ioc_enrich(request):
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': LOGIN_REQUIRED_SOC_MESSAGE,
            'login_required': True,
        }, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    indicator = str(data.get('indicator', '')).strip()
    lookup_value = str(data.get('lookup_value', indicator)).strip()
    if not lookup_value:
        return JsonResponse({'error': 'Indicator is required.'}, status=400)

    indicator_type, normalized = _detect_indicator(lookup_value)
    if not indicator_type and _EMAIL_PATTERN.fullmatch(indicator):
        sources = [
            _source_result('VirusTotal', 'virustotal', 'Not applicable', summary='Email address enrichment is not supported by this lookup.'),
            _source_result('AbuseIPDB', 'abuseipdb', 'Not applicable', summary='AbuseIPDB is used for IP address indicators only.'),
            _source_result('AlienVault OTX', 'otx', 'Not applicable', summary='OTX email address enrichment is not enabled in this workspace.'),
        ]
        return JsonResponse({
            'result': {
                'indicator': indicator,
                'indicator_type': 'email_address',
                'combined': _combined_verdict('email_address', sources),
                'sources': sources,
            }
        })

    if not indicator_type:
        return JsonResponse({'error': 'Unsupported or invalid indicator.'}, status=400)

    cache_key = 'ioc-enrich:' + hashlib.sha256(normalized.encode()).hexdigest()
    cached = cache.get(cache_key)
    if cached:
        cached['cached'] = True
        return JsonResponse({'result': cached})

    try:
        result = _build_threat_intel_result(normalized)
    except httpx.TimeoutException:
        return JsonResponse({'error': 'Threat intelligence lookup timed out.'}, status=504)
    except httpx.RequestError:
        return JsonResponse({'error': 'Could not connect to threat intelligence sources.'}, status=503)

    cache.set(cache_key, result, 600)
    return JsonResponse({'result': result})


@require_POST
def ioc_summary(request):
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': LOGIN_REQUIRED_SOC_MESSAGE,
            'login_required': True,
        }, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    enriched = data.get('results') or []
    if not isinstance(enriched, list):
        return JsonResponse({'error': 'Invalid enrichment result format.'}, status=400)

    return JsonResponse({'summary': _summarize_investigation(enriched)})


@require_POST
def threat_intelligence_lookup(request):
    """Server-side multi-source threat intelligence lookup. API keys never reach the browser."""
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

    allowed, remaining, limit = _consume_guest_limit(request, 'guest_ti_lookup_usage', GUEST_TI_DAILY_LIMIT)
    if not allowed:
        return JsonResponse({
            'error': GUEST_LIMIT_MESSAGE,
            'guest_limit_reached': True,
            'limit': limit,
            'remaining': remaining,
        }, status=429)

    try:
        result = _build_threat_intel_result(normalized)
    except httpx.TimeoutException:
        return JsonResponse({'error': 'Threat intelligence lookup timed out.'}, status=504)
    except httpx.RequestError:
        return JsonResponse({'error': 'Could not connect to threat intelligence sources.'}, status=503)

    return JsonResponse({
        'result': result,
        'guest_usage': None if request.user.is_authenticated else {
            'limit': limit,
            'remaining': remaining,
        },
    })


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

        allowed, remaining, limit = _consume_guest_limit(request, 'guest_chat_usage', GUEST_CHAT_DAILY_LIMIT)
        if not allowed:
            return JsonResponse({
                'error': GUEST_LIMIT_MESSAGE,
                'rate_limited': True,
                'guest_limit_reached': True,
                'limit': limit,
                'remaining': remaining,
            }, status=429)

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
        return JsonResponse({
            'response': assistant_text,
            'error': None,
            'guest_usage': {
                'limit': limit,
                'remaining': remaining,
            },
        })

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
