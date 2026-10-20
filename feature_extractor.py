"""
PhishGuard - Lexical Feature Extractor
======================================
Extracts 13 lexical and structural security features directly from a URL string
without making any network requests (100% offline, safe, and sub-millisecond).
"""

import re
import ipaddress
import urllib.parse
from typing import Dict, Any, List

# Common URL shortener domains used by attackers to mask destinations
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'rb.gy', 'cutt.ly', 'tiny.cc', 'shorturl.at', 'qr.net'
}

# High-risk keywords commonly found in phishing campaigns
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'verification', 'secure', 'security', 'account',
    'update', 'banking', 'signin', 'confirm', 'password', 'credential',
    'wallet', 'authenticate', 'billing', 'support', 'service', 'paypal'
]

# Feature names in the exact order expected by the machine learning model
FEATURE_NAMES = [
    'url_length',
    'hostname_length',
    'count_dots',
    'count_hyphens',
    'count_digits',
    'count_special_chars',
    'has_at_symbol',
    'has_ip_address',
    'is_https',
    'count_subdomains',
    'suspicious_keyword_count',
    'is_shortened',
    'has_double_slash_path'
]


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts raw numerical and binary features from a URL string.
    Returns a dictionary mapping feature names to numerical values.
    """
    url_str = str(url).strip()
    
    # Prepend scheme if missing so urllib parses hostname and path reliably
    parsed_target = url_str if url_str.startswith(('http://', 'https://')) else 'http://' + url_str
    try:
        parsed = urllib.parse.urlparse(parsed_target)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
    except Exception:
        hostname = ''
        path = ''

    # 1. Length features
    url_length = len(url_str)
    hostname_length = len(hostname)

    # 2. Character counts
    count_dots = url_str.count('.')
    count_hyphens = url_str.count('-')
    count_digits = sum(c.isdigit() for c in url_str)
    count_special_chars = len(re.findall(r'[@_?=&%#+]', url_str))

    # 3. Security-relevant flags
    has_at_symbol = 1 if '@' in url_str else 0

    # Raw IP address in domain (e.g. http://192.168.1.1/login)
    has_ip = 0
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            has_ip = 1
        except ValueError:
            # Check for standard IPv4 pattern with regex
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
                has_ip = 1

    # HTTPS check
    is_https = 1 if url_str.lower().startswith('https://') else 0

    # Subdomain count: number of dot segments in hostname minus top-level domain and main domain
    if hostname:
        parts = hostname.split('.')
        count_subdomains = max(0, len(parts) - 2)
    else:
        count_subdomains = 0

    # Suspicious keywords count
    lower_url = url_str.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)

    # Shortener detection
    is_shortened = 1 if any(shortener in hostname.lower() for shortener in SHORTENERS) else 0

    # Double slash in path (redirection trick)
    has_double_slash_path = 1 if '//' in path else 0

    return {
        'url_length': url_length,
        'hostname_length': hostname_length,
        'count_dots': count_dots,
        'count_hyphens': count_hyphens,
        'count_digits': count_digits,
        'count_special_chars': count_special_chars,
        'has_at_symbol': has_at_symbol,
        'has_ip_address': has_ip,
        'is_https': is_https,
        'count_subdomains': count_subdomains,
        'suspicious_keyword_count': suspicious_keyword_count,
        'is_shortened': is_shortened,
        'has_double_slash_path': has_double_slash_path
    }


def explain_features(url: str, features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Transforms raw features into human-readable explanations with risk flags.
    Used by the web UI for the 'Why this result?' feature breakdown.
    """
    breakdown = []

    # 1. IP Address
    if features['has_ip_address'] == 1:
        breakdown.append({
            'name': 'Raw IP in Hostname',
            'value': 'Yes',
            'is_flagged': True,
            'risk_level': 'danger',
            'reason': 'Attackers use raw IP addresses (e.g., http://192.168.1.1) to avoid DNS registration records and blacklist filters.'
        })
    else:
        breakdown.append({
            'name': 'Domain Type',
            'value': 'Registered Domain Name',
            'is_flagged': False,
            'risk_level': 'safe',
            'reason': 'Uses a standard alphanumeric domain name instead of a raw IP address.'
        })

    # 2. HTTPS Protocol
    if features['is_https'] == 1:
        breakdown.append({
            'name': 'HTTPS Protocol',
            'value': 'Enabled',
            'is_flagged': False,
            'risk_level': 'safe',
            'reason': 'Uses SSL/TLS encryption. (Note: some modern phishing sites also obtain free certificates).'
        })
    else:
        breakdown.append({
            'name': 'HTTPS Protocol',
            'value': 'Missing (HTTP)',
            'is_flagged': True,
            'risk_level': 'warning',
            'reason': 'Transmits traffic unencrypted over HTTP, a common trait of quick phishing pages.'
        })

    # 3. URL Length
    url_len = features['url_length']
    if url_len > 75:
        breakdown.append({
            'name': 'URL Length',
            'value': f'{url_len} chars',
            'is_flagged': True,
            'risk_level': 'warning',
            'reason': f'Abnormally long URL ({url_len} characters). Phishers frequently pad URLs with redundant tokens to hide the true destination.'
        })
    else:
        breakdown.append({
            'name': 'URL Length',
            'value': f'{url_len} chars',
            'is_flagged': False,
            'risk_level': 'safe',
            'reason': 'Standard URL length within normal browsing parameters.'
        })

    # 4. Subdomains
    sub_count = features['count_subdomains']
    if sub_count >= 3:
        breakdown.append({
            'name': 'Subdomain Depth',
            'value': f'{sub_count} subdomains',
            'is_flagged': True,
            'risk_level': 'danger',
            'reason': f'Excessive subdomains ({sub_count}). Phishers create nested subdomains (e.g. paypal.com.login.verify.xyz) to spoof reputable brands.'
        })
    else:
        breakdown.append({
            'name': 'Subdomain Depth',
            'value': f'{sub_count} subdomains',
            'is_flagged': False,
            'risk_level': 'safe',
            'reason': 'Normal domain hierarchy depth.'
        })

    # 5. Suspicious Keywords
    kw_count = features['suspicious_keyword_count']
    if kw_count > 0:
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
        breakdown.append({
            'name': 'Suspicious Keywords',
            'value': f"{kw_count} found ({', '.join(found_keywords[:3])})",
            'is_flagged': True,
            'risk_level': 'danger' if kw_count >= 2 else 'warning',
            'reason': 'Contains high-urgency keywords frequently used in credential harvesting and bank spoofing scams.'
        })
    else:
        breakdown.append({
            'name': 'Suspicious Keywords',
            'value': 'None found',
            'is_flagged': False,
            'risk_level': 'safe',
            'reason': 'No high-risk credential-theft or urgent action keywords detected.'
        })

    # 6. '@' Symbol
    if features['has_at_symbol'] == 1:
        breakdown.append({
            'name': '@ Character in URL',
            'value': 'Present',
            'is_flagged': True,
            'risk_level': 'danger',
            'reason': "The '@' character instructs browsers to ignore everything preceding it as authentication credentials and navigate to the domain after the symbol."
        })

    # 7. URL Shortener
    if features['is_shortened'] == 1:
        breakdown.append({
            'name': 'URL Shortener Service',
            'value': 'Detected',
            'is_flagged': True,
            'risk_level': 'warning',
            'reason': 'Uses a public link shortener (e.g. bit.ly, tinyurl) which conceals the destination host.'
        })

    # 8. Double Slash in Path
    if features['has_double_slash_path'] == 1:
        breakdown.append({
            'name': 'Double Slash in Path',
            'value': 'Present (//)',
            'is_flagged': True,
            'risk_level': 'danger',
            'reason': 'A double slash in the path component often triggers an open redirect to an external malicious server.'
        })

    # 9. Special Characters & Dots
    dots = features['count_dots']
    specials = features['count_special_chars']
    if dots > 4 or specials > 5:
        breakdown.append({
            'name': 'Character Density',
            'value': f"{dots} dots, {specials} special chars",
            'is_flagged': True,
            'risk_level': 'warning',
            'reason': 'High density of dots and parameter delimiters commonly seen in obfuscated attack links.'
        })
    else:
        breakdown.append({
            'name': 'Character Density',
            'value': f"{dots} dots, {specials} special chars",
            'is_flagged': False,
            'risk_level': 'safe',
            'reason': 'Normal character distribution.'
        })

    return breakdown
