from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_WORDS = {
    'login', 'verify', 'verification', 'account', 'secure', 'update',
    'password', 'signin', 'banking', 'wallet', 'confirm', 'reset', 'free-gift'
}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'ow.ly', 'shorturl.at'}


def analyze_url(raw_url: str) -> dict:
    url = raw_url.strip()
    candidate = url if '://' in url else 'http://' + url
    parsed = urlparse(candidate)
    host = (parsed.hostname or '').lower().strip('.')
    path_and_query = (parsed.path + ' ' + parsed.query).lower()
    full_lower = candidate.lower()

    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0

    words_found = sorted(word for word in SUSPICIOUS_WORDS if word in full_lower)
    has_suspicious_word = int(bool(words_found))
    uses_https = int(parsed.scheme.lower() == 'https')
    hyphen_count = host.count('-')
    at_count = url.count('@')
    digit_count = sum(ch.isdigit() for ch in host)
    dot_count = host.count('.')
    labels = [part for part in host.split('.') if part]
    subdomain_count = max(0, len(labels) - 2)
    path_depth = len([part for part in parsed.path.split('/') if part])
    query_count = len([part for part in parsed.query.split('&') if part])
    has_shortener = int(host in SHORTENERS)
    has_double_slash = int('//' in parsed.path)

    score = 0
    reasons = []
    if not uses_https:
        score += 15
        reasons.append('The URL does not use HTTPS.')
    if has_ip:
        score += 25
        reasons.append('The hostname is an IP address rather than a typical domain name.')
    if has_suspicious_word:
        score += min(25, 10 + 3 * max(0, len(words_found) - 1))
        reasons.append('Potentially sensitive words found: ' + ', '.join(words_found) + '.')
    if hyphen_count >= 2:
        score += 10
        reasons.append('The hostname contains multiple hyphens.')
    if subdomain_count >= 3:
        score += 10
        reasons.append('The URL has several subdomain levels.')
    if at_count:
        score += 20
        reasons.append('The URL contains an @ symbol, which can obscure the intended destination.')
    if has_shortener:
        score += 15
        reasons.append('The domain is a known URL-shortening service, so the final destination is not visible here.')
    if len(url) > 100:
        score += 5
        reasons.append('The URL is unusually long.')
    if not reasons:
        reasons.append('No obvious warning signal was found in the selected URL features.')
    score = min(100, score)
    label = 'danger' if score >= 40 else 'safe'
    verdict = 'Potentially Malicious' if label == 'danger' else 'Likely Legitimate'
    reasons.insert(0, 'Rule-based prototype assessment; this is not a verified reputation check.')

    features = {
        'url_length': len(url),
        'uses_https': uses_https,
        'has_ip_address': has_ip,
        'has_suspicious_word': has_suspicious_word,
        'suspicious_words_found': ', '.join(words_found) if words_found else 'None',
        'hyphen_count': hyphen_count,
        'at_count': at_count,
        'digit_count': digit_count,
        'dot_count': dot_count,
        'subdomain_count': subdomain_count,
        'path_depth': path_depth,
        'query_count': query_count,
        'has_url_shortener': has_shortener,
        'has_double_slash_in_path': has_double_slash,
    }
    return {
        'url': url,
        'label': label,
        'verdict': verdict,
        'risk_score': score,
        'reasons': reasons,
        'features': features,
        'disclaimer': 'Educational prototype. The risk score is an estimate, not a verified security rating. False positives and false negatives are possible.'
    }
