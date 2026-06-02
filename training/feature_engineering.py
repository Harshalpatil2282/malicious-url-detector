"""
feature_engineering.py
======================
Extract 40+ lexical features from raw URL strings for ML-based phishing/malicious URL detection.
All features are derived from the URL string alone — no network calls.
Covers: length/count stats, structural indicators, obfuscation signals, entropy, punycode, etc.

IMPORTANT: Keep in perfect sync with api/feature_extractor.py
"""

import re
import math
from urllib.parse import urlparse, parse_qs, unquote


# ─── Keyword lists ────────────────────────────────────────────────────────────

SENSITIVE_WORDS = [
    'secure', 'account', 'update', 'login', 'banking', 'confirm',
    'verify', 'paypal', 'signin', 'password', 'webscr', 'ebay',
    'apple', 'amazon', 'microsoft', 'google', 'netflix', 'instagram',
    'wallet', 'reset', 'suspend', 'urgent', 'click', 'free', 'prize',
    'billing', 'support', 'helpdesk', 'admin',
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.link', '.work', '.bid', '.win', '.loan', '.online', '.site',
    '.club', '.pw', '.cc', '.co', '.info',
]

SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl', 'ow.ly', 't.co', 'goo.gl', 'is.gd',
    'cli.gs', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'tr.im',
    'twit.ac', 'su.pr', 'buff.ly', 'adf.ly', 'j.mp', 'qr.net',
    'cutt.ly', 'rb.gy', 'lnk.to', 'shorturl.at',
]

# Regex to detect IP address in netloc
IP_RE = re.compile(
    r'^(?:\d{1,3}\.){3}\d{1,3}$'   # IPv4
    r'|'
    r'^\[?[0-9a-fA-F:]+\]?$'       # IPv6
)


# ─── Helper: Shannon entropy ───────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ─── Main extractor ────────────────────────────────────────────────────────────

def extract_url_features(url: str) -> dict:
    """
    Extract 40+ lexical features from a raw URL string.

    Returns a dict of numeric features.  Returns all-zeros on empty/invalid input.
    """
    feats = {
        # ── Length / counts ──────────────────────────────────────────────
        'url_length':           0,
        'n_dots':               0,
        'n_hyphens':            0,
        'n_at':                 0,
        'n_question_marks':     0,
        'n_equals':             0,
        'n_slash':              0,
        'n_percent':            0,
        'n_digits':             0,
        'n_ampersands':         0,
        'n_underscores':        0,
        'n_tilde':              0,
        'n_comma':              0,
        'n_semicolon':          0,

        # ── Structural ───────────────────────────────────────────────────
        'n_subdomains':         0,
        'url_depth':            0,
        'n_params':             0,
        'domain_length':        0,
        'path_length':          0,
        'query_length':         0,
        'fragment_length':      0,
        'tld_length':           0,

        # ── Ratios ───────────────────────────────────────────────────────
        'ratio_digits':         0.0,
        'ratio_alpha':          0.0,
        'ratio_special':        0.0,

        # ── Entropy ──────────────────────────────────────────────────────
        'url_entropy':          0.0,
        'domain_entropy':       0.0,
        'path_entropy':         0.0,

        # ── Domain properties ────────────────────────────────────────────
        'has_ip_address':       0,
        'has_port':             0,
        'has_prefix_suffix':    0,   # hyphen in domain
        'domain_has_digits':    0,
        'is_punycode':          0,   # xn-- IDN homograph

        # ── URL behaviour flags ──────────────────────────────────────────
        'uses_https':           0,
        'has_at_symbol':        0,
        'has_double_slash':     0,
        'n_external_redirects': 0,   # http(s):// appearing again in path/query
        'shortening_service':   0,

        # ── Content-based ────────────────────────────────────────────────
        'n_sensitive_words':    0,
        'has_suspicious_tld':   0,

        # ── Path token analysis ──────────────────────────────────────────
        'longest_token_length': 0,
        'avg_token_length':     0.0,
    }

    if not url or not isinstance(url, str):
        return feats

    try:
        parsed    = urlparse(url)
        netloc    = parsed.netloc  or ''
        path      = parsed.path    or ''
        query     = parsed.query   or ''
        fragment  = parsed.fragment or ''
        url_lower = url.lower()
        netloc_lower = netloc.lower()
    except Exception:
        return feats

    url_len = len(url)
    feats['url_length']       = url_len
    feats['n_dots']           = url.count('.')
    feats['n_hyphens']        = url.count('-')
    feats['n_at']             = url.count('@')
    feats['n_question_marks'] = url.count('?')
    feats['n_equals']         = url.count('=')
    feats['n_slash']          = url.count('/')
    feats['n_percent']        = url.count('%')
    feats['n_ampersands']     = url.count('&')
    feats['n_underscores']    = url.count('_')
    feats['n_tilde']          = url.count('~')
    feats['n_comma']          = url.count(',')
    feats['n_semicolon']      = url.count(';')

    n_digits = sum(c.isdigit() for c in url)
    n_alpha  = sum(c.isalpha() for c in url)
    n_special = url_len - n_digits - n_alpha
    feats['n_digits']     = n_digits
    feats['ratio_digits'] = n_digits  / max(url_len, 1)
    feats['ratio_alpha']  = n_alpha   / max(url_len, 1)
    feats['ratio_special']= n_special / max(url_len, 1)

    # ── Domain / subdomain ───────────────────────────────────────────────────
    netloc_parts = netloc.split('.')
    feats['n_subdomains'] = max(len(netloc_parts) - 2, 0)
    tld = '.' + netloc_parts[-1] if netloc_parts else ''
    feats['tld_length']   = len(tld)

    # strip port for IP / digit checks
    netloc_no_port = netloc.split(':')[0] if ':' in netloc else netloc
    feats['has_ip_address']   = 1 if IP_RE.match(netloc_no_port) else 0
    feats['domain_has_digits']= 1 if any(c.isdigit() for c in netloc_no_port) else 0
    feats['is_punycode']      = 1 if 'xn--' in netloc_lower else 0
    feats['has_prefix_suffix']= 1 if '-' in netloc_no_port else 0

    if ':' in netloc:
        port_part = netloc.split(':')[-1]
        try:
            if int(port_part) not in (80, 443):
                feats['has_port'] = 1
        except ValueError:
            pass

    feats['domain_length'] = len(netloc)
    feats['domain_entropy'] = _entropy(netloc_lower)

    # ── Path ─────────────────────────────────────────────────────────────────
    path_parts = [p for p in path.split('/') if p]
    feats['url_depth']    = len(path_parts)
    feats['path_length']  = len(path)
    feats['path_entropy'] = _entropy(path)

    if path_parts:
        token_lens = [len(t) for t in path_parts]
        feats['longest_token_length'] = max(token_lens)
        feats['avg_token_length']     = sum(token_lens) / len(token_lens)

    # ── Query ──────────────────────────────────────────────────────────────
    feats['query_length'] = len(query)
    try:
        feats['n_params'] = len(parse_qs(query, keep_blank_values=True))
    except Exception:
        feats['n_params'] = query.count('=')

    # ── Fragment ──────────────────────────────────────────────────────────
    feats['fragment_length'] = len(fragment)

    # ── Entropy of full URL ───────────────────────────────────────────────
    feats['url_entropy'] = _entropy(url_lower)

    # ── Protocol / scheme flags ───────────────────────────────────────────
    feats['uses_https']      = 1 if url_lower.startswith('https') else 0
    feats['has_at_symbol']   = 1 if '@' in url else 0
    feats['has_double_slash']= 1 if '//' in url[7:] else 0

    # Embedded redirects: count http(s):// occurrences beyond the first
    redirect_count = url_lower.count('http://') + url_lower.count('https://') - 1
    feats['n_external_redirects'] = max(redirect_count, 0)

    # ── Content-based ────────────────────────────────────────────────────
    feats['n_sensitive_words'] = sum(1 for w in SENSITIVE_WORDS if w in url_lower)

    for tld_s in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld_s) or (tld_s + '/') in url_lower or (tld_s + '?') in url_lower:
            feats['has_suspicious_tld'] = 1
            break

    for svc in SHORTENING_SERVICES:
        if svc in netloc_lower:
            feats['shortening_service'] = 1
            break

    return feats


def get_feature_names() -> list:
    """Return the ordered list of feature names produced by extract_url_features."""
    return list(extract_url_features('http://dummy.com').keys())


if __name__ == '__main__':
    test_urls = [
        'https://www.google.com',
        'http://paypal-secure-login.tk/verify?user=admin&id=12345&session=abc',
        'http://192.168.1.1:8080/admin/panel',
        'https://bit.ly/3xY2z',
        'http://xn--pypal-4ve.com/account/login',
        'https://very-long-suspicious-domain-with-many-hyphens.co/login/account/update?token=abc123def456ghi789jkl&verify=true&redirect=http://evil.tk',
        '',
    ]
    names = get_feature_names()
    print(f"Total features: {len(names)}")
    for u in test_urls:
        f = extract_url_features(u)
        print(f"\nURL: {u[:80]}")
        print(f"  entropy={f['url_entropy']:.2f}  len={f['url_length']}  "
              f"params={f['n_params']}  sensitive={f['n_sensitive_words']}  "
              f"punycode={f['is_punycode']}  https={f['uses_https']}")
