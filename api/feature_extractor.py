"""
feature_extractor.py  (API inference)
======================================
Feature extraction for the Flask API pipeline.
Uses the EXACT SAME 44-feature logic as training/feature_engineering.py
to guarantee training-inference consistency.

IMPORTANT: Keep in perfect sync with training/feature_engineering.py
"""

import os
import re
import math
import json
import numpy as np
from urllib.parse import urlparse, parse_qs


# ─── Load feature column order from training ──────────────────────────────────
_SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
_COLUMNS_PATH = os.path.join(_SCRIPT_DIR, 'feature_columns.json')

if os.path.exists(_COLUMNS_PATH):
    with open(_COLUMNS_PATH, 'r') as _f:
        FEATURE_COLUMNS = json.load(_f)
    print(f"  📋 Loaded {len(FEATURE_COLUMNS)} feature columns from feature_columns.json")
else:
    FEATURE_COLUMNS = []   # filled after first call to _extract_url_features()
    print("  ⚠ feature_columns.json not found — will use default order from extractor")


# ─── Keyword lists (must match training/feature_engineering.py exactly) ───────

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

IP_RE = re.compile(
    r'^(?:\d{1,3}\.){3}\d{1,3}$'
    r'|'
    r'^\[?[0-9a-fA-F:]+\]?$'
)


# ─── Shannon entropy ──────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ─── Feature extraction ───────────────────────────────────────────────────────

def _extract_url_features(url: str) -> dict:
    """
    Extract 44 lexical features from a URL string.
    Identical logic to training/feature_engineering.py → extract_url_features().
    """
    feats = {
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
        'n_subdomains':         0,
        'url_depth':            0,
        'n_params':             0,
        'domain_length':        0,
        'path_length':          0,
        'query_length':         0,
        'fragment_length':      0,
        'tld_length':           0,
        'ratio_digits':         0.0,
        'ratio_alpha':          0.0,
        'ratio_special':        0.0,
        'url_entropy':          0.0,
        'domain_entropy':       0.0,
        'path_entropy':         0.0,
        'has_ip_address':       0,
        'has_port':             0,
        'has_prefix_suffix':    0,
        'domain_has_digits':    0,
        'is_punycode':          0,
        'uses_https':           0,
        'has_at_symbol':        0,
        'has_double_slash':     0,
        'n_external_redirects': 0,
        'shortening_service':   0,
        'n_sensitive_words':    0,
        'has_suspicious_tld':   0,
        'longest_token_length': 0,
        'avg_token_length':     0.0,
    }

    if not url or not isinstance(url, str):
        return feats

    try:
        parsed   = urlparse(url)
        netloc   = parsed.netloc   or ''
        path     = parsed.path     or ''
        query    = parsed.query    or ''
        fragment = parsed.fragment or ''
        url_lower    = url.lower()
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

    n_digits  = sum(c.isdigit() for c in url)
    n_alpha   = sum(c.isalpha() for c in url)
    n_special = url_len - n_digits - n_alpha
    feats['n_digits']      = n_digits
    feats['ratio_digits']  = n_digits  / max(url_len, 1)
    feats['ratio_alpha']   = n_alpha   / max(url_len, 1)
    feats['ratio_special'] = n_special / max(url_len, 1)

    netloc_parts = netloc.split('.')
    feats['n_subdomains']  = max(len(netloc_parts) - 2, 0)
    tld = '.' + netloc_parts[-1] if netloc_parts else ''
    feats['tld_length']    = len(tld)

    netloc_no_port = netloc.split(':')[0] if ':' in netloc else netloc
    feats['has_ip_address']    = 1 if IP_RE.match(netloc_no_port) else 0
    feats['domain_has_digits'] = 1 if any(c.isdigit() for c in netloc_no_port) else 0
    feats['is_punycode']       = 1 if 'xn--' in netloc_lower else 0
    feats['has_prefix_suffix'] = 1 if '-' in netloc_no_port else 0

    if ':' in netloc:
        port_part = netloc.split(':')[-1]
        try:
            if int(port_part) not in (80, 443):
                feats['has_port'] = 1
        except ValueError:
            pass

    feats['domain_length']  = len(netloc)
    feats['domain_entropy'] = _entropy(netloc_lower)

    path_parts = [p for p in path.split('/') if p]
    feats['url_depth']   = len(path_parts)
    feats['path_length'] = len(path)
    feats['path_entropy']= _entropy(path)

    if path_parts:
        token_lens = [len(t) for t in path_parts]
        feats['longest_token_length'] = max(token_lens)
        feats['avg_token_length']     = sum(token_lens) / len(token_lens)

    feats['query_length']    = len(query)
    feats['fragment_length'] = len(fragment)
    try:
        feats['n_params'] = len(parse_qs(query, keep_blank_values=True))
    except Exception:
        feats['n_params'] = query.count('=')

    feats['url_entropy']  = _entropy(url_lower)
    feats['uses_https']   = 1 if url_lower.startswith('https') else 0
    feats['has_at_symbol']= 1 if '@' in url else 0
    feats['has_double_slash'] = 1 if '//' in url[7:] else 0

    redirect_count = url_lower.count('http://') + url_lower.count('https://') - 1
    feats['n_external_redirects'] = max(redirect_count, 0)

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


def extract_features(url: str) -> np.ndarray:
    """
    Extract features from a URL and return as numpy array
    in the EXACT ORDER matching the trained model.

    Returns
    -------
    np.ndarray  shape (1, n_features)
    """
    feat_dict = _extract_url_features(url)

    if FEATURE_COLUMNS:
        values = [feat_dict.get(col, 0) for col in FEATURE_COLUMNS]
    else:
        values = list(feat_dict.values())

    return np.array(values, dtype=np.float64).reshape(1, -1)


def get_feature_names() -> list:
    """Return the ordered list of feature column names."""
    if FEATURE_COLUMNS:
        return FEATURE_COLUMNS.copy()
    return list(_extract_url_features('http://dummy.com').keys())


if __name__ == '__main__':
    test_urls = [
        'https://www.google.com',
        'http://paypal-account-verify.tk/login?user=admin',
        'http://192.168.1.1:8080/admin',
        'http://xn--pypal-4ve.com/signin',
    ]
    for u in test_urls:
        arr = extract_features(u)
        print(f"\nURL: {u}")
        print(f"  Shape: {arr.shape}  entropy={arr[0][25]:.2f}")
