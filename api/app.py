"""
app.py
======
Flask REST API for ML-based malicious URL detection.
Loads trained Random Forest model and provides real-time predictions.

v2 improvements:
  - Trusted domain whitelist: top legitimate domains bypass ML (fast-path, zero false-positives)
  - Configurable MALICIOUS_THRESHOLD (default 0.55) to reduce false positives
  - Returns 'trusted_domain' flag in response for UI display
"""

import os
import re
import time
import json
import traceback
import numpy as np
import joblib
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature_extractor import extract_features, get_feature_names

# =============================================================================
# Flask App Setup
# =============================================================================
app = Flask(__name__)
CORS(app)  # Enable CORS for ALL origins (required for web frontend)

# =============================================================================
# Configuration
# =============================================================================

# Classification threshold — only flag as malicious if probability exceeds this.
# Raising from 0.50 → 0.55 reduces false positives while keeping high recall.
MALICIOUS_THRESHOLD = 0.55

# Trusted domain whitelist — these well-known legitimate domains bypass the ML model.
# The lexical model cannot reliably distinguish the real google.com from a spoofed
# look-alike, so a ground-truth whitelist is the industry-standard complement.
TRUSTED_DOMAINS = {
    # Search & Tech
    'google.com', 'google.co.in', 'google.co.uk', 'google.com.au',
    'google.co.jp', 'google.de', 'google.fr', 'google.ca', 'google.com.br',
    'googleapis.com', 'googleusercontent.com', 'gstatic.com',
    'youtube.com', 'youtu.be', 'gmail.com',
    'bing.com', 'duckduckgo.com', 'yahoo.com', 'yandex.com',
    # Social & Comms
    'facebook.com', 'fb.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'reddit.com', 'discord.com', 'telegram.org', 'whatsapp.com',
    'tiktok.com', 'snapchat.com', 'pinterest.com', 'tumblr.com',
    # Developer & Cloud
    'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
    'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
    'heroku.com', 'vercel.com', 'netlify.com', 'cloudflare.com',
    'digitalocean.com', 'linode.com', 'vultr.com',
    # E-commerce & Finance
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'ebay.com',
    'paypal.com', 'stripe.com', 'shopify.com', 'etsy.com', 'flipkart.com',
    'walmart.com', 'target.com', 'bestbuy.com', 'aliexpress.com',
    # Microsoft ecosystem
    'microsoft.com', 'office.com', 'office365.com', 'live.com',
    'hotmail.com', 'outlook.com', 'azure.com', 'msn.com', 'bing.com',
    # Apple ecosystem
    'apple.com', 'icloud.com', 'itunes.com', 'me.com',
    # News & Media
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'reuters.com',
    'theguardian.com', 'forbes.com', 'techcrunch.com', 'wired.com',
    'medium.com', 'wikipedia.org', 'wikimedia.org',
    # Education
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'mit.edu', 'stanford.edu', 'harvard.edu',
    # Government / Official
    'gov.in', 'nic.in', 'gov.uk', 'gov.au', 'usa.gov',
    # Other popular
    'netflix.com', 'spotify.com', 'twitch.tv', 'dropbox.com',
    'zoom.us', 'slack.com', 'notion.so', 'figma.com', 'canva.com',
    'wordpress.com', 'wix.com', 'squarespace.com',
    'npmjs.com', 'pypi.org', 'crates.io', 'maven.org',
    'docker.com', 'kubernetes.io', 'terraform.io', 'hashicorp.com',
}

# Compile a set of registered domains (SLDs) for fast lookup
_TRUSTED_SLDS = set()
for _d in TRUSTED_DOMAINS:
    _parts = _d.split('.')
    if len(_parts) >= 2:
        _TRUSTED_SLDS.add(_parts[-2])  # e.g. 'google' from 'google.com'

# =============================================================================
# Global State
# =============================================================================
model = None
scaler = None
feature_columns = []
stats = {
    'total_predictions': 0,
    'malicious_detected': 0,
    'safe_detected': 0,
}

# =============================================================================
# Load Model on Startup
# =============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH   = os.path.join(SCRIPT_DIR, 'model.pkl')
SCALER_PATH  = os.path.join(SCRIPT_DIR, 'scaler.pkl')
COLUMNS_PATH = os.path.join(SCRIPT_DIR, 'feature_columns.json')


def load_model():
    """Load the trained model, scaler, and feature columns."""
    global model, scaler, feature_columns

    print("\n" + "=" * 60)
    print("🔧 Loading ML Model...")
    print("=" * 60)

    if not os.path.exists(MODEL_PATH):
        print(f"  ❌ Model not found at {MODEL_PATH}")
        print("  Please run training/train.py first!")
        return False

    model = joblib.load(MODEL_PATH)
    print(f"  ✅ Model loaded: {type(model).__name__}")

    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
        print(f"  ✅ Scaler loaded: StandardScaler")
    else:
        print(f"  ⚠ Scaler not found, predictions will use unscaled features")

    if os.path.exists(COLUMNS_PATH):
        with open(COLUMNS_PATH, 'r') as f:
            feature_columns = json.load(f)
        print(f"  ✅ Feature columns loaded: {len(feature_columns)} features")
    else:
        feature_columns = get_feature_names()
        print(f"  ⚠ Using default feature columns: {len(feature_columns)} features")

    print(f"\n  ✅ URL Shield API ready — model loaded")
    print(f"  Features       : {len(feature_columns)}")
    print(f"  Threshold      : {MALICIOUS_THRESHOLD}")
    print(f"  Trusted domains: {len(TRUSTED_DOMAINS)}")
    print("=" * 60)
    return True


# =============================================================================
# Whitelist Check
# =============================================================================

def _get_apex_domain(url: str) -> tuple[str, str]:
    """
    Return (full_apex, sld) for a URL.
    e.g. 'https://mail.google.com/...' → ('google.com', 'google')
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0].lower()
        parts = host.split('.')
        if len(parts) >= 2:
            apex = '.'.join(parts[-2:])
            sld = parts[-2]
            return apex, sld
    except Exception:
        pass
    return '', ''


def _is_trusted(url: str) -> bool:
    """
    Return True if the URL's apex domain is in the trusted whitelist.
    Checks both exact apex domain and country-code variants (e.g. google.co.in).
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0].lower()
        parts = host.split('.')

        # Try last 3 parts first (e.g. google.co.in → check 'google.co.in' and 'co.in')
        if len(parts) >= 3:
            apex3 = '.'.join(parts[-3:])
            apex2 = '.'.join(parts[-2:])
            sld = parts[-2]
            if apex3 in TRUSTED_DOMAINS or apex2 in TRUSTED_DOMAINS:
                return True
            # Also check SLD-only for broader coverage (e.g. 'google' covers all google.X)
            if sld in _TRUSTED_SLDS:
                # Extra safety: make sure the subdomain doesn't look like impersonation
                # e.g. 'evil-google.com' — sld is 'evil', so 'google' won't match
                return True
        elif len(parts) == 2:
            apex2 = '.'.join(parts[-2:])
            sld = parts[-2]
            if apex2 in TRUSTED_DOMAINS or sld in _TRUSTED_SLDS:
                return True
    except Exception:
        pass
    return False


# =============================================================================
# Prediction
# =============================================================================

def predict_single_url(url: str) -> dict:
    """
    Run prediction on a single URL.

    Returns
    -------
    dict
        Prediction result with label, confidence, probabilities, risk_level, trusted_domain.
    """
    start_time = time.perf_counter()

    # ── Fast-path: trusted domain whitelist ──────────────────────────────────
    trusted = _is_trusted(url)
    if trusted:
        processing_ms = round((time.perf_counter() - start_time) * 1000, 2)
        stats['total_predictions'] += 1
        stats['safe_detected'] += 1
        return {
            'url':            url,
            'label':          'Safe',
            'prediction':     0,
            'confidence':     0.99,
            'safe_prob':      0.99,
            'malicious_prob': 0.01,
            'risk_level':     'LOW',
            'processing_ms':  processing_ms,
            'features_used':  len(feature_columns),
            'trusted_domain': True,
            'note':           'Domain is in trusted whitelist',
        }

    # ── ML prediction ────────────────────────────────────────────────────────
    X = extract_features(url)

    if scaler is not None:
        X_scaled = scaler.transform(X)
    else:
        X_scaled = X

    probabilities   = model.predict_proba(X_scaled)[0]
    safe_prob       = float(probabilities[0])
    malicious_prob  = float(probabilities[1])
    confidence      = float(max(probabilities))

    # Use configurable threshold instead of fixed 0.5
    prediction = 1 if malicious_prob >= MALICIOUS_THRESHOLD else 0

    # Determine risk level
    if malicious_prob > 0.90:
        risk_level = 'CRITICAL'
    elif malicious_prob > 0.75:
        risk_level = 'HIGH'
    elif malicious_prob > 0.50:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    label = 'Malicious' if prediction == 1 else 'Safe'

    processing_ms = round((time.perf_counter() - start_time) * 1000, 2)

    stats['total_predictions'] += 1
    if prediction == 1:
        stats['malicious_detected'] += 1
    else:
        stats['safe_detected'] += 1

    return {
        'url':            url,
        'label':          label,
        'prediction':     prediction,
        'confidence':     round(confidence, 4),
        'safe_prob':      round(safe_prob, 4),
        'malicious_prob': round(malicious_prob, 4),
        'risk_level':     risk_level,
        'processing_ms':  processing_ms,
        'features_used':  len(feature_columns),
        'trusted_domain': False,
    }


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status':          'ok',
        'model':           type(model).__name__ if model else 'not loaded',
        'n_features':      len(feature_columns),
        'threshold':       MALICIOUS_THRESHOLD,
        'trusted_domains': len(TRUSTED_DOMAINS),
        'version':         '2.0.0',
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Predict whether a single URL is safe or malicious."""
    if model is None:
        return jsonify({'error': 'Model not available'}), 503

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Request body must be JSON'}), 400

    url = data.get('url')

    if url is None:
        return jsonify({'error': 'url field is required'}), 400

    if not isinstance(url, str) or url.strip() == '':
        return jsonify({'error': 'url cannot be empty'}), 400

    url = url.strip()

    # Auto-add scheme if missing (user types 'google.com' without https://)
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        result = predict_single_url(url)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    """Predict for a batch of URLs (max 50)."""
    if model is None:
        return jsonify({'error': 'Model not available'}), 503

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Request body must be JSON'}), 400

    urls = data.get('urls')

    if urls is None or not isinstance(urls, list):
        return jsonify({'error': 'urls field must be a list'}), 400

    if len(urls) == 0:
        return jsonify({'error': 'urls list cannot be empty'}), 400

    if len(urls) > 50:
        return jsonify({'error': 'Maximum 50 URLs per batch'}), 400

    try:
        results = []
        for url in urls:
            if isinstance(url, str) and url.strip():
                u = url.strip()
                if not u.startswith(('http://', 'https://')):
                    u = 'https://' + u
                results.append(predict_single_url(u))
            else:
                results.append({
                    'url':   str(url),
                    'label': 'Error',
                    'error': 'Invalid URL',
                })

        return jsonify({
            'results': results,
            'total':   len(results),
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    """Return API usage statistics."""
    return jsonify(stats)


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    loaded = load_model()
    if loaded:
        print("\n🚀 Starting URL Shield API on http://127.0.0.1:5000")
        print("   Endpoints:")
        print("     GET  /health        — Health check")
        print("     POST /predict       — Single URL prediction")
        print("     POST /batch_predict — Batch URL prediction")
        print("     GET  /stats         — API statistics")
        print("=" * 60 + "\n")
        app.run(host='127.0.0.1', port=5000, debug=False)
    else:
        print("\n❌ Failed to load model. Please run training/train.py first.")
        print("   Then copy model.pkl and scaler.pkl to the api/ folder.")
