"""
index.py  —  Vercel Serverless Entry Point
===========================================
This is the Vercel-adapted version of app.py.
Vercel routes all /api/* requests to this file.
Flask routes are prefixed with /api/ to match.

The original api/app.py is kept for local development (python api/app.py).
"""

import os
import re
import sys
import time
import json
import traceback
import numpy as np
import joblib
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

# Ensure this file's directory is on the path so feature_extractor can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features, get_feature_names

# ─── Flask app ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ─── Configuration ────────────────────────────────────────────────────────────
MALICIOUS_THRESHOLD = 0.55

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
    'hotmail.com', 'outlook.com', 'azure.com', 'msn.com',
    # Apple ecosystem
    'apple.com', 'icloud.com', 'itunes.com', 'me.com',
    # News & Media
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'reuters.com',
    'theguardian.com', 'forbes.com', 'techcrunch.com', 'wired.com',
    'medium.com', 'wikipedia.org', 'wikimedia.org',
    # Education
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'mit.edu', 'stanford.edu', 'harvard.edu',
    # Government
    'gov.in', 'nic.in', 'gov.uk', 'gov.au', 'usa.gov',
    # Others
    'netflix.com', 'spotify.com', 'twitch.tv', 'dropbox.com',
    'zoom.us', 'slack.com', 'notion.so', 'figma.com', 'canva.com',
    'wordpress.com', 'wix.com', 'squarespace.com',
    'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io',
}

_TRUSTED_SLDS = {d.split('.')[-2] for d in TRUSTED_DOMAINS if len(d.split('.')) >= 2}

# ─── Model loading ────────────────────────────────────────────────────────────
# Loaded once on cold start; Vercel reuses warm instances across requests.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_model          = None
_scaler         = None
_feature_columns = []

def _load_model():
    global _model, _scaler, _feature_columns
    if _model is not None:
        return

    model_path   = os.path.join(_SCRIPT_DIR, 'model.pkl')
    scaler_path  = os.path.join(_SCRIPT_DIR, 'scaler.pkl')
    columns_path = os.path.join(_SCRIPT_DIR, 'feature_columns.json')

    _model  = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    with open(columns_path, 'r') as f:
        _feature_columns = json.load(f)

# Load immediately on import so first request isn't slow
try:
    _load_model()
except Exception as _e:
    print(f"[WARN] Model load error at startup: {_e}")

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_trusted(url: str) -> bool:
    try:
        host  = urlparse(url).netloc.split(':')[0].lower()
        parts = host.split('.')
        if len(parts) >= 3:
            if '.'.join(parts[-3:]) in TRUSTED_DOMAINS:
                return True
            if '.'.join(parts[-2:]) in TRUSTED_DOMAINS:
                return True
            if parts[-2] in _TRUSTED_SLDS:
                return True
        elif len(parts) == 2:
            if '.'.join(parts) in TRUSTED_DOMAINS or parts[-2] in _TRUSTED_SLDS:
                return True
    except Exception:
        pass
    return False


def _predict_url(url: str) -> dict:
    start = time.perf_counter()

    # Trusted-domain fast path
    if _is_trusted(url):
        return {
            'url':            url,
            'label':          'Safe',
            'prediction':     0,
            'confidence':     0.99,
            'safe_prob':      0.99,
            'malicious_prob': 0.01,
            'risk_level':     'LOW',
            'processing_ms':  round((time.perf_counter() - start) * 1000, 2),
            'features_used':  len(_feature_columns),
            'trusted_domain': True,
            'note':           'Domain is in trusted whitelist',
        }

    # ML prediction
    X  = extract_features(url)
    Xs = _scaler.transform(X) if _scaler else X

    proba        = _model.predict_proba(Xs)[0]
    safe_prob    = float(proba[0])
    mal_prob     = float(proba[1])
    confidence   = float(max(proba))
    prediction   = 1 if mal_prob >= MALICIOUS_THRESHOLD else 0

    if mal_prob > 0.90:
        risk_level = 'CRITICAL'
    elif mal_prob > 0.75:
        risk_level = 'HIGH'
    elif mal_prob > 0.50:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    return {
        'url':            url,
        'label':          'Malicious' if prediction == 1 else 'Safe',
        'prediction':     prediction,
        'confidence':     round(confidence, 4),
        'safe_prob':      round(safe_prob, 4),
        'malicious_prob': round(mal_prob, 4),
        'risk_level':     risk_level,
        'processing_ms':  round((time.perf_counter() - start) * 1000, 2),
        'features_used':  len(_feature_columns),
        'trusted_domain': False,
    }

# ─── Routes  (all prefixed /api/ to match Vercel routing) ────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status':          'ok',
        'model':           type(_model).__name__ if _model else 'not loaded',
        'n_features':      len(_feature_columns),
        'threshold':       MALICIOUS_THRESHOLD,
        'trusted_domains': len(TRUSTED_DOMAINS),
        'version':         '2.0.0',
    })


@app.route('/api/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    if _model is None:
        return jsonify({'error': 'Model not loaded'}), 503

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    url = data.get('url')
    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({'error': 'url field is required and cannot be empty'}), 400

    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        return jsonify(_predict_url(url))
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch_predict', methods=['POST', 'OPTIONS'])
def batch_predict():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    if _model is None:
        return jsonify({'error': 'Model not loaded'}), 503

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    urls = data.get('urls')
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({'error': 'urls must be a non-empty list'}), 400
    if len(urls) > 50:
        return jsonify({'error': 'Maximum 50 URLs per batch'}), 400

    try:
        results = []
        for u in urls:
            if isinstance(u, str) and u.strip():
                u = u.strip()
                if not u.startswith(('http://', 'https://')):
                    u = 'https://' + u
                results.append(_predict_url(u))
            else:
                results.append({'url': str(u), 'label': 'Error', 'error': 'Invalid URL'})

        return jsonify({'results': results, 'total': len(results)})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def stats():
    # NOTE: In serverless mode, stats are per-instance and reset on cold start.
    # For persistent stats, use a database (e.g., Vercel KV, PlanetScale).
    return jsonify({
        'note': 'Stats are per serverless instance and reset on cold start.',
        'total_predictions': 0,
        'malicious_detected': 0,
        'safe_detected': 0,
    })


# ─── Local dev fallback ───────────────────────────────────────────────────────
# When run locally (not via Vercel), also mount routes without /api/ prefix
# so you can test with: python api/index.py
if __name__ == '__main__':
    print('[INFO] Running locally — routes available at http://127.0.0.1:5000/api/...')
    app.run(host='127.0.0.1', port=5000, debug=True)
