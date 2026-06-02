"""
app.py
======
Flask REST API for ML-based malicious URL detection.
Loads trained Random Forest model and provides real-time predictions.
"""

import os
import time
import json
import traceback
import numpy as np
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature_extractor import extract_features, get_feature_names

# =============================================================================
# Flask App Setup
# =============================================================================
app = Flask(__name__)
CORS(app)  # Enable CORS for ALL origins (required for Chrome extension)

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

MODEL_PATH = os.path.join(SCRIPT_DIR, 'model.pkl')
SCALER_PATH = os.path.join(SCRIPT_DIR, 'scaler.pkl')
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
    print(f"  Features: {len(feature_columns)}")
    print("=" * 60)
    return True


def predict_single_url(url: str) -> dict:
    """
    Run prediction on a single URL.

    Returns
    -------
    dict
        Prediction result with label, confidence, probabilities, etc.
    """
    start_time = time.perf_counter()

    # Extract features
    X = extract_features(url)

    # Scale features
    if scaler is not None:
        X_scaled = scaler.transform(X)
    else:
        X_scaled = X

    # Predict
    prediction = int(model.predict(X_scaled)[0])
    probabilities = model.predict_proba(X_scaled)[0]

    safe_prob = float(probabilities[0])
    malicious_prob = float(probabilities[1])
    confidence = float(max(probabilities))

    # Determine risk level
    if malicious_prob > 0.95:
        risk_level = 'CRITICAL'
    elif malicious_prob > 0.85:
        risk_level = 'HIGH'
    elif safe_prob > 0.85:
        risk_level = 'LOW'
    else:
        risk_level = 'MEDIUM'

    # Determine label
    label = 'Malicious' if prediction == 1 else 'Safe'

    # Processing time
    processing_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # Update stats
    stats['total_predictions'] += 1
    if prediction == 1:
        stats['malicious_detected'] += 1
    else:
        stats['safe_detected'] += 1

    return {
        'url': url,
        'label': label,
        'prediction': prediction,
        'confidence': round(confidence, 4),
        'safe_prob': round(safe_prob, 4),
        'malicious_prob': round(malicious_prob, 4),
        'risk_level': risk_level,
        'processing_ms': processing_ms,
        'features_used': len(feature_columns),
    }


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'model': type(model).__name__ if model else 'not loaded',
        'n_features': len(feature_columns),
        'version': '1.0.0',
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Predict whether a single URL is safe or malicious."""
    # Check model loaded
    if model is None:
        return jsonify({'error': 'Model not available'}), 503

    # Parse request
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Request body must be JSON'}), 400

    url = data.get('url')

    if url is None:
        return jsonify({'error': 'url field is required'}), 400

    if not isinstance(url, str) or url.strip() == '':
        return jsonify({'error': 'url cannot be empty'}), 400

    url = url.strip()

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
                results.append(predict_single_url(url.strip()))
            else:
                results.append({
                    'url': str(url),
                    'label': 'Error',
                    'error': 'Invalid URL',
                })

        return jsonify({
            'results': results,
            'total': len(results),
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
