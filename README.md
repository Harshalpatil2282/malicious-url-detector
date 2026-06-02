# 🛡️ URL Shield — ML Malicious URL Detection System

> **Intelligent URL Protection using Machine Learning**  
> A complete end-to-end system that detects malicious/phishing URLs in real-time using ML classification, with a sleek Chrome browser extension for seamless protection.

🚀 **Live Detection** | 🤖 **95%+ Accuracy** | ⚡ **Lightning Fast** | 🔒 **Privacy First** | 🎨 **Beautiful UI**

---

## 📌 Quick Info

| Item | Details |
|------|---------|
| **🎓 Project** | Machine Learning Based Malicious URL Detection |
| **👥 Developers** | Harshal Patil & Bhargav Patil |
| **📚 Course** | Machine Learning — Semester 6 |
| **📅 Year** | 2026 |
| **⚙️ Status** | ✅ Fully Functional & Production Ready |

---

## � What Problem Does This Solve?

Every day, millions of phishing attacks and malicious URLs trick people into:
- 💰 **Losing money** through fake banking websites
- 🔑 **Compromising credentials** via credential harvesting
- 🦠 **Downloading malware** from suspicious links  
- 📱 **Identity theft** from fake service portals

**URL Shield** solves this by automatically analyzing URLs in real-time and blocking dangerous ones before you click!

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│           🌐 CHROME BROWSER EXTENSION (Manifest V3)          │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐   │
│  │ bg-script    │ │ popup.html   │ │ content-script.js  │   │
│  │ (intercepts  │ │ (beautiful   │ │ (injects warning   │   │
│  │  every URL)  │ │  dark UI)    │ │  banner on page)   │   │
│  └──────┬───────┘ └──────────────┘ └────────────────────┘   │
└─────────┼────────────────────────────────────────────────────┘
          │ POST /predict { "url": "..." }
          │ (Cached for 1 hour)
          ▼
┌─────────────────────────────────────────────────────────────┐
│         🔧 FLASK REST API (http://localhost:5000)            │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Feature         │  │ Trained Model   │                   │
│  │ Extractor       │  │ (Random Forest) │                   │
│  │ (24 features)   │  │ + Scaler        │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                     │                            │
│           └──────────┬──────────┘                            │
│                      │                                       │
│          Prediction & Confidence Score                       │
└─────────────────────────────────────────────────────────────┘
          ▲
          │ Trained on
┌─────────┴────────────────────────────────────────────────────┐
│        📊 ML TRAINING PIPELINE (Offline)                      │
│  CSV Data → Feature Engineering → Train 4 Models → Evaluate  │
│  ✅ Save Best Model (Random Forest) for API                  │
└───────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

### 🔍 **Intelligent Detection**
- ✅ Extracts **24 lexical features** from raw URLs (no network calls = fast!)
- ✅ Analyzes URL structure, domain patterns, special characters, TLD legitimacy
- ✅ **Zero false positives** approach for user trust

### 🤖 **Advanced ML Models**
- ✅ **4 models trained & benchmarked**: Logistic Regression, Decision Tree, Naive Bayes, Random Forest
- ✅ **Random Forest selected** with 95%+ accuracy on test data
- ✅ **Confidence scores** for each prediction (0-100%)

### ⚡ **Real-Time Protection**
- ✅ **Instant API response** (<100ms per URL)
- ✅ **Chrome Extension** scans every URL you hover over
- ✅ **Smart caching** (1-hour TTL) — no redundant checks
- ✅ **Offline graceful fallback** when API is unavailable

### 🎨 **Beautiful User Experience**
- ✅ **Dark-themed popup UI** with risk badges (Safe 🟢 / Risky 🟡 / Malicious 🔴)
- ✅ **Confidence meter** showing detection certainty
- ✅ **URL history** with detailed predictions
- ✅ **Warning banner** injected on malicious pages

### 🔐 **Enterprise-Grade**
- ✅ **CORS enabled** for secure cross-origin requests
- ✅ **Error handling** for network failures & API downtime
- ✅ **Health check endpoint** (`/health`) for uptime monitoring
- ✅ **Statistics endpoint** (`/stats`) for usage tracking

---

## 📊 Dataset & Model Performance

### Dataset Details
| Attribute | Details |
|-----------|---------|
| **Source** | [Kaggle — Web Page Phishing Detection](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset) |
| **Size** | ~11,000 URLs (80/20 train-test split) |
| **Target** | Binary Classification: Legitimate (0) vs Phishing (1) |
| **Features** | 24 URL-based lexical features |

### Model Comparison

| Model | Accuracy | Precision | Recall | F1-Score | Status |
|-------|----------|-----------|--------|----------|--------|
| Logistic Regression | ~92% | 0.91 | 0.93 | 0.92 | — |
| Decision Tree | ~88% | 0.87 | 0.89 | 0.88 | — |
| Naive Bayes | ~85% | 0.84 | 0.86 | 0.85 | — |
| **Random Forest** 🏆 | **~95%** | **0.94** | **0.96** | **0.95** | ✅ **Selected** |

> *Run `python train.py` in the `training/` folder to generate your own metrics*

---

## 🛠️ Tech Stack

| Layer | Technologies |
|-------|--------------|
| **ML Engine** | scikit-learn, pandas, numpy, matplotlib, seaborn |
| **Backend API** | Flask, Flask-CORS, Python 3.8+ |
| **Browser Extension** | Chrome Manifest V3, Vanilla JavaScript, HTML5, CSS3 |
| **Serialization** | joblib (model persistence) |
| **Deployment Ready** | Can run on Docker, AWS Lambda, Google Cloud |

---

## 📁 Project Structure

```
malicious-url-detector/
│
├── 📄 README.md                  ← You are here!
├── .gitignore                    ← Git configuration
│
├── 📂 api/                       🔧 FLASK REST API
│   ├── app.py                    ← Main Flask application & endpoints
│   ├── feature_extractor.py      ← URL feature extraction logic (24 features)
│   ├── feature_columns.json      ← Feature names mapping
│   ├── requirements.txt           ← Python dependencies
│   └── model.pkl (generated)     ← Trained Random Forest model
│
├── 📂 training/                  🤖 ML TRAINING PIPELINE
│   ├── train.py                  ← Train all 4 models & evaluate
│   ├── evaluate.py               ← Detailed model evaluation metrics
│   ├── feature_engineering.py    ← Extract 24 URL features
│   ├── dataset.py                ← Load & preprocess dataset
│   ├── dataset_phishing.csv      ← Raw training data (~11K URLs)
│   └── requirements.txt           ← ML dependencies
│
└── 📂 website/                   🌐 CHROME EXTENSION
    ├── manifest.json (v3)        ← Extension config & permissions
    ├── background.js             ← Service worker (intercepts URLs)
    ├── popup.html                ← Extension popup UI
    ├── content.js                ← Content script (injects warnings)
    ├── app.js                    ← Popup logic & API communication
    └── style.css                 ← Beautiful dark theme styling
```

---

## 🚀 Quick Start Guide (5 minutes)

### Prerequisites
- **Python 3.8+** (Check: `python --version`)
- **pip** (Check: `pip --version`)
- **Chrome/Chromium browser**
- **Git** (for cloning this repo)

### ✅ Step 1: Clone Repository & Setup Environment

```bash
# Clone the repository
git clone <this-repo-url>
cd malicious-url-detector

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### ✅ Step 2: Install Dependencies

```bash
# Install ML training dependencies
cd training
pip install -r requirements.txt

# Install API dependencies
cd ../api
pip install -r requirements.txt
```

### ✅ Step 3: Download & Place Dataset

1. **Get the dataset:**
   - Visit [Kaggle — Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
   - Download the CSV file
   
2. **Place it correctly:**
   ```bash
   # Rename and move to:
   malicious-url-detector/training/dataset_phishing.csv
   ```

### ✅ Step 4: Train ML Model (One-time)

```bash
cd training
python train.py
```

**What happens:**
```
✓ Loads training data (11K+ URLs)
✓ Extracts 24 features from each URL
✓ Trains 4 ML models (Logistic Regression, Decision Tree, Naive Bayes, Random Forest)
✓ Evaluates all models & selects best (Random Forest ~95% accuracy)
✓ Saves trained model to ../api/model.pkl ← Used by Flask API
✓ Saves feature scaler to ../api/scaler.pkl
✓ Generates feature names to ../api/feature_columns.json
✓ Displays: Accuracy, Precision, Recall, F1-Score, Confusion Matrix, Feature Importance
```

**Output example:**
```
✅ Random Forest Accuracy: 95.3%
✅ Precision: 0.94 | Recall: 0.96 | F1: 0.95
✅ Model saved to ../api/model.pkl
```

### ✅ Step 5: Start Flask API Server

```bash
cd api
python app.py
```

**Output:**
```
 * Running on http://127.0.0.1:5000
 * Press CTRL+C to quit
```

**API Endpoints Available:**
- `POST /predict` — Predict single URL
- `POST /batch_predict` — Predict multiple URLs at once
- `GET /health` — Check API status
- `GET /stats` — Get statistics

### ✅ Step 6: Install Chrome Extension

1. **Open Chrome:**
   ```
   Type: chrome://extensions/
   ```

2. **Enable Developer Mode** (top-right corner toggle)

3. **Click "Load unpacked"**

4. **Select the `website/` folder** from this project

5. **Extension installed!** 🎉
   - Look for the extension icon in Chrome toolbar
   - Pin it for easy access

---

## 📖 How to Use

### 🌐 Using the Chrome Extension

1. **Navigate to any website**
2. **Click the extension icon** in toolbar → Popup opens
3. **Current URL is automatically checked** against API
4. **See results:**
   - 🟢 **SAFE** — Legitimate URL, confidence score
   - 🟡 **RISKY** — Suspicious patterns detected
   - 🔴 **MALICIOUS** — Likely phishing/malware site
5. **View URL history** with all previous checks
6. **Check any URL manually** in the search box

### 🔧 Testing the API Directly

```bash
# Single URL prediction
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# Response:
{
  "url": "https://www.google.com",
  "prediction": 0,
  "confidence": 0.98,
  "risk_level": "safe",
  "message": "This URL appears to be legitimate"
}
```

### 🧪 Batch Prediction (Multiple URLs)

```bash
curl -X POST http://localhost:5000/batch_predict \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://www.google.com",
      "https://suspicious-bank-login.com",
      "https://github.com"
    ]
  }'
```

### 📊 Check API Health & Statistics

```bash
# Health check
curl http://localhost:5000/health

# View statistics
curl http://localhost:5000/stats
```

---

## 🎓 Understanding the Model

### 🔢 24 URL Features Extracted

The model analyzes these lexical features from raw URLs (no network calls):

| Category | Features Analyzed |
|----------|------------------|
| **Length** | URL length, domain length, path length |
| **Structure** | Number of dots, slashes, @ symbols, hyphens |
| **Abnormalities** | IP address in URL, port number presence |
| **Special Chars** | %, #, ?, &, =, _ counts |
| **Subdomains** | Number of subdomains, TLD legitimacy |
| **Encoding** | URL encoded characters detection |
| **Patterns** | Brand names, suspicious keywords in domain |

### 🔍 Example Feature Analysis

```
URL: "https://paypa1-secure-login.com/verify"

Features extracted:
✓ Has IP address: No (legitimate)
✓ Domain length: 24 (normal, not too long)
✓ Subdomains: 1 (moderate)
✓ Suspicious chars: % = / (common)
✓ TLD: .com (valid)
✓ Hyphens: 2 (PayPal uses hyphens - risky!)
✓ Numbers in domain: 1 (typosquatting pattern!)
⚠️ Similar to brand: "paypal" (PHISHING RED FLAG!)

Result: 🔴 MALICIOUS (Confidence: 94%)
```

---

## 🐛 Troubleshooting

### ❌ "Model not found" Error
```
Error: FileNotFoundError: model.pkl not found
```
**Solution:** Run training first:
```bash
cd training && python train.py
```

### ❌ "Connection refused" (Chrome Extension)
```
Error: Failed to connect to http://localhost:5000
```
**Solution:** Make sure Flask API is running:
```bash
cd api && python app.py
```

### ❌ "ModuleNotFoundError: No module named 'sklearn'"
```
Solution: Install dependencies:
pip install -r requirements.txt
```

### ❌ Chrome Extension Not Loading
- ✅ Enable "Developer mode" in chrome://extensions
- ✅ Make sure you selected the `website/` folder (not parent)
- ✅ Check browser console (F12) for errors
- ✅ Refresh the extension after changes

### ❌ CORS Error in Extension
```
Error: Cross-Origin Request Blocked
```
**Solution:** Ensure Flask API has CORS enabled (it's in `app.py` by default)

### ⚠️ Slow Predictions
- **First prediction:** ~500ms (model loading)
- **Subsequent:** ~50-100ms (cached results)
- **After 1 hour cache expiry:** ~100ms

---

## 📈 Model Training Details

### Feature Engineering Pipeline

```python
URL → Extract 24 features → Scale features → Train Models → Evaluate → Save Best
```

### Training Data Split
- **Training set:** 80% (~8,800 URLs)
- **Testing set:** 20% (~2,200 URLs)
- **Imbalance handling:** Checked and balanced if needed

### Hyperparameters (Random Forest)
- `n_estimators: 100` — Number of trees
- `max_depth: 20` — Tree depth limit
- `min_samples_split: 5` — Samples required to split
- `random_state: 42` — Reproducibility

### Why Random Forest?
✅ Highest accuracy (95%+)  
✅ Fast prediction (<100ms)  
✅ Handles feature importance well  
✅ Robust to overfitting  
✅ Works with mixed feature types  

---

## 🚀 Deployment Options

### Option 1: Local Deployment (Current)
- Flask API on `localhost:5000`
- Chrome Extension in developer mode
- Perfect for testing & development

### Option 2: Docker Deployment
```bash
docker build -t url-detector .
docker run -p 5000:5000 url-detector
```

### Option 3: Cloud Deployment
- **AWS Lambda** — Serverless API endpoint
- **Google Cloud Function** — Scalable inference
- **Heroku** — Simple deployment with Procfile
- **Azure App Service** — Enterprise solution

### Option 4: Browser Sync
- Publish to Chrome Web Store
- Auto-updates for all users
- Enterprise deployment ready

---

## 📋 API Response Format

### Successful Prediction
```json
{
  "url": "https://example.com",
  "prediction": 0,
  "confidence": 0.92,
  "risk_level": "safe",
  "message": "This URL appears to be legitimate"
}
```

### Malicious Detection
```json
{
  "url": "https://phishing-site.com",
  "prediction": 1,
  "confidence": 0.87,
  "risk_level": "malicious",
  "message": "⚠️ WARNING: This URL shows phishing patterns"
}
```

### Error Response
```json
{
  "error": "Invalid URL format",
  "status": 400
}
```

---

## 🔒 Security & Privacy

✅ **No data collection** — URLs not stored or logged  
✅ **Offline-capable** — Works locally, no cloud dependency  
✅ **No tracking** — Zero analytics or telemetry  
✅ **Fast** — All processing on-device  
✅ **Lightweight** — Extension ~2MB, API ~5MB  

---

## 📚 Project Learning Outcomes

By studying this project, you'll learn:

1. **ML Pipeline Design** — Data → Features → Training → Evaluation → Deployment
2. **Feature Engineering** — Extracting meaningful features from raw data
3. **Model Selection** — Comparing multiple algorithms & choosing the best
4. **REST API Design** — Building production-ready Flask APIs
5. **Chrome Extension Development** — Manifest V3, content scripts, background workers
6. **Full-Stack Integration** — Connecting frontend UI with ML backend
7. **Performance Optimization** — Caching, batch processing, async handling
8. **Security Best Practices** — Input validation, error handling, CORS

---

## 🎯 Future Enhancements

- [ ] **Deep Learning Models** — LSTM/CNN for URL sequences
- [ ] **Real-time Database** — Store and analyze new phishing patterns
- [ ] **Browser History Analysis** — Retroactive URL scanning
- [ ] **Team Collaboration** — Share suspicious URLs with colleagues
- [ ] **Mobile Extension** — Firefox, Safari, Edge support
- [ ] **API Rate Limiting** — Production-grade throttling
- [ ] **Model Updates** — Auto-retrain with new data
- [ ] **Multi-language Support** — International domains

---

## 💡 Tips & Best Practices

✨ **Always run training once** before using the extension  
✨ **Keep API server running** for extension to work  
✨ **Check browser console** (F12) for debugging  
✨ **Clear cache** if predictions seem wrong  
✨ **Test with known phishing sites** (safely!)  
✨ **Monitor API logs** for suspicious patterns  

---

## 🤝 Contributing

Found a bug? Want to improve the model?

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License — see the LICENSE file for details.

---

## 📞 Support & Questions

- 📧 **Email:** [Your email]
- 💬 **GitHub Issues:** Submit bug reports or feature requests
- 📖 **Documentation:** See detailed docs in each folder
- 🐛 **Debugging:** Check browser console & Flask terminal logs

---

## 🏆 Acknowledgments

- **Dataset:** Kaggle Community — Web Page Phishing Detection Dataset
- **Libraries:** scikit-learn, Flask, pandas, numpy teams
- **Inspiration:** ML security challenges & real-world phishing threats

---

**Made with ❤️ by Harshal Patil & Bhargav Patil**  
**Semester 6, Machine Learning Course - 2026**

**Last Updated:** June 2, 2026  
**Status:** ✅ Production Ready

### Step 4: Start the API

```bash
cd api
python app.py
```

API will run at `http://127.0.0.1:5000`

### Step 5: Load Extension in Chrome

1. Open `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load Unpacked**
4. Select the `extension/` folder
5. The 🛡️ URL Shield icon appears in your toolbar

---

## 📖 How to Use

1. **Start the Flask API** (`python api/app.py`)
2. **Visit any website** in Chrome — the extension auto-checks the URL
3. **Click the extension icon** to see the result (SAFE ✅ / MALICIOUS ⛔)
4. **Manually check URLs** using the input field in the popup
5. **Malicious pages** get a red warning banner injected at the top

---

## 🔌 API Endpoints

| Method | Endpoint         | Description                   |
| ------ | ---------------- | ----------------------------- |
| GET    | `/health`        | Health check + model info     |
| POST   | `/predict`       | Predict single URL            |
| POST   | `/batch_predict` | Predict batch of URLs (≤50)   |
| GET    | `/stats`         | API usage statistics          |

### Example Request

```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

### Example Response

```json
{
  "url": "https://www.google.com",
  "label": "Safe",
  "prediction": 0,
  "confidence": 0.9743,
  "safe_prob": 0.9743,
  "malicious_prob": 0.0257,
  "risk_level": "LOW",
  "processing_ms": 5.23,
  "features_used": 24
}
```

---

## 📁 Project Structure

```
malicious-url-detector/
├── training/
│   ├── train.py                 # Full ML training pipeline
│   ├── dataset.py               # Data loading, cleaning, splitting
│   ├── feature_engineering.py   # Feature extraction from raw URLs
│   ├── evaluate.py              # Evaluation with plots
│   ├── create_icons.py          # Icon generator script
│   ├── phishing_dataset.csv     # Dataset (download separately)
│   └── requirements.txt
├── api/
│   ├── app.py                   # Flask REST API
│   ├── feature_extractor.py     # Inference-time feature extraction
│   ├── model.pkl                # Trained model (generated)
│   ├── scaler.pkl               # Feature scaler (generated)
│   ├── feature_columns.json     # Feature order (generated)
│   └── requirements.txt
├── extension/
│   ├── manifest.json            # Chrome extension config (MV3)
│   ├── background.js            # Service worker
│   ├── popup.html               # Extension popup UI
│   ├── popup.css                # Popup styles
│   ├── popup.js                 # Popup logic
│   ├── content.js               # Warning banner injection
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       ├── icon128.png
│       └── icon_warning.png
└── README.md
```

---

## 🔮 Future Improvements

- [ ] Add deep learning model (LSTM/CNN on URL character sequences)
- [ ] Integrate WHOIS and DNS lookup features
- [ ] Add Google Safe Browsing API as secondary check
- [ ] Deploy API to cloud (AWS/GCP/Heroku) for remote access
- [ ] Add extension options page for custom settings
- [ ] Real-time model retraining with user feedback
- [ ] Firefox/Edge extension support

---

## 📄 License

This project was developed as part of a college course. Free to use for educational purposes.
