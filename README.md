# 🛡️ URL Shield — ML Malicious URL Detection System

> **Intelligent URL Protection using Machine Learning**  
> A complete end-to-end system that detects malicious/phishing URLs using advanced Gradient Boosting ML classification. Includes Flask REST API and simple HTML web interface for seamless protection.

🚀 **Live Detection** | 🤖 **89% Accuracy** | ⚡ **Lightning Fast** | 🔒 **Privacy First** | 🎨 **Beautiful UI**

---

## 📌 Quick Info

| Item | Details |
|------|---------|
| **🎓 Project** | Machine Learning Based Malicious URL Detection |
| **👥 Developer** | Harshal Patil |
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
│         🌐 WEB INTERFACE (Simple HTML Website)               │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐   │
│  │ index.html   │ │ style.css    │ │ app.js             │   │
│  │ (main page)  │ │ (beautiful   │ │ (UI logic)         │   │
│  │              │ │  styling)    │ │                    │   │
│  └──────┬───────┘ └──────────────┘ └────────────────────┘   │
└─────────┼────────────────────────────────────────────────────┘
          │ POST /predict { "url": "..." }
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│         🔧 FLASK REST API (http://localhost:5000)            │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Feature         │  │ Trained Model   │                   │
│  │ Extractor       │  │ (Gradient       │                   │
│  │ (42 features)   │  │  Boosting)      │                   │
│  │                 │  │ + Scaler        │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                     │                            │
│           └──────────┬──────────┘                            │
│                      │                                       │
│     Prediction (89% Accuracy) & Confidence Score            │
└─────────────────────────────────────────────────────────────┘
          ▲
          │ Trained on
┌─────────┴────────────────────────────────────────────────────┐
│        📊 ML TRAINING PIPELINE (Completed)                    │
│  11,430 URLs → Extract 42 Features → Train 5 Models         │
│  ✅ Best: Gradient Boosting (89.0% Test Accuracy)           │
└───────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

### 🔍 **Intelligent Detection**
- ✅ Extracts **42 advanced features** from raw URLs (no network calls = fast!)
- ✅ Analyzes URL structure, entropy, domain patterns, special characters, sensitive words
- ✅ **89% test accuracy** with 0.9591 AUC-ROC score
- ✅ Robust features: ratio_digits, sensitive words, entropy, subdomains, hyphens

### 🤖 **Advanced ML Models**
- ✅ **5 models trained & benchmarked**: Logistic Regression, Decision Tree, Extra Trees, Random Forest, Gradient Boosting
- ✅ **Gradient Boosting selected** as best model (89.0% test accuracy)
- ✅ **Cross-validated**: Mean AUC-ROC 0.9549 ± 0.0051 (5-fold)
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
| **Total URLs** | 11,430 URLs (50% Legitimate / 50% Phishing) |
| **Train/Val/Test** | 70% (8,001) / 10% (1,143) / 20% (2,286) |
| **Target** | Binary Classification: Legitimate (0) vs Phishing (1) |
| **Features** | 42 Advanced URL-based features |

### ✅ Actual Model Performance (Test Set)

| Model | Accuracy | Precision | Recall | F1-Score | AUC-ROC | Status |
|-------|----------|-----------|--------|----------|---------|--------|
| **Gradient Boosting** 🏆 | **89.0%** | **0.8953** | **0.8828** | **0.8890** | **0.9591** | ✅ **SELECTED** |
| Extra Trees | 88.5% | 0.8998 | 0.8651 | 0.8821 | 0.9492 | — |
| Random Forest | 86.8% | 0.8763 | 0.8564 | 0.8663 | 0.9473 | — |
| Decision Tree | 84.1% | 0.8636 | 0.8091 | 0.8354 | 0.8788 | — |
| Logistic Regression | 81.0% | 0.8457 | 0.7583 | 0.7996 | 0.9011 | — |

**Cross-Validation Results (5-Fold):**
- Mean AUC-ROC: 0.9549 ± 0.0051
- Mean F1-Score: 0.8842 ± 0.0075

**Confusion Matrix (Gradient Boosting):**
```
             Predicted Legit   Predicted Phish
Actual Legit       1,025               118
Actual Phish         134             1,009
```

| Layer | Technologies |
|-------|--------------|
| **ML Engine** | scikit-learn (Gradient Boosting), pandas, numpy, matplotlib, seaborn |
| **Backend API** | Flask, Flask-CORS, Python 3.8+ |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript (Simple Web Interface) |
| **Model Serialization** | joblib (model persistence) |
| **Deployment Ready** | Flask server, can scale with Docker, AWS, Google Cloud |

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
│   ├── feature_extractor.py      ← URL feature extraction logic (42 features)
│   ├── feature_columns.json      ← Feature names mapping (42 features)
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
└── 📂 website/                   🌐 SIMPLE HTML WEB INTERFACE
    ├── index.html                ← Main webpage
    ├── app.js                    ← UI logic & API communication
    ├── style.css                 ← Beautiful styling
    └── (Future: Convert to Chrome Extension)
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

### ✅ Step 6: Access Web Interface

1. **Open the website:**
   ```bash
   # Option 1: Direct file
   Open website/index.html in your browser
   
   # Option 2: Local server
   cd website
   python -m http.server 8000
   # Then visit http://localhost:8000/
   ```

2. **Website Interface loaded!** 🎉
   - Simple HTML form to input URLs
   - Real-time prediction from Flask API
   - Beautiful dark-themed UI
   - Instant results with confidence scores

---

## 📖 How to Use

### 🌐 Using the Web Interface

1. **Open `website/index.html`** in your browser
2. **Enter a URL** in the input field
3. **Click "Check URL"** button
4. **See results:**
   - 🟢 **LEGITIMATE** — Safe URL, confidence score shown
   - 🟡 **SUSPICIOUS** — Suspicious patterns detected
   - 🔴 **MALICIOUS** — Likely phishing/malware site
5. **Instant feedback** with risk analysis and feature breakdown

### 🔮 Future Enhancement: Chrome Extension
The `website/` folder will be converted to a full Chrome Extension (Manifest V3) that will:
- ✨ Intercept all URLs automatically
- ✨ Show warnings before visiting phishing sites
- ✨ Maintain detailed URL history
- ✨ Work seamlessly in background with smart caching

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

### 🔢 42 Advanced URL Features Extracted & Used

The Gradient Boosting model analyzes these features from raw URLs (no network calls):

**Top 20 Most Important Features:**

| Rank | Feature | Importance | What It Means |
|------|---------|------------|--------------|
| 1 | `ratio_digits` | 10.4% | Proportion of digits in URL |
| 2 | `n_sensitive_words` | 8.7% | Count of phishing keywords ("verify", "confirm", "update") |
| 3 | `url_entropy` | 8.3% | Randomness/chaos in entire URL string |
| 4 | `domain_entropy` | 6.9% | Randomness in domain name only |
| 5 | `n_subdomains` | 6.9% | Number of subdomains (phishing uses many) |
| 6 | `longest_token_length` | 6.4% | Longest continuous alphanumeric segment |
| 7 | `domain_has_digits` | 4.9% | Domain contains numbers (suspicious typos like "paypa1") |
| 8 | `n_hyphens` | 4.9% | Number of hyphens in domain |
| 9 | `url_length` | 4.4% | Total URL length |
| 10 | `ratio_special` | 4.3% | Proportion of special characters (%, &, =, etc.) |
| 11 | `n_slash` | 4.3% | Number of forward slashes |
| 12 | `avg_token_length` | 4.1% | Average word segment length |
| 13 | `tld_length` | 3.2% | Length of top-level domain (.com, .org, etc.) |
| 14 | `domain_length` | 3.1% | Total domain length |
| 15 | `n_dots` | 2.8% | Number of dots in URL |
| 16 | `ratio_alpha` | 2.6% | Proportion of alphabetic characters |
| 17 | `n_digits` | 2.3% | Total count of digit characters |
| 18 | `path_entropy` | 2.1% | Randomness in URL path portion |
| 19 | `path_length` | 1.7% | Length of the path component |
| 20 | `url_depth` | 1.6% | Number of directory levels |

### 🎯 How Gradient Boosting Uses These Features

- **Ratio Features**: Detects unusual character distributions (phishing URLs have suspicious ratios)
- **Sensitive Words**: Flags urgency keywords ("verify", "confirm", "urgent") common in phishing
- **Entropy Scores**: Legitimate domains are readable (google.com), phishing uses random strings
- **Structure Patterns**: Attackers use tricks (google-verify.com, paypal-update.tk, secure-login.com)
- **Digit Patterns**: Phishers misspell brands (amaz0n.com, paypa1.com, g00gle.org)

### 🔍 Real-World Example: Phishing URL

```
URL: "https://paypa1-secure-verify.bank-login.com:8080/update/account"

🚨 PHISHING SIGNALS DETECTED:
  ✗ n_sensitive_words: 3 (secure, verify, update) → Urgency tactics
  ✗ domain_has_digits: YES (paypa1 ≠ paypal) → Typosquatting
  ✗ n_hyphens: 2 (not in PayPal domains) → Suspicious structure
  ✗ n_subdomains: 2 (complex layering) → Domain spoofing
  ✗ has_port: 8080 (non-standard) → Evasion attempt
  ✗ url_entropy: HIGH (random-looking) → Randomized domain

📊 Model Verdict: PHISHING (91% confidence)
💔 Result: BLOCKED
```

### 🔍 Legitimate URL Example

```
URL: "https://www.github.com/user/repository/settings"

✅ LEGITIMATE SIGNALS DETECTED:
  ✓ n_sensitive_words: 0 → No urgency tactics
  ✓ domain_has_digits: NO → Clear brand name
  ✓ n_hyphens: 0 → Standard domain format
  ✓ n_subdomains: 1 (www) → Normal structure
  ✓ has_port: NO → Standard HTTPS (443)
  ✓ url_entropy: LOW → Readable word (github)

📊 Model Verdict: LEGITIMATE (96% confidence)
✅ Result: SAFE TO VISIT
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

### ❌ CORS Error When Accessing API
```
Error: Cross-Origin Request Blocked
```
**Solution:** Ensure Flask API has CORS enabled (it's in `app.py` by default). Restart the Flask server.

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

## 📈 Model Training Details (Completed)

### Feature Engineering Pipeline

```
Raw URLs (11,430) → Extract 42 Features → StandardScaler
     ↓
Train 5 Models in Parallel:
  • Logistic Regression
  • Decision Tree  
  • Extra Trees
  • Random Forest
  • Gradient Boosting ← Best Model! ✅
     ↓
Evaluate on Validation Set
5-Fold Cross-Validation
     ↓
Test on 20% Holdout Set (2,286 URLs)
```

### ✅ Actual Training Results

**Dataset:**
- **Total:** 11,430 URLs (perfectly balanced: 50% legitimate, 50% phishing)
- **Train:** 70% (8,001 URLs)
- **Validation:** 10% (1,143 URLs)  
- **Test:** 20% (2,286 URLs)
- **Features:** 42 extracted from raw URL strings

**Model Comparison - Validation Set:**

| Model | Accuracy | Precision | Recall | F1 | AUC-ROC |
|-------|----------|-----------|--------|-----|---------|
| Gradient Boosting | 87.8% | 0.9013 | 0.8476 | 0.8736 | 0.9519 |
| Extra Trees | 88.5% | 0.8998 | 0.8651 | 0.8821 | 0.9492 |
| Random Forest | 86.8% | 0.8763 | 0.8564 | 0.8663 | 0.9473 |
| Decision Tree | 84.1% | 0.8636 | 0.8091 | 0.8354 | 0.8788 |
| Logistic Regression | 81.0% | 0.8457 | 0.7583 | 0.7996 | 0.9011 |

**Final Test Set Performance (Gradient Boosting):**
```
              Precision  Recall  F1-Score  Support
Legitimate     0.8844    0.8968    0.8905   1,143
Phishing       0.8953    0.8828    0.8890   1,143

Accuracy:      0.8898 (89.0%) ✅
AUC-ROC:       0.9591
F1-Score:      0.8890
```

**5-Fold Cross-Validation Results:**
- Mean AUC-ROC: **0.9549 ± 0.0051**
- Mean F1-Score: **0.8842 ± 0.0075**
- Consistency: Very stable across folds ✅

### Why Gradient Boosting?
✅ **Highest AUC-ROC** (0.9591) — Best discrimination between phishing/legitimate  
✅ **89% Test Accuracy** — Reliable real-world performance  
✅ **Strong Cross-Validation** — Generalizes well to unseen data  
✅ **Feature Importance** — Clear insights into which features matter  
✅ **Fast Inference** (~100ms per URL)  
✅ **No overfitting** — Train/validation/test scores are consistent

### Training Data Split
- **Training set:** 70% (8,001 URLs)
- **Validation set:** 10% (1,143 URLs)
- **Test set:** 20% (2,286 URLs)
- **Class balance:** Perfectly balanced 50/50

### Hyperparameters (Gradient Boosting)
- `learning_rate: 0.1` — Learning rate for boosting
- `n_estimators: 100` — Number of boosting stages
- `max_depth: 5` — Maximum tree depth
- `subsample: 0.8` — Fraction of samples for fitting
- `random_state: 42` — Reproducibility

### Model Artifacts Saved
✅ `model.pkl` (383 KB) — Trained Gradient Boosting model  
✅ `scaler.pkl` — StandardScaler for feature normalization  
✅ `feature_columns.json` — 42 feature names mapping  

---

## 🚀 Deployment Options

### Option 1: Local Deployment (Current)
- **Flask API** on `localhost:5000`
- **HTML Website** in browser or local server
- **Perfect for:** Testing, development, learning
- **Setup:** Just run `python app.py` and open `index.html`

### Option 2: Docker Deployment
```bash
docker build -t url-detector .
docker run -p 5000:5000 url-detector
```
Scales easily and ensures consistent environment

### Option 3: Cloud Deployment
- **AWS Lambda** — Serverless API (pay-per-request)
- **Google Cloud Run** — Container-based serverless
- **Azure Container Apps** — Microsoft managed containers
- **Heroku** — Simple git push deployment

### Option 4: Chrome Extension (Future)
When converted to Chrome extension:
- Publish to Chrome Web Store
- Auto-updates for all users
- Background URL checking
- Zero configuration for end-users

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

### 🤖 Machine Learning
1. **Feature Engineering** — Extract 42 meaningful features from raw URLs
2. **Model Training & Evaluation** — Train 5 different algorithms, compare metrics, select best
3. **Hyperparameter Tuning** — Optimize for accuracy, precision, recall, AUC-ROC
4. **Cross-Validation** — Use 5-fold CV to validate model generalization
5. **Gradient Boosting** — Understand boosting ensembles & why they outperform single models
6. **Class Imbalance Handling** — Balance legitimate vs phishing samples

### 💻 Software Engineering
7. **ML Pipeline Design** — Data → Features → Scaling → Training → Evaluation → Deployment
8. **REST API Development** — Flask routes, request validation, error handling, CORS
9. **Frontend-Backend Integration** — HTML/CSS/JS communicating with Python API
10. **Configuration Management** — Feature columns, model persistence, scaler serialization

### 🏗️ Architecture & Deployment
11. **Production-Ready Code** — Error handling, logging, graceful degradation
12. **Model Deployment** — Save trained models, load for inference, serve via API
13. **Performance Optimization** — Caching strategies, batch processing, response times
14. **Security Best Practices** — CORS, input validation, secure defaults

### 📊 Data Science Workflow
15. **Dataset Exploration** — 11,430 balanced URLs, 50% legitimate, 50% phishing
16. **Feature Analysis** — Identify top 20 features by importance for interpretability
17. **Model Interpretability** — Understand which features drive predictions
18. **Real-world Problem Solving** — Detect phishing URLs, a genuine cybersecurity challenge

### 🚀 Future Extension Paths
19. **Chrome Extension Development** — When you convert `website/` to Manifest V3
20. **Scaling & Cloud Deployment** — Docker, AWS Lambda, Google Cloud
21. **Continuous Learning** — Auto-retrain models with new phishing data

**Key Technologies Mastered:**
```
Data Science:  Pandas, NumPy, scikit-learn, Gradient Boosting
Backend:       Flask, Python, REST APIs, CORS
Frontend:      HTML5, CSS3, Vanilla JavaScript
Tools:         Git, Jupyter, feature engineering, model evaluation
```

---

## 🎯 Future Enhancements

**Phase 1: Web Platform Improvements** 🚀
- [ ] **Database** — Store URLs & results for analytics
- [ ] **User Accounts** — Save personal URL history
- [ ] **Batch Upload** — Check multiple URLs from CSV
- [ ] **API Rate Limiting** — Production-grade throttling
- [ ] **Result Explanations** — Show which features triggered alert

**Phase 2: Model Enhancements** 🤖
- [ ] **Continuous Learning** — Update model with new phishing data
- [ ] **Ensemble Methods** — Combine multiple models for higher accuracy
- [ ] **Deep Learning** — LSTM/CNN for URL sequence analysis
- [ ] **Real-time Updates** — Auto-retrain daily with new threats
- [ ] **Explainability** — SHAP/LIME for feature contributions

**Phase 3: Chrome Extension** 🌐
- [ ] **Full Extension Build** — Manifest V3 implementation
- [ ] **Auto-checking** — Intercept every URL automatically
- [ ] **Warning Banners** — Inject alerts on phishing sites
- [ ] **Context Menu** — Check URL from right-click menu
- [ ] **Chrome Web Store** — Publish for public access

**Phase 4: Scale & Deployment** 🚀
- [ ] **Docker Containerization** — Production-ready images
- [ ] **Cloud Deployment** — AWS/GCP/Azure scaling
- [ ] **Mobile Browsers** — Firefox, Safari, Edge extensions
- [ ] **Performance Optimization** — Cache, CDN, edge computing
- [ ] **Multi-language Support** — International domain detection

---

## 💡 Tips & Best Practices

✨ **For Training Phase**  
- Always run `python train.py` first to generate model.pkl
- Check training output for model accuracy metrics  
- Validate results on test set before deployment

✨ **For API Usage**  
- Keep Flask server running while using website
- Monitor API logs for errors: `tail -f flask_logs.txt`
- Test API with curl before using in website

✨ **For Web Interface**  
- Clear browser cache if seeing stale results
- Check F12 console for JavaScript errors
- Test with known legitimate & phishing URLs

✨ **For Security**  
- Never commit credentials or API keys
- Use environment variables for sensitive data
- Keep dependencies updated: `pip install --upgrade -r requirements.txt`

✨ **For Production**  
- Use HTTPS for all communications
- Implement rate limiting (100 requests/hour)
- Add logging & monitoring
- Setup error alerts & notifications  

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
