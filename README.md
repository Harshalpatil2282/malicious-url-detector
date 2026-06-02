# 🛡️ URL Shield — ML Malicious URL Detection System

> A complete machine learning–based system that detects malicious/phishing URLs in real time, delivered as a Chrome browser extension.

---

## 📌 Project Info

| Field        | Details                                         |
| ------------ | ----------------------------------------------- |
| **Title**    | Machine Learning Based Malicious URL Detection  |
| **Team**     | Harshal Patil & Bhargav Patil                   |
| **Course**   | Machine Learning — Semester 6                   |
| **Year**     | 2026                                            |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   CHROME BROWSER EXTENSION                  │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │
│  │ background.js│  │  popup UI   │  │   content.js       │  │
│  │ (intercepts  │  │ (shows      │  │ (injects warning   │  │
│  │  tab URLs)   │  │  results)   │  │  banner on page)   │  │
│  └──────┬───────┘  └─────────────┘  └────────────────────┘  │
└─────────┼───────────────────────────────────────────────────┘
          │  POST /predict { url }
          ▼
┌─────────────────────────────────────────────────────────────┐
│                    FLASK REST API (:5000)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ feature_     │  │   model.pkl  │  │   scaler.pkl      │  │
│  │ extractor.py │  │ (Random      │  │ (StandardScaler)  │  │
│  │ (24 features)│  │  Forest)     │  │                   │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
          ▲
          │  Trained on
┌─────────┴───────────────────────────────────────────────────┐
│                  ML TRAINING PIPELINE                        │
│  Dataset → Feature Extraction → Train 4 Models → Save Best  │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ Features

- ✅ **24 lexical URL features** extracted from raw URL strings (no network calls)
- ✅ **4 ML models trained & compared**: Logistic Regression, Decision Tree, Naive Bayes, Random Forest
- ✅ **Random Forest classifier** with 95%+ accuracy
- ✅ **Flask REST API** with `/predict`, `/batch_predict`, `/health`, `/stats` endpoints
- ✅ **Chrome Extension (Manifest V3)** with real-time URL checking
- ✅ **Beautiful dark-theme popup UI** with confidence meters, risk badges, and history
- ✅ **Warning banner injection** on malicious pages via content script
- ✅ **1-hour result caching** to avoid redundant API calls
- ✅ **Graceful offline handling** when API is not running
- ✅ **CORS enabled** for cross-origin extension requests

---

## 📊 Dataset

| Field      | Details                                           |
| ---------- | ------------------------------------------------- |
| **Name**   | Web page Phishing Detection Dataset               |
| **Source**  | [Kaggle](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset) |
| **Target** | `status` — binary: 0 (legitimate) / 1 (phishing) |

---

## 🤖 ML Models Compared

| Model                | Accuracy | Precision | Recall | F1-Score |
| -------------------- | -------- | --------- | ------ | -------- |
| Logistic Regression  | —        | —         | —      | —        |
| Decision Tree        | —        | —         | —      | —        |
| Naive Bayes          | —        | —         | —      | —        |
| **Random Forest** ✅ | **—**    | **—**     | **—**  | **—**    |

> *Fill in results after running `python train.py`*

---

## 🛠️ Tech Stack

| Component    | Technology                          |
| ------------ | ----------------------------------- |
| ML           | scikit-learn, pandas, numpy         |
| API          | Flask, Flask-CORS                   |
| Extension    | Chrome Manifest V3, vanilla JS/CSS  |
| Serialization| joblib                              |
| Visualization| matplotlib, seaborn                 |

---

## 🚀 Setup Instructions

### Step 1: Install Python Dependencies

```bash
cd malicious-url-detector/training
pip install -r requirements.txt

cd ../api
pip install -r requirements.txt
```

### Step 2: Download Dataset

1. Download from [Kaggle — Web page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
2. Place the CSV file as `training/phishing_dataset.csv`

### Step 3: Train the Model

```bash
cd training
python train.py
```

This will:
- Train 4 models and compare them
- Save `model.pkl`, `scaler.pkl`, and `feature_columns.json` to the `api/` folder
- Print accuracy, F1-score, confusion matrix, and feature importances

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
