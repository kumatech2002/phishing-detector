# 🛡️ PhishShield NG — Nigerian Bank Phishing Detection System

An ML-powered phishing detection system that identifies suspicious domains impersonating major Nigerian banking websites. Built as a complete full-stack application: scikit-learn backend, Flask REST API, SQLite history, and a rich dark-themed web interface.

> **⚠️ Important:** This system analyses domain names using *lexical features only* — it never visits or resolves the domain being analysed. All predictions are probabilistic and must not be treated as guarantees of safety or malice.

---

## 🏗️ Architecture

```
phishing-detector/
├── backend/
│   ├── app.py              # Flask app factory (serves API + frontend on port 5001)
│   ├── config.py           # Environment-based configuration
│   ├── requirements.txt    # Python dependencies
│   ├── .env.example        # Environment variable template
│   ├── api/
│   │   └── routes.py       # REST endpoints (/api/*)
│   ├── ml/
│   │   ├── features.py     # Feature extraction pipeline (shared by train + predict)
│   │   ├── dataset.py      # Synthetic dataset generator
│   │   ├── train.py        # Model training script (RF + GBM)
│   │   └── predict.py      # Prediction wrapper
│   ├── db/
│   │   └── database.py     # SQLite scan history
│   ├── models/             # Generated model artifacts (gitignored)
│   └── data/               # Generated dataset (gitignored)
├── frontend/
│   ├── index.html
│   ├── css/styles.css
│   └── js/
│       ├── app.js           # SPA router + API client
│       ├── dashboard.js     # Stats, charts, model comparison
│       ├── analyzer.js      # Domain submission + result display
│       └── history.js       # Scan history table + CSV export
└── tests/
    ├── conftest.py
    ├── test_features.py
    ├── test_predict.py
    └── test_api.py
```

---

## 🎯 Target Banks

Access Bank, GTBank, First Bank, UBA, Zenith Bank, Fidelity Bank, Union Bank, Ecobank, Stanbic IBTC, Polaris Bank

---

## ⚙️ Prerequisites

- **Python 3.10 or higher** — [python.org/downloads](https://www.python.org/downloads/)
- **Git** — [git-scm.com](https://git-scm.com/)

No Node.js, Docker, or other tools are required.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/orkuma-soc-portfolio.git
cd "orkuma-soc-portfolio/phishing-detector"
```

### 2. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

```bash
# Windows
copy backend\.env.example backend\.env

# Linux / macOS
cp backend/.env.example backend/.env
```

Edit `backend/.env` and set a strong `SECRET_KEY`.

### 5. Generate the dataset and train the model

```bash
python backend/ml/train.py
```

This will:
- Generate a synthetic labelled dataset (`backend/data/dataset.csv`)
- Train a **Random Forest** and a **Gradient Boosting** classifier
- Compare both on held-out test data and print real metrics
- Save the best model to `backend/models/model.joblib`
- Save metadata (metrics, feature importances) to `backend/models/meta.json`

Expected output example (your results will differ based on the dataset):
```
[INFO] Training Random Forest with GridSearchCV (5-fold CV)...
[INFO] Training Gradient Boosting with GridSearchCV (5-fold CV)...
[INFO] >>> Best model: Gradient Boosting (ROC-AUC=0.9987)
[INFO] TRAINING COMPLETE
[INFO] Accuracy  : 0.9921
[INFO] Precision : 0.9934
[INFO] Recall    : 0.9934
[INFO] F1 Score  : 0.9934
[INFO] ROC-AUC   : 0.9987
```

> **Note:** Figures shown above are illustrative only. Run `train.py` yourself to see actual results.

### 6. Start the application

```bash
python backend/app.py
```

Open your browser at **http://127.0.0.1:5001**

---

## 🔬 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Liveness + model readiness check |
| POST | `/api/analyze` | Analyse a domain for phishing signals |
| GET | `/api/history` | Paginated scan history |
| GET | `/api/history/<id>` | Single scan record |
| DELETE | `/api/history/<id>` | Delete a scan record |
| GET | `/api/stats` | Aggregate dashboard statistics |
| GET | `/api/model-info` | Model metadata and performance |

### Example: Analyse a domain

```bash
curl -X POST http://127.0.0.1:5001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "gtbank-secure-login.com"}'
```

Response:
```json
{
  "ok": true,
  "result": {
    "domain": "gtbank-secure-login.com",
    "label": 1,
    "label_text": "Phishing",
    "confidence": 0.9321,
    "phishing_probability": 0.9321,
    "explanation": "HIGH CONFIDENCE — strong phishing signals detected",
    "features": { "hyphen_count": 2, "suspicious_keyword_count": 2, ... },
    "risk_indicators": [
      { "level": "HIGH", "text": "Bank brand combined with suspicious keyword..." }
    ],
    "model_name": "Gradient Boosting",
    "disclaimer": "..."
  }
}
```

---

## 🧪 Running Tests

```bash
# From the phishing-detector/ directory, with venv activated:
python -m pytest tests/ -v --tb=short
```

Tests that require a trained model use mocks and will pass without model artifacts.
Feature extraction tests are fully standalone.

---

## 🧠 ML Models

Two classifiers are trained and compared:

| Model | Algorithm | Hyperparameter Search |
|-------|-----------|-----------------------|
| Random Forest | `sklearn.ensemble.RandomForestClassifier` | GridSearchCV (5-fold CV) |
| Gradient Boosting | `sklearn.ensemble.GradientBoostingClassifier` | GridSearchCV (5-fold CV) |

The **best model by ROC-AUC** on the held-out test set is saved. Both models' full metrics are stored in `backend/models/meta.json` and displayed on the dashboard.

### Features (37 total)

| Category | Examples |
|----------|---------|
| Structural | domain length, dot count, hyphen count, digit ratio |
| Lexical | Shannon entropy, word count, consonant/vowel ratio |
| Brand Similarity | Levenshtein distance, Jaro-Winkler similarity to 10 bank names |
| TLD | is `.ng`, is `.com`, TLD risk score |
| Suspicious Keywords | contains "secure", "login", "verify", "account", etc. |
| Camouflage | bank name in subdomain, typosquatting signal, IDN/punycode |

---

## 📊 Dataset

The model is trained on a **programmatically-generated synthetic dataset** (~5,000 labelled domains). Legitimate domains are derived from 10 Nigerian bank base domains. Phishing domains are generated using 8 realistic attack patterns:

1. Character transposition (gtbnak.com)
2. Character insertion (gttbank.com)
3. Character deletion (gtban.com)
4. Homoglyph substitution (zen1thbank.com)
5. Hyphenation camouflage (gtbank-secure.com)
6. Subdomain camouflage (gtbank.verify-account.com)
7. Risky TLD swap (gtbank.xyz)
8. Random suffix (gtbank91823.com)

The dataset is **reproducible** — running `python backend/ml/dataset.py` with the same seed produces identical output. To supplement with real data, append rows from [PhishTank](https://phishtank.org) or [OpenPhish](https://openphish.com) to the CSV before training.

---

## 🔒 Security Notes

- No HTTP requests are made to the domain being analysed
- All database queries use parameterised statements
- API endpoints are rate-limited (default: 30 requests/minute)
- Secrets are loaded from `.env` and never committed to source control
- Debug mode is disabled when `FLASK_ENV=production`

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|---------|
| `ModuleNotFoundError` | Activate virtual environment (`.\venv\Scripts\Activate.ps1`) |
| `Model file not found` | Run `python backend/ml/train.py` first |
| Port 5001 in use | Change port in `backend/app.py` or kill the existing process |
| `ExecutionPolicy` error (Windows) | Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Tests fail with import errors | Ensure you run pytest from the `phishing-detector/` directory |

---

## 📝 License

Built for educational and portfolio purposes. Adapt freely.

---

**Built by Orkuma** — SOC Analyst Portfolio Project
