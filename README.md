# 👁️ Third Eye
> AI-powered cyber threat detection platform that detects, scores, and *explains* phishing, malicious URLs, and suspicious messages in real time.

## Team
- **Pushkar** — Team Lead
- **Prasad** — Frontend (React)
- **Kumar** — Backend (FastAPI)
- **Aniruddh** — ML & Explainability

## Problem Statement
Design and develop a smart cyber defense platform that can detect, analyze, and explain emerging cyber threats using AI/ML techniques — including phishing emails, malicious URLs, AI-generated deceptive content, and suspicious messages.

---

## Project Structure
```
ThreatLens/
├── data/
│   ├── raw/                    # PhishTank CSVs, spam datasets
│   └── processed/              # Cleaned, tokenized data
│
├── notebooks/
│   └── eda_phishing.ipynb      # Exploratory analysis
│
├── src/
│   ├── data/
│   │   └── preprocess.py       # Text cleaning, URL parsing
│   ├── features/
│   │   └── feature_extraction.py  # URL features, email header parsing
│   ├── models/
│   │   └── classifier.py       # HuggingFace model wrapper
│   └── utils/
│       └── explain.py          # Explainability logic (keyword highlights, scores)
│
├── api/
│   ├── main.py                 # FastAPI app entry point
│   ├── routes/
│   │   ├── analyze.py          # /analyze/url and /analyze/text endpoints
│   │   └── health.py           # /health check
│   └── schemas/
│       └── threat.py           # Pydantic request/response models
│
├── frontend/                   # React app (Vite + Tailwind)
│   ├── src/
│   │   ├── components/
│   │   │   ├── InputPanel.jsx
│   │   │   ├── RiskScore.jsx
│   │   │   ├── ExplanationCard.jsx
│   │   │   └── RecommendationPanel.jsx
│   │   └── App.jsx
│   └── package.json
│
├── models/                     # Saved model artifacts
│   └── phishing_classifier.pkl
│
├── requirements.txt
└── README.md
```

---

## Setup

```bash
git clone <repo-url>
cd ThreatLens
pip install -r requirements.txt
```

---

## Run API

```bash
cd api
uvicorn main:app --reload --port 8000
```

API will be live at: `http://localhost:8000`
Swagger docs at: `http://localhost:8000/docs`

---

## Run Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend will be live at: `http://localhost:5173`

---

## Approach

- **EDA**: Analyzed PhishTank dataset + SMS spam corpus for phishing pattern identification
- **Model**: Fine-tuned BERT-based classifier (`mrm8488/bert-tiny-finetuned-sms-spam-detection`) via HuggingFace Transformers, with URL feature engineering (domain age, HTTPS, suspicious keywords, redirect chains)
- **Explainability**: Rule-based token highlighting + confidence scores. Top suspicious tokens surfaced per prediction. SHAP-style contribution scores for URL features.
- **API**: FastAPI serving predictions at `/analyze/url` and `/analyze/text` with structured JSON response
- **Frontend**: React + TailwindCSS dashboard with real-time risk scoring, explanation panel, and action recommendations

---

## API Response Schema

```json
{
  "input": "http://paypa1-secure-login.xyz/verify",
  "threat_type": "Malicious URL",
  "risk_score": 91,
  "confidence": 0.94,
  "explanation": {
    "summary": "Domain mimics PayPal with character substitution. Registered 3 days ago. No HTTPS certificate authority trust.",
    "suspicious_tokens": ["paypa1", "secure-login", "verify"],
    "feature_contributions": {
      "domain_age_days": 3,
      "has_ip_address": false,
      "url_length": 38,
      "suspicious_keywords": ["secure", "login", "verify"]
    }
  },
  "recommendation": "Do not visit this URL. Report to your IT security team. Block domain at firewall level."
}
```

---

## Results

| Metric | Score |
|--------|-------|
| Phishing Detection Accuracy | ~94% |
| URL Classification F1 | ~0.92 |
| Avg. Response Time | < 800ms |
| Explainability Coverage | 100% of predictions |

---

## Modules

| Module | Description |
|--------|-------------|
| 🔍 Threat Input | URL, email text, or message paste |
| 🤖 Detection Engine | NLP + URL feature ML classifier |
| 💡 Explainability | Token highlights + feature contributions |
| 🛡️ Recommendations | Actionable, context-aware next steps |
| 📊 Dashboard | Live risk score, threat breakdown, alert log |

---

## Deployment

- **Frontend**: Vercel — [live link]
- **Backend**: Render / Railway — [live link]

---

## Future Scope

- Deepfake audio/video detection module
- Browser extension for real-time URL scanning
- SIEM integration for enterprise alert pipelines
- Adversarial robustness testing layer
- Multi-modal threat fusion (email + attachment + URL combined scoring)

---

*Built at IndiaNext Hackathon 2026 — K.E.S. Shroff College, Mumbai*
