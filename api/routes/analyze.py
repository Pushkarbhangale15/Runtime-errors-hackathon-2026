from fastapi import APIRouter
from api.schemas.threat import AnalyzeRequest, ThreatResponse, ExplanationDetail

router = APIRouter()

# ─────────────────────────────────────────────────────────────
# Lazy model loading
# Models load once on first request, not at startup
# Returns None if model file not found (falls back to mock)
# ─────────────────────────────────────────────────────────────

_url_model = None
_prompt_clf = None

def get_url_model():
    global _url_model
    if _url_model is None:
        try:
            import joblib
            _url_model = joblib.load("models/url_classifier.pkl")
            print("✅ URL model loaded")
        except Exception as e:
            print(f"⚠️  URL model not ready: {e}")
    return _url_model

def get_prompt_clf():
    global _prompt_clf
    if _prompt_clf is None:
        try:
            from transformers import pipeline
            _prompt_clf = pipeline(
                "text-classification",
                model="models/prompt_classifier",
                tokenizer="models/prompt_classifier"
            )
            print("✅ Prompt classifier loaded")
        except Exception as e:
            print(f"⚠️  Prompt model not ready: {e}")
    return _prompt_clf


# ─────────────────────────────────────────────────────────────
# Mock response — used when model isn't trained yet
# Kumar can build the full UI against this immediately
# ─────────────────────────────────────────────────────────────

def mock_response(input_text: str) -> ThreatResponse:
    return ThreatResponse(
        input=input_text,
        threat_type="Phishing Attempt",
        risk_score=78,
        confidence=0.91,
        is_threat=True,
        explanation=ExplanationDetail(
            summary="[MOCK] URL contains credential-harvesting keywords. Domain registered 2 days ago. Uses suspicious .xyz TLD.",
            suspicious_tokens=["verify", "secure", "login"],
            feature_contributions={
                "suspicious_words": 0.31,
                "tld_suspicious": 0.28,
                "url_length": 0.19
            }
        ),
        recommendation="⛔ High Risk: Do not interact. Block this domain. Report to your security team."
    )


# ─────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────

CATEGORY_EXPLANATIONS = {
    "jailbreak": "Attempts to override system instructions entirely — makes the AI ignore its safety guidelines.",
    "payload":   "Embeds a hidden malicious command inside what appears to be a normal request.",
    "evasion":   "Uses obfuscation or indirect phrasing to bypass keyword-based safety filters.",
    "generic":   "General manipulation attempt — tries to convince the AI to behave without restrictions.",
    "none":      "No significant threat indicators detected in this prompt."
}

def classify_category(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ["ignore", "forget", "disregard", "override", "dan", "jailbreak"]):
        return "jailbreak"
    if any(w in t for w in ["system:", "assistant:", "[inject", "<inject", "[system"]):
        return "payload"
    if any(w in t for w in ["h-e-l-p", "b.a.s.e", "base64", "rot13"]):
        return "evasion"
    return "generic"

def extract_suspicious_tokens(text: str) -> list:
    keywords = ["ignore", "override", "forget", "jailbreak", "dan", "verify",
                "login", "secure", "password", "credentials", "base64", "system:"]
    return [kw for kw in keywords if kw.lower() in text.lower()][:5]

def get_recommendation(risk_score: int) -> str:
    if risk_score >= 75:
        return "⛔ High Risk: Do not interact. Block sender/domain immediately. Report to your security team."
    elif risk_score >= 45:
        return "⚠️ Medium Risk: Treat with caution. Do not click links or enter credentials. Verify through official channels."
    else:
        return "✅ Low Risk: Appears safe. Stay vigilant and verify sender if unexpected."


# ─────────────────────────────────────────────────────────────
# POST /analyze/url
# ─────────────────────────────────────────────────────────────

@router.post("/url", response_model=ThreatResponse)
async def analyze_url(request: AnalyzeRequest):
    model = get_url_model()
    if model is None:
        return mock_response(request.input)

    import sys, os
    sys.path.append(os.getcwd())
    from src.features.feature_extraction import extract_features

    features      = extract_features(request.input)
    feat_values   = list(features.values())
    feat_names    = list(features.keys())

    prediction    = model.predict([feat_values])[0]
    proba         = float(model.predict_proba([feat_values])[0].max())

    is_threat     = prediction != "benign"
    risk_score    = int(proba * 100) if is_threat else int((1 - proba) * 35)

    # Explainability — top 3 contributing features
    importances   = model.feature_importances_
    contributions = {
        feat_names[i]: round(float(importances[i]) * float(feat_values[i]), 4)
        for i in range(len(feat_names))
    }
    top3 = dict(sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:3])

    FEATURE_MESSAGES = {
        "url_length":       "URL is unusually long — often used to obscure the real destination.",
        "has_ip":           "Uses a raw IP address instead of a domain name — classic phishing technique.",
        "tld_suspicious":   "Domain uses a high-risk TLD commonly associated with phishing.",
        "suspicious_words": "URL contains credential-harvesting keywords (verify, login, secure).",
        "at_symbol":        "Contains @ symbol — browser ignores everything before it.",
        "double_slash":     "Contains redirect trick using double slash.",
        "https":            "No HTTPS — connection would be unencrypted.",
    }

    reasons = [FEATURE_MESSAGES[f] for f in top3 if f in FEATURE_MESSAGES and top3[f] > 0]
    summary = " ".join(reasons) if reasons else (
        "URL structure matches known malicious patterns." if is_threat
        else "No significant threat indicators detected."
    )

    return ThreatResponse(
        input=request.input,
        threat_type=prediction.capitalize() if is_threat else "Clean URL",
        risk_score=risk_score,
        confidence=round(proba, 3),
        is_threat=is_threat,
        explanation=ExplanationDetail(
            summary=summary,
            suspicious_tokens=extract_suspicious_tokens(request.input),
            feature_contributions=top3
        ),
        recommendation=get_recommendation(risk_score)
    )


# ─────────────────────────────────────────────────────────────
# POST /analyze/prompt
# ─────────────────────────────────────────────────────────────

@router.post("/prompt", response_model=ThreatResponse)
async def analyze_prompt(request: AnalyzeRequest):
    clf = get_prompt_clf()
    if clf is None:
        return mock_response(request.input)

    result       = clf(request.input[:512])[0]
    is_injection = result["label"] == "LABEL_1"
    confidence   = round(float(result["score"]), 3)
    risk_score   = int(confidence * 100) if is_injection else int((1 - confidence) * 30)
    category     = classify_category(request.input) if is_injection else "none"

    return ThreatResponse(
        input=request.input,
        threat_type="Prompt Injection" if is_injection else "Benign Prompt",
        risk_score=risk_score,
        confidence=confidence,
        is_threat=is_injection,
        explanation=ExplanationDetail(
            summary=CATEGORY_EXPLANATIONS.get(category, "No threat detected."),
            suspicious_tokens=extract_suspicious_tokens(request.input),
            feature_contributions={
                "attack_category": category,
                "confidence": confidence
            }
        ),
        recommendation=get_recommendation(risk_score)
    )


# ─────────────────────────────────────────────────────────────
# POST /analyze/text  (email / SMS — reuses prompt classifier)
# ─────────────────────────────────────────────────────────────

@router.post("/text", response_model=ThreatResponse)
async def analyze_text(request: AnalyzeRequest):
    return await analyze_prompt(request)