from pydantic import BaseModel
from typing import List, Dict, Any

class AnalyzeRequest(BaseModel):
    input: str
    type: str = "auto"  # "url" | "text" | "prompt" | "auto"

class ExplanationDetail(BaseModel):
    summary: str
    suspicious_tokens: List[str] = []
    feature_contributions: Dict[str, Any] = {}

class ThreatResponse(BaseModel):
    input: str
    threat_type: str
    risk_score: int        # 0-100
    confidence: float      # 0.0-1.0
    is_threat: bool
    explanation: ExplanationDetail
    recommendation: str