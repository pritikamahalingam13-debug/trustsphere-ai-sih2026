from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional, List, Dict

# URL Analysis
class URLAnalysisRequest(BaseModel):
    url: str
    awareness_level: Optional[str] = "intermediate"

class URLAnalysisResponse(BaseModel):
    trust_score: int
    risk_level: str
    domain: str
    domain_age: str
    https_status: str
    suspicious_patterns: List[str]
    reputation: str
    impersonation_risk: str
    explanation: str
    recommended_action: str

# Identity Verification
class IdentityVerificationRequest(BaseModel):
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    organization_id: Optional[str] = None

class IdentityVerificationResponse(BaseModel):
    consistency_score: int
    risk_level: str
    verified_fields: List[str]
    suspicious_mismatches: List[str]
    explanation: str
    recommended_action: str

# Document Analysis
class DocumentAnalysisResponse(BaseModel):
    authenticity_score: int
    risk_level: str
    detected_anomalies: List[str]
    modification_indicators: List[str]
    explanation: str
    recommended_action: str

# Transaction Analysis
class TransactionAnalysisRequest(BaseModel):
    message: str
    website_url: Optional[str] = None
    upi_id: Optional[str] = None
    organization: str

class TransactionAnalysisResponse(BaseModel):
    transaction_score: int
    risk_level: str
    chain_mismatches: List[str]
    suspicious_signals: List[str]
    explanation: str
    recommended_action: str

# Message Analysis
class MessageAnalysisRequest(BaseModel):
    message: str
    awareness_level: Optional[str] = "intermediate"

class MessageAnalysisResponse(BaseModel):
    risk_level: str
    urgency_detected: bool
    threats: List[str]
    suspicious_links: List[str]
    payment_requests: bool
    impersonation_risk: str
    social_engineering_patterns: List[str]
    explanation: str
    recommended_action: str

# Scam Network
class ScamEntity(BaseModel):
    id: str
    type: str  # person, phone, email, website, upi, organization
    name: str
    risk_level: str

class ScamRelationship(BaseModel):
    source: str
    target: str
    type: str
    risk_score: int

class ScamNetworkResponse(BaseModel):
    entities: List[ScamEntity]
    relationships: List[ScamRelationship]
    scam_patterns: List[str]

# Dashboard
class RecentScan(BaseModel):
    id: str
    type: str
    input: str
    risk_level: str
    timestamp: str

class ThreatStatistics(BaseModel):
    total_threats: int
    critical: int
    high: int
    medium: int
    low: int

class DashboardResponse(BaseModel):
    overall_trust_score: int
    threats_detected: int
    websites_scanned: int
    transactions_analyzed: int
    recent_scans: List[RecentScan]
    threat_statistics: ThreatStatistics
