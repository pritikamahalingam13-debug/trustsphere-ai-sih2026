# Sample threat data for demonstration

SAMPLE_SUSPICIOUS_URLS = [
    {
        "url": "https://secure-login-example.com",
        "domain": "secure-login-example.com",
        "domain_age": "3 days",
        "https_status": "SELF_SIGNED",
        "suspicious_patterns": [
            "Domain age is very recent",
            "Self-signed SSL certificate",
            "Homograph attack pattern detected"
        ],
        "reputation": "UNKNOWN",
        "impersonation_risk": "VERY_HIGH",
        "risk_score": 92
    },
    {
        "url": "https://amazon.in",
        "domain": "amazon.in",
        "domain_age": "12 years",
        "https_status": "SECURE",
        "suspicious_patterns": [],
        "reputation": "EXCELLENT",
        "impersonation_risk": "LOW",
        "risk_score": 8
    },
    {
        "url": "https://verify-account-now.tk",
        "domain": "verify-account-now.tk",
        "domain_age": "2 days",
        "https_status": "SELF_SIGNED",
        "suspicious_patterns": [
            "Very new domain",
            "Free TLD (.tk)",
            "Suspicious keyword pattern"
        ],
        "reputation": "UNKNOWN",
        "impersonation_risk": "CRITICAL",
        "risk_score": 95
    }
]

SAMPLE_SUSPICIOUS_MESSAGES = [
    {
        "message": "Urgent! Your account has been compromised. Click here immediately to verify: https://verify-account-now.tk",
        "urgency": True,
        "threats": ["Urgency", "Account compromise claim", "Credential request"],
        "links": ["https://verify-account-now.tk"],
        "payment_request": False,
        "impersonation_risk": "CRITICAL",
        "patterns": ["False urgency", "Account hijacking scam", "Phishing attempt"],
        "risk_score": 94
    },
    {
        "message": "Congratulations! You have won Rs. 1,00,000 in our lottery. Click to claim: https://lottery-prize.in and send Rs. 500 processing fee via UPI: lottery@bank",
        "urgency": True,
        "threats": ["Unsolicited prize", "Payment request", "Credential request"],
        "links": ["https://lottery-prize.in"],
        "payment_request": True,
        "impersonation_risk": "HIGH",
        "patterns": ["Prize/lottery scam", "Advance fee fraud", "Unrealistic claims"],
        "risk_score": 88
    },
    {
        "message": "Your HDFC Bank account requires verification. Update your details within 24 hours: https://hdfc-verify-now.com",
        "urgency": True,
        "threats": ["Time limit", "Account verification claim", "Credential request"],
        "links": ["https://hdfc-verify-now.com"],
        "payment_request": False,
        "impersonation_risk": "CRITICAL",
        "patterns": ["Bank impersonation", "Phishing attack", "Credential harvesting"],
        "risk_score": 96
    },
    {
        "message": "Hi, I'm from XYZ Recruitment. We're hiring for Senior Developer role. Interested? Visit: https://xyz-recruitment.in/apply",
        "urgency": False,
        "threats": [],
        "links": ["https://xyz-recruitment.in/apply"],
        "payment_request": False,
        "impersonation_risk": "MEDIUM",
        "patterns": ["Legitimate recruitment"],
        "risk_score": 35
    }
]

SAMPLE_IDENTITIES = [
    {
        "name": "HDFC Bank",
        "email": "support@hdfc-bank-verify.tk",
        "phone": "+91-9999999999",
        "website": "https://hdfc-verify-now.com",
        "mismatches": [
            "Email domain does not match official HDFC Bank domain",
            "Phone number is suspicious",
            "Website domain is not official"
        ],
        "risk_score": 92
    },
    {
        "name": "Amazon India",
        "email": "care@amazon.in",
        "phone": "+91-9000000000",
        "website": "https://amazon.in",
        "mismatches": [],
        "risk_score": 5
    },
    {
        "name": "XYZ Recruitment Solutions",
        "email": "hr@xyz-recruitment.fake",
        "phone": "+1-800-SCAM123",
        "website": "https://xyz-recruitment.in",
        "mismatches": [
            "Email domain appears fake",
            "Phone format is suspicious",
            "No verifiable online presence"
        ],
        "risk_score": 78
    }
]

SAMPLE_SCAM_NETWORK = {
    "entities": [
        {"id": "person_1", "type": "person", "name": "Rajesh Kumar", "risk": "HIGH"},
        {"id": "phone_1", "type": "phone", "name": "+91-8765432109", "risk": "HIGH"},
        {"id": "email_1", "type": "email", "name": "rajesh.work@suspicious.tk", "risk": "CRITICAL"},
        {"id": "email_2", "type": "email", "name": "jobs.notification@xyz.in", "risk": "HIGH"},
        {"id": "website_1", "type": "website", "name": "https://xyz-recruitment.in", "risk": "HIGH"},
        {"id": "website_2", "type": "website", "name": "https://secure-jobs-portal.com", "risk": "HIGH"},
        {"id": "upi_1", "type": "upi", "name": "rajesh@okhdfcbank", "risk": "CRITICAL"},
        {"id": "org_1", "type": "organization", "name": "XYZ Recruitment (Fake)", "risk": "CRITICAL"},
    ],
    "relationships": [
        {"source": "person_1", "target": "phone_1", "type": "uses", "risk": 85},
        {"source": "phone_1", "target": "email_1", "type": "receives", "risk": 88},
        {"source": "phone_1", "target": "email_2", "type": "receives", "risk": 80},
        {"source": "email_1", "target": "website_1", "type": "manages", "risk": 90},
        {"source": "email_2", "target": "website_2", "type": "manages", "risk": 82},
        {"source": "website_1", "target": "upi_1", "type": "collects", "risk": 95},
        {"source": "website_1", "target": "org_1", "type": "impersonates", "risk": 98},
    ],
    "patterns": ["Recruitment fraud", "Payment scam", "Identity theft", "Phishing network"]
}

RECENT_SCANS = [
    {"id": "scan_001", "type": "url", "input": "https://secure-login-example.com", "risk_level": "HIGH", "timestamp": "2026-09-01 10:30"},
    {"id": "scan_002", "type": "message", "input": "Urgent! Click here to verify...", "risk_level": "CRITICAL", "timestamp": "2026-09-01 09:15"},
    {"id": "scan_003", "type": "identity", "input": "HDFC Bank", "risk_level": "CRITICAL", "timestamp": "2026-09-01 08:45"},
    {"id": "scan_004", "type": "url", "input": "https://amazon.in", "risk_level": "LOW", "timestamp": "2026-09-01 08:00"},
]

THREAT_STATS = {
    "total_threats": 47,
    "critical": 12,
    "high": 18,
    "medium": 12,
    "low": 5
}
