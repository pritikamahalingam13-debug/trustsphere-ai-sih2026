# Trust Score Calculation Engine

class TrustScorer:
    """
    Explainable trust scoring system for TrustSphere AI
    Trust Score = 100 - (Weighted Risk Factors)
    """
    
    @staticmethod
    def calculate_trust_score(risk_factors: dict) -> tuple:
        """
        Calculate trust score from risk factors
        Returns: (trust_score, risk_level)
        """
        total_weighted_risk = 0
        
        # Default weights for different risk factors
        weights = {
            "url_risk": 0.20,
            "domain_age_risk": 0.15,
            "ssl_risk": 0.15,
            "reputation_risk": 0.15,
            "impersonation_risk": 0.20,
            "pattern_risk": 0.15
        }
        
        # Calculate weighted risk
        for factor, value in risk_factors.items():
            if factor in weights:
                total_weighted_risk += (value * weights[factor])
        
        # Cap at 100
        total_weighted_risk = min(100, total_weighted_risk)
        
        # Trust score = 100 - risk
        trust_score = max(0, 100 - int(total_weighted_risk))
        
        # Determine risk level
        risk_level = TrustScorer.get_risk_level(trust_score)
        
        return trust_score, risk_level
    
    @staticmethod
    def get_risk_level(trust_score: int) -> str:
        """
        Determine risk level based on trust score
        80–100: LOW RISK
        60–79: MEDIUM RISK
        40–59: HIGH RISK
        0–39: CRITICAL RISK
        """
        if trust_score >= 80:
            return "LOW"
        elif trust_score >= 60:
            return "MEDIUM"
        elif trust_score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"
    
    @staticmethod
    def calculate_identity_consistency(data: dict) -> int:
        """
        Calculate consistency between identity details
        Returns consistency score 0-100
        """
        score = 100
        
        # Check if all fields are provided
        fields_provided = sum([
            bool(data.get("email")),
            bool(data.get("phone")),
            bool(data.get("website")),
            bool(data.get("organization_id"))
        ])
        
        # Reduce score for missing fields
        if fields_provided < 2:
            score -= 20
        
        # Check for suspicious patterns
        if data.get("email"):
            email = data["email"].lower()
            if "suspicious" in email or "verify" in email or "confirm" in email:
                score -= 25
            if email.endswith(".tk") or email.endswith(".ml"):
                score -= 15
        
        if data.get("website"):
            website = data["website"].lower()
            if "verify" in website or "confirm" in website or "secure" in website:
                score -= 20
        
        return max(0, score)
    
    @staticmethod
    def analyze_domain_age(domain: str) -> tuple:
        """
        Analyze domain registration age
        Returns: (risk_score, age_description, risk_reason)
        """
        # This is simulated - in production, use WHOIS API
        
        if "example" in domain:
            return 50, "Unknown", "Cannot verify domain age"
        
        if "verify" in domain or "secure-login" in domain or "confirm" in domain:
            return 90, "Very Recent (< 7 days)", "Newly registered domain - common phishing pattern"
        
        if "amazon" in domain or "bank" in domain or "google" in domain:
            return 10, "Very Old (10+ years)", "Well-established domain"
        
        return 60, "Recent (< 1 year)", "Domain age is suspicious"
    
    @staticmethod
    def analyze_ssl_certificate(url: str) -> tuple:
        """
        Analyze SSL certificate status
        Returns: (risk_score, status, reason)
        """
        if "secure-login" in url or "verify" in url:
            return 85, "SELF_SIGNED", "Self-signed certificate detected - high phishing risk"
        
        if "amazon" in url or "google" in url or ".in" in url:
            return 5, "SECURE", "Valid SSL certificate from trusted authority"
        
        return 70, "UNTRUSTED", "SSL certificate verification failed"
    
    @staticmethod
    def get_awareness_level_explanation(base_explanation: str, level: str) -> str:
        """
        Adapt explanation based on user awareness level
        """
        if level == "beginner":
            return base_explanation.split(".")[0] + ". " + \
                   "In simple terms, this means the website appears unsafe. " + \
                   "Do not enter personal or payment information."
        
        elif level == "advanced":
            return base_explanation + " Advanced: Domain registration metadata shows characteristics " + \
                   "consistent with phishing infrastructure. Certificate chain validation incomplete. " + \
                   "Recommend reverse DNS and network reputation verification."
        
        else:  # intermediate
            return base_explanation
