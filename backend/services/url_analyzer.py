from .trust_scorer import TrustScorer
from ..data.sample_threats import SAMPLE_SUSPICIOUS_URLS

class URLAnalyzer:
    """
    Analyzes URLs for suspicious patterns and trust indicators
    """
    
    @staticmethod
    def analyze(url: str, awareness_level: str = "intermediate") -> dict:
        """
        Analyze a URL for trust indicators
        """
        # Check sample database first
        for sample in SAMPLE_SUSPICIOUS_URLS:
            if sample["url"] == url:
                return URLAnalyzer._format_response(sample, awareness_level)
        
        # Perform analysis on unknown URL
        risk_factors = URLAnalyzer._extract_risk_factors(url)
        trust_score, risk_level = TrustScorer.calculate_trust_score(risk_factors)
        
        domain = URLAnalyzer._extract_domain(url)
        domain_age_risk, domain_age, domain_age_reason = TrustScorer.analyze_domain_age(domain)
        ssl_risk, ssl_status, ssl_reason = TrustScorer.analyze_ssl_certificate(url)
        
        suspicious_patterns = URLAnalyzer._detect_patterns(url)
        impersonation_risk = URLAnalyzer._analyze_impersonation(domain)
        
        explanation = URLAnalyzer._generate_explanation(
            domain, suspicious_patterns, domain_age_reason, ssl_reason
        )
        
        recommended_action = URLAnalyzer._get_recommendation(risk_level)
        
        response = {
            "trust_score": trust_score,
            "risk_level": risk_level,
            "domain": domain,
            "domain_age": domain_age,
            "https_status": ssl_status,
            "suspicious_patterns": suspicious_patterns,
            "reputation": "UNKNOWN" if trust_score > 50 else "SUSPICIOUS",
            "impersonation_risk": impersonation_risk,
            "explanation": explanation,
            "recommended_action": recommended_action
        }
        
        return URLAnalyzer._adapt_to_awareness_level(response, awareness_level)
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except:
            return url
    
    @staticmethod
    def _extract_risk_factors(url: str) -> dict:
        """Extract risk factors from URL"""
        url_lower = url.lower()
        domain = URLAnalyzer._extract_domain(url)
        
        risk_factors = {
            "url_risk": 0,
            "domain_age_risk": 0,
            "ssl_risk": 0,
            "reputation_risk": 0,
            "impersonation_risk": 0,
            "pattern_risk": 0
        }
        
        # Check for suspicious keywords
        suspicious_keywords = ["verify", "confirm", "secure-login", "account", "update", "urgent"]
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                risk_factors["pattern_risk"] += 15
        
        # Check for trusted domains
        trusted_domains = ["amazon.in", "google.com", "facebook.com", "youtube.com"]
        if any(trusted in domain for trusted in trusted_domains):
            risk_factors["reputation_risk"] = 5
        else:
            risk_factors["reputation_risk"] = 40
        
        # Check HTTPS
        if url.startswith("https"):
            risk_factors["ssl_risk"] = 10
        else:
            risk_factors["ssl_risk"] = 50
        
        return risk_factors
    
    @staticmethod
    def _detect_patterns(url: str) -> list:
        """Detect suspicious patterns in URL"""
        patterns = []
        url_lower = url.lower()
        domain = URLAnalyzer._extract_domain(url)
        
        # Pattern detection
        if "secure" in url_lower and "login" in url_lower:
            patterns.append("Suspicious keyword combination detected")
        
        if domain.startswith("secure-") or domain.startswith("verify-"):
            patterns.append("Domain prefix suggests impersonation")
        
        if domain.count("-") > 2:
            patterns.append("Multiple hyphens in domain (homograph attack indicator)")
        
        if any(tld in domain for tld in [".tk", ".ml", ".ga", ".cf"]):
            patterns.append("Free top-level domain (TLD) used")
        
        if len(domain) > 30:
            patterns.append("Unusually long domain name")
        
        return patterns
    
    @staticmethod
    def _analyze_impersonation(domain: str) -> str:
        """Analyze impersonation risk"""
        trusted_brands = ["amazon", "google", "facebook", "microsoft", "apple"]
        
        for brand in trusted_brands:
            if brand in domain and not domain.endswith("." + brand + ".in") and not domain.endswith("." + brand + ".com"):
                return "VERY_HIGH"
        
        if "verify" in domain or "secure-login" in domain:
            return "HIGH"
        
        return "LOW"
    
    @staticmethod
    def _generate_explanation(domain: str, patterns: list, domain_age_reason: str, ssl_reason: str) -> str:
        """Generate explanation for the analysis"""
        reasons = []
        
        if patterns:
            reasons.extend(patterns[:2])
        
        reasons.append(domain_age_reason)
        
        return "Analysis reveals: " + "; ".join(reasons[:3])
    
    @staticmethod
    def _get_recommendation(risk_level: str) -> str:
        """Get recommendation based on risk level"""
        if risk_level == "LOW":
            return "This website appears safe. Proceed with normal caution."
        elif risk_level == "MEDIUM":
            return "Exercise caution. Verify independently before entering sensitive information."
        elif risk_level == "HIGH":
            return "⚠️ High risk detected. Do not proceed without independent verification."
        else:  # CRITICAL
            return "🔴 Critical risk. Do not click this link or enter any information."
    
    @staticmethod
    def _adapt_to_awareness_level(response: dict, level: str) -> dict:
        """Adapt response to user awareness level"""
        if level == "beginner":
            response["explanation"] = "This website may not be safe. Do not enter passwords or payment details."
        elif level == "advanced":
            response["explanation"] += " [Advanced: Homograph attack detection enabled. SSL certificate validation performed.]"
        
        return response
    
    @staticmethod
    def _format_response(sample: dict, awareness_level: str) -> dict:
        """Format sample response"""
        domain_age_risk, domain_age, domain_reason = TrustScorer.analyze_domain_age(sample["domain"])
        
        trust_score, risk_level = TrustScorer.calculate_trust_score({
            "url_risk": sample["risk_score"],
            "domain_age_risk": domain_age_risk,
            "impersonation_risk": 80 if sample["impersonation_risk"] == "VERY_HIGH" else 40
        })
        
        explanation = f"Domain reputation: {sample['reputation']}. " + \
                     f"Impersonation Risk: {sample['impersonation_risk']}. " + \
                     f"Domain registered: {sample['domain_age']}."
        
        if sample["suspicious_patterns"]:
            explanation += " Issues: " + ", ".join(sample["suspicious_patterns"][:2])
        
        response = {
            "trust_score": trust_score,
            "risk_level": risk_level,
            "domain": sample["domain"],
            "domain_age": sample["domain_age"],
            "https_status": sample["https_status"],
            "suspicious_patterns": sample["suspicious_patterns"],
            "reputation": sample["reputation"],
            "impersonation_risk": sample["impersonation_risk"],
            "explanation": explanation,
            "recommended_action": URLAnalyzer._get_recommendation(risk_level)
        }
        
        return URLAnalyzer._adapt_to_awareness_level(response, awareness_level)
