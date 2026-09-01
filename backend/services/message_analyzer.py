from .trust_scorer import TrustScorer
from ..data.sample_threats import SAMPLE_SUSPICIOUS_MESSAGES

class MessageAnalyzer:
    """
    Analyzes messages (SMS, email, WhatsApp) for scam/phishing indicators
    """
    
    @staticmethod
    def analyze(message: str, awareness_level: str = "intermediate") -> dict:
        """
        Analyze message for threats
        """
        # Check sample database
        for sample in SAMPLE_SUSPICIOUS_MESSAGES:
            if sample["message"].lower() == message.lower():
                return MessageAnalyzer._format_response(sample, awareness_level)
        
        # Perform analysis
        urgency_detected = MessageAnalyzer._detect_urgency(message)
        threats = MessageAnalyzer._detect_threats(message)
        links = MessageAnalyzer._extract_links(message)
        payment_requests = MessageAnalyzer._detect_payment_request(message)
        impersonation_risk = MessageAnalyzer._analyze_impersonation(message)
        patterns = MessageAnalyzer._detect_patterns(message)
        
        # Calculate risk score
        risk_score = MessageAnalyzer._calculate_risk_score(
            urgency_detected, threats, links, payment_requests, patterns
        )
        
        risk_level = TrustScorer.get_risk_level(100 - risk_score)
        
        explanation = MessageAnalyzer._generate_explanation(
            message, threats, patterns, urgency_detected, awareness_level
        )
        
        recommended_action = MessageAnalyzer._get_recommendation(risk_level, threats)
        
        return {
            "risk_level": risk_level,
            "urgency_detected": urgency_detected,
            "threats": threats,
            "suspicious_links": links,
            "payment_requests": payment_requests,
            "impersonation_risk": impersonation_risk,
            "social_engineering_patterns": patterns,
            "explanation": explanation,
            "recommended_action": recommended_action
        }
    
    @staticmethod
    def _detect_urgency(message: str) -> bool:
        """Detect urgency language"""
        urgency_words = ["urgent", "immediately", "now", "today", "asap", "within 24 hours",
                        "expire", "limited time", "act now", "don't delay"]
        message_lower = message.lower()
        return any(word in message_lower for word in urgency_words)
    
    @staticmethod
    def _detect_threats(message: str) -> list:
        """Detect threat indicators"""
        threats = []
        message_lower = message.lower()
        
        # Account/security threats
        if any(phrase in message_lower for phrase in ["account", "compromised", "verify", "confirm"]):
            threats.append("Account verification request")
        
        # Credential requests
        if any(phrase in message_lower for phrase in ["password", "pin", "otp", "credentials", "details"]):
            threats.append("Credential request detected")
        
        # Time pressure
        if any(phrase in message_lower for phrase in ["urgent", "immediately", "within 24"]):
            threats.append("Artificial time pressure")
        
        # Reward/prize claims
        if any(phrase in message_lower for phrase in ["won", "prize", "reward", "claim", "congratulations"]):
            threats.append("Unsolicited reward/prize claim")
        
        # Links/actions
        if "http" in message_lower or "click" in message_lower or "link" in message_lower:
            threats.append("Suspicious link detected")
        
        return threats[:3]  # Return top 3 threats
    
    @staticmethod
    def _extract_links(message: str) -> list:
        """Extract links from message"""
        import re
        url_pattern = r'https?://[^\s]+'
        links = re.findall(url_pattern, message)
        return links
    
    @staticmethod
    def _detect_payment_request(message: str) -> bool:
        """Detect payment requests"""
        payment_words = ["pay", "rupee", "rs.", "upi", "transfer", "send", "fee", "processing fee",
                        "bank", "credit card", "debit card", "amount"]
        message_lower = message.lower()
        return sum(1 for word in payment_words if word in message_lower) >= 2
    
    @staticmethod
    def _analyze_impersonation(message: str) -> str:
        """Analyze impersonation risk"""
        brands = ["bank", "hdfc", "icici", "amazon", "google", "microsoft", "apple"]
        message_lower = message.lower()
        
        impersonation_indicators = [
            "verify", "confirm", "secure login", "update information",
            "unusual activity", "security alert"
        ]
        
        if any(brand in message_lower for brand in brands):
            if any(indicator in message_lower for indicator in impersonation_indicators):
                return "CRITICAL"
            return "HIGH"
        
        return "MEDIUM" if impersonation_indicators else "LOW"
    
    @staticmethod
    def _detect_patterns(message: str) -> list:
        """Detect social engineering patterns"""
        patterns = []
        message_lower = message.lower()
        
        # Phishing patterns
        if "verify" in message_lower and "account" in message_lower:
            patterns.append("Phishing attempt pattern")
        
        # Credential harvesting
        if "password" in message_lower or "pin" in message_lower:
            patterns.append("Credential harvesting")
        
        # Impersonation
        if any(brand in message_lower for brand in ["bank", "amazon", "google"]):
            if any(word in message_lower for word in ["verify", "confirm", "update"]):
                patterns.append("Brand impersonation")
        
        # Advance fee fraud
        if "fee" in message_lower or "process" in message_lower:
            if "prize" in message_lower or "reward" in message_lower:
                patterns.append("Advance fee fraud")
        
        # Recruitment fraud
        if "job" in message_lower or "recruit" in message_lower or "position" in message_lower:
            if "fee" in message_lower or "process" in message_lower:
                patterns.append("Recruitment fraud")
        
        return patterns
    
    @staticmethod
    def _calculate_risk_score(urgency: bool, threats: list, links: list, 
                             payment: bool, patterns: list) -> int:
        """Calculate overall risk score"""
        score = 0
        
        if urgency:
            score += 20
        
        score += len(threats) * 15
        score += len(links) * 20
        
        if payment:
            score += 25
        
        score += len(patterns) * 20
        
        return min(100, score)
    
    @staticmethod
    def _generate_explanation(message: str, threats: list, patterns: list, 
                            urgency: bool, awareness_level: str) -> str:
        """Generate explanation based on awareness level"""
        if awareness_level == "beginner":
            return "⚠️ This message appears suspicious. Be careful about clicking links or sharing information."
        
        elif awareness_level == "advanced":
            parts = []
            if threats:
                parts.append(f"Detected threats: {', '.join(threats[:2])}")
            if patterns:
                parts.append(f"Social engineering patterns: {', '.join(patterns[:2])}")
            if urgency:
                parts.append("Artificial urgency detected")
            return " | ".join(parts) if parts else "Suspicious indicators detected"
        
        else:  # intermediate
            parts = []
            if threats:
                parts.append(f"Issues: {threats[0]}")
            if patterns:
                parts.append(f"Pattern: {patterns[0]}")
            return " | ".join(parts) if parts else "Potential risks detected"
    
    @staticmethod
    def _get_recommendation(risk_level: str, threats: list) -> str:
        """Get recommendation"""
        if risk_level == "LOW":
            return "This message appears legitimate. Verify if needed."
        elif risk_level == "MEDIUM":
            return "⚠️ Exercise caution. Verify through official channels before responding."
        elif risk_level == "HIGH":
            return "⚠️ High risk. Do not click links or share information."
        else:  # CRITICAL
            return "🔴 Critical risk. Do not interact with this message. Report as spam/phishing."
    
    @staticmethod
    def _format_response(sample: dict, awareness_level: str) -> dict:
        """Format sample response"""
        risk_level = TrustScorer.get_risk_level(100 - sample["risk_score"])
        
        explanation = MessageAnalyzer._generate_explanation(
            sample["message"], sample["threats"], sample["patterns"],
            sample["urgency"], awareness_level
        )
        
        return {
            "risk_level": risk_level,
            "urgency_detected": sample["urgency"],
            "threats": sample["threats"],
            "suspicious_links": sample["links"],
            "payment_requests": sample["payment_request"],
            "impersonation_risk": sample["impersonation_risk"],
            "social_engineering_patterns": sample["patterns"],
            "explanation": explanation,
            "recommended_action": MessageAnalyzer._get_recommendation(risk_level, sample["threats"])
        }
