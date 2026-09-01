from .trust_scorer import TrustScorer
from ..data.sample_threats import SAMPLE_SCAM_NETWORK, RECENT_SCANS, THREAT_STATS

class DocumentAnalyzer:
    """
    Analyzes documents for authenticity and manipulation
    """
    
    @staticmethod
    def analyze(file_content: str, filename: str) -> dict:
        """
        Analyze document for authenticity
        """
        risk_score = DocumentAnalyzer._calculate_document_risk(filename, file_content)
        trust_score = 100 - risk_score
        risk_level = TrustScorer.get_risk_level(trust_score)
        
        anomalies = DocumentAnalyzer._detect_anomalies(file_content, filename)
        modification_indicators = DocumentAnalyzer._detect_modifications(file_content)
        
        explanation = DocumentAnalyzer._generate_explanation(anomalies, modification_indicators)
        recommended_action = DocumentAnalyzer._get_recommendation(risk_level)
        
        return {
            "authenticity_score": trust_score,
            "risk_level": risk_level,
            "detected_anomalies": anomalies,
            "modification_indicators": modification_indicators,
            "explanation": explanation,
            "recommended_action": recommended_action
        }
    
    @staticmethod
    def _calculate_document_risk(filename: str, content: str) -> int:
        """Calculate document risk score"""
        risk = 0
        
        # Check file type
        if not filename:
            risk += 20
        elif filename.endswith(".pdf"):
            risk += 5  # PDFs are generally safer
        elif filename.endswith((".doc", ".docx")):
            risk += 15  # Office documents can be manipulated
        elif filename.endswith((".txt", ".csv")):
            risk += 10
        else:
            risk += 25  # Unknown format
        
        # Check content length
        if not content or len(content) < 10:
            risk += 30
        
        return min(100, risk)
    
    @staticmethod
    def _detect_anomalies(content: str, filename: str) -> list:
        """Detect anomalies in document"""
        anomalies = []
        
        # Check for suspicious patterns
        if "verify" in content.lower() and "account" in content.lower():
            anomalies.append("Document contains account verification language")
        
        if "click here" in content.lower() or "http" in content.lower():
            anomalies.append("Suspicious links or call-to-action")
        
        if "urgent" in content.lower() or "immediately" in content.lower():
            anomalies.append("Artificial urgency detected")
        
        # Check for metadata anomalies (simulated)
        if not filename:
            anomalies.append("Missing filename or metadata")
        
        return anomalies
    
    @staticmethod
    def _detect_modifications(content: str) -> list:
        """Detect modification indicators"""
        indicators = []
        
        # Check for formatting inconsistencies
        if "   " in content:  # Multiple spaces
            indicators.append("Inconsistent spacing detected")
        
        # Check for font/style anomalies (simulated)
        if content.count("\n") > 50:
            indicators.append("Unusual line break patterns")
        
        # Check for copy-paste indicators
        lines = content.split("\n")
        if len(set(lines)) < len(lines) * 0.8:
            indicators.append("Duplicate content detected")
        
        return indicators
    
    @staticmethod
    def _generate_explanation(anomalies: list, modifications: list) -> str:
        """Generate explanation"""
        if anomalies or modifications:
            issues = anomalies + modifications
            return f"Document analysis detected: {', '.join(issues[:2])}"
        return "Document appears authentic. No major anomalies detected."
    
    @staticmethod
    def _get_recommendation(risk_level: str) -> str:
        """Get recommendation"""
        if risk_level == "LOW":
            return "Document appears authentic. Safe to use."
        elif risk_level == "MEDIUM":
            return "Exercise caution. Verify document authenticity independently."
        elif risk_level == "HIGH":
            return "⚠️ High risk of manipulation. Do not rely on this document."
        else:
            return "🔴 Critical risk. Document appears fraudulent."


class TransactionAnalyzer:
    """
    Analyzes complete transaction chains for consistency
    """
    
    @staticmethod
    def analyze(message: str, website_url: str = None, upi_id: str = None, 
                organization: str = None) -> dict:
        """
        Analyze transaction chain for trust
        """
        risk_score = 0
        chain_mismatches = []
        suspicious_signals = []
        
        # Analyze message
        message_risk, message_signals = TransactionAnalyzer._analyze_message(message)
        risk_score += message_risk * 0.25
        suspicious_signals.extend(message_signals)
        
        # Analyze website
        if website_url:
            website_risk, website_signals = TransactionAnalyzer._analyze_website(website_url, organization)
            risk_score += website_risk * 0.25
            suspicious_signals.extend(website_signals)
            
            # Check message-website consistency
            mismatch = TransactionAnalyzer._check_message_website_consistency(message, website_url)
            if mismatch:
                chain_mismatches.append(mismatch)
        
        # Analyze UPI/payment
        if upi_id and organization:
            upi_risk, upi_signals = TransactionAnalyzer._analyze_upi(upi_id, organization)
            risk_score += upi_risk * 0.25
            suspicious_signals.extend(upi_signals)
            
            # Check UPI-organization consistency
            if not organization.lower() in upi_id.lower() and organization.lower() != "self":
                chain_mismatches.append("UPI ID does not match organization name")
        
        # Check payment-website consistency
        if upi_id and website_url:
            payment_risk, payment_signals = TransactionAnalyzer._analyze_payment_request(message)
            risk_score += payment_risk * 0.25
            suspicious_signals.extend(payment_signals)
        
        risk_score = min(100, risk_score)
        trust_score = 100 - int(risk_score)
        risk_level = TrustScorer.get_risk_level(trust_score)
        
        explanation = TransactionAnalyzer._generate_explanation(
            chain_mismatches, suspicious_signals
        )
        recommended_action = TransactionAnalyzer._get_recommendation(risk_level)
        
        return {
            "transaction_score": trust_score,
            "risk_level": risk_level,
            "chain_mismatches": chain_mismatches,
            "suspicious_signals": suspicious_signals,
            "explanation": explanation,
            "recommended_action": recommended_action
        }
    
    @staticmethod
    def _analyze_message(message: str) -> tuple:
        """Analyze message risk"""
        risk = 0
        signals = []
        
        message_lower = message.lower()
        
        if "urgent" in message_lower or "immediately" in message_lower:
            risk += 25
            signals.append("Urgency detected")
        
        if "verify" in message_lower or "confirm" in message_lower:
            risk += 20
            signals.append("Credential request suspected")
        
        if any(word in message_lower for word in ["click", "link", "http"]):
            risk += 15
            signals.append("Suspicious link")
        
        return min(100, risk), signals
    
    @staticmethod
    def _analyze_website(url: str, organization: str) -> tuple:
        """Analyze website risk"""
        risk = 0
        signals = []
        
        url_lower = url.lower()
        
        if "verify" in url_lower or "secure" in url_lower:
            risk += 30
            signals.append("Suspicious website pattern")
        
        if organization and organization.lower() not in url_lower:
            risk += 20
            signals.append("Website domain mismatch")
        
        if not url.startswith("https"):
            risk += 25
            signals.append("No HTTPS protection")
        
        return min(100, risk), signals
    
    @staticmethod
    def _analyze_upi(upi_id: str, organization: str) -> tuple:
        """Analyze UPI/payment ID risk"""
        risk = 0
        signals = []
        
        upi_lower = upi_id.lower()
        org_lower = organization.lower()
        
        if not organization.lower() in upi_lower:
            risk += 40
            signals.append("UPI ID does not match organization")
        
        if "okhdfcbank" in upi_lower or "okaxis" in upi_lower:
            risk += 30
            signals.append("Personal UPI ID used (not business)")
        
        if any(word in upi_lower for word in ["temporary", "test", "demo"]):
            risk += 25
            signals.append("Temporary payment ID")
        
        return min(100, risk), signals
    
    @staticmethod
    def _analyze_payment_request(message: str) -> tuple:
        """Analyze payment request risk"""
        risk = 0
        signals = []
        
        message_lower = message.lower()
        
        if any(word in message_lower for word in ["pay", "rupee", "rs.", "amount"]):
            risk += 20
            signals.append("Payment request detected")
        
        if "upi" in message_lower or "transfer" in message_lower:
            risk += 15
            signals.append("Digital payment method requested")
        
        return risk, signals
    
    @staticmethod
    def _check_message_website_consistency(message: str, website: str) -> str:
        """Check if message and website are consistent"""
        message_lower = message.lower()
        website_lower = website.lower()
        
        # Extract domain from website
        from urllib.parse import urlparse
        try:
            domain = urlparse(website).netloc
        except:
            domain = website
        
        # Check if domain appears in message
        if domain not in message_lower:
            return "Message and website domain do not match"
        
        return None
    
    @staticmethod
    def _generate_explanation(mismatches: list, signals: list) -> str:
        """Generate explanation"""
        parts = []
        
        if mismatches:
            parts.append(f"Issues: {mismatches[0]}")
        
        if signals:
            parts.append(f"Signals: {', '.join(signals[:2])}")
        
        return " | ".join(parts) if parts else "Transaction chain analysis complete"
    
    @staticmethod
    def _get_recommendation(risk_level: str) -> str:
        """Get recommendation"""
        if risk_level == "LOW":
            return "Transaction appears legitimate. Proceed with normal verification."
        elif risk_level == "MEDIUM":
            return "⚠️ Exercise caution. Verify all details independently."
        elif risk_level == "HIGH":
            return "⚠️ High risk detected. Do not proceed without verification."
        else:
            return "🔴 Critical risk. Do not complete this transaction."
