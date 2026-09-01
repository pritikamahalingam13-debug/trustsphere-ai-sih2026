from .trust_scorer import TrustScorer
from ..data.sample_threats import SAMPLE_IDENTITIES

class IdentityAnalyzer:
    """
    Analyzes digital identity consistency and verification
    """
    
    @staticmethod
    def analyze(name: str, email: str = None, phone: str = None, 
                website: str = None, organization_id: str = None) -> dict:
        """
        Analyze identity consistency across provided fields
        """
        data = {
            "name": name,
            "email": email,
            "phone": phone,
            "website": website,
            "organization_id": organization_id
        }
        
        # Check sample database
        for sample in SAMPLE_IDENTITIES:
            if sample["name"].lower() == name.lower():
                return IdentityAnalyzer._format_response(sample)
        
        # Perform analysis
        consistency_score = TrustScorer.calculate_identity_consistency(data)
        
        verified_fields = IdentityAnalyzer._verify_fields(data)
        suspicious_mismatches = IdentityAnalyzer._detect_mismatches(data)
        
        risk_level = TrustScorer.get_risk_level(consistency_score)
        
        explanation = IdentityAnalyzer._generate_explanation(
            data, verified_fields, suspicious_mismatches
        )
        
        recommended_action = IdentityAnalyzer._get_recommendation(risk_level, suspicious_mismatches)
        
        return {
            "consistency_score": consistency_score,
            "risk_level": risk_level,
            "verified_fields": verified_fields,
            "suspicious_mismatches": suspicious_mismatches,
            "explanation": explanation,
            "recommended_action": recommended_action
        }
    
    @staticmethod
    def _verify_fields(data: dict) -> list:
        """Verify individual fields"""
        verified = []
        
        if data.get("name"):
            # Name is provided
            if len(data["name"]) > 2:
                verified.append("name")
        
        if data.get("email"):
            # Check email format
            if "@" in data["email"] and "." in data["email"].split("@")[1]:
                verified.append("email")
        
        if data.get("phone"):
            # Check phone format
            phone = data["phone"].replace("-", "").replace(" ", "")
            if phone.isdigit() and len(phone) >= 10:
                verified.append("phone")
        
        if data.get("website"):
            # Check website format
            if "http" in data["website"] and "." in data["website"]:
                verified.append("website")
        
        if data.get("organization_id"):
            if len(data["organization_id"]) > 2:
                verified.append("organization_id")
        
        return verified
    
    @staticmethod
    def _detect_mismatches(data: dict) -> list:
        """Detect suspicious mismatches between fields"""
        mismatches = []
        
        name = data.get("name", "").lower()
        email = data.get("email", "").lower()
        phone = data.get("phone", "")
        website = data.get("website", "").lower()
        
        # Check if name appears in email
        name_parts = name.split()
        if email and not any(part in email for part in name_parts):
            mismatches.append("Name does not appear in email address")
        
        # Check suspicious email patterns
        if email:
            if "suspicious" in email or "verify" in email or "confirm" in email:
                mismatches.append("Email contains suspicious keywords")
            if any(tld in email for tld in [".tk", ".ml", ".ga"]):
                mismatches.append("Email uses free/suspicious TLD")
        
        # Check phone patterns
        if phone and phone.startswith("+1") and "india" in name.lower():
            mismatches.append("Phone country code doesn't match organization location")
        
        # Check website consistency
        if website and name:
            if not any(part in website for part in name_parts[:1]):
                if "verify" in website or "secure" in website:
                    mismatches.append("Website contains suspicious verification keywords")
        
        return mismatches
    
    @staticmethod
    def _generate_explanation(data: dict, verified: list, mismatches: list) -> str:
        """Generate explanation"""
        parts = []
        
        if verified:
            parts.append(f"Verified fields: {', '.join(verified)}")
        
        if mismatches:
            parts.append(f"Detected issues: {mismatches[0]}")
        else:
            parts.append("All provided information appears consistent")
        
        return " | ".join(parts)
    
    @staticmethod
    def _get_recommendation(risk_level: str, mismatches: list) -> str:
        """Get recommendation"""
        if risk_level == "LOW" and not mismatches:
            return "Identity details appear consistent. You may proceed with normal verification."
        elif risk_level == "MEDIUM":
            return "Some inconsistencies detected. Verify through official channels before trusting."
        elif risk_level == "HIGH":
            return "⚠️ Multiple mismatches detected. Do not trust this identity without independent verification."
        else:
            return "🔴 Critical inconsistencies. This identity is likely fraudulent. Do not engage."
    
    @staticmethod
    def _format_response(sample: dict) -> dict:
        """Format sample response"""
        consistency_score = 100 - sample["risk_score"]
        risk_level = TrustScorer.get_risk_level(consistency_score)
        
        return {
            "consistency_score": consistency_score,
            "risk_level": risk_level,
            "verified_fields": [] if sample["mismatches"] else ["email", "phone", "website"],
            "suspicious_mismatches": sample["mismatches"],
            "explanation": f"Identity analysis: {', '.join(sample['mismatches'])}" if sample["mismatches"] else "Identity details are consistent",
            "recommended_action": IdentityAnalyzer._get_recommendation(risk_level, sample["mismatches"])
        }
