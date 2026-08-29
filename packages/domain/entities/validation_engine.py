import re
from urllib.parse import urlparse

class IntelligenceValidator:
    @staticmethod
    def validate_upi_id(upi: str) -> dict:
        """
        Validates UPI ID structure and provider.
        Returns {"valid": bool, "confidence": float, "reason": str}
        """
        # Basic pattern: name@bank
        if not re.match(r"^[a-zA-Z0-9._-]+@[a-zA-Z]{2,}$", upi):
             return {"valid": False, "confidence": 0.0, "reason": "Invalid format"}
             
        # Check common banks
        handle = upi.split('@')[1].lower()
        common_handles = ['okaxis', 'okhdfc', 'oksbi', 'okicici', 'paytm', 'ybl', 'ibl', 'axl', 'icici', 'sbi']
        
        if handle in common_handles:
             return {"valid": True, "confidence": 0.95, "reason": "Valid format and known bank handle"}
             
        return {"valid": True, "confidence": 0.7, "reason": "Valid format but unknown bank handle"}

    @staticmethod
    def validate_phone(phone: str) -> dict:
        """
        Validates Indian phone numbers.
        """
        # Remove +91 or 0
        clean_phone = re.sub(r"^(?:\+91|91|0)", "", phone)
        
        if not re.match(r"^[6-9]\d{9}$", clean_phone):
             return {"valid": False, "confidence": 0.0, "reason": "Invalid Indian mobile format"}
             
        # Check for repeating digits (e.g. 9999999999 - often fake)
        if len(set(clean_phone)) == 1:
             return {"valid": False, "confidence": 0.1, "reason": "Suspicious repeating digits"}
             
        return {"valid": True, "confidence": 0.9, "reason": "Valid Indian mobile format"}

    @staticmethod
    def validate_bank_account(account: str) -> dict:
        """
        Validates bank account numbers.
        """
        if not re.match(r"^\d{9,18}$", account):
            return {"valid": False, "confidence": 0.0, "reason": "Invalid length"}
            
        return {"valid": True, "confidence": 0.8, "reason": "Valid account number format"}

    @staticmethod
    def validate_url(url: str) -> dict:
        """
        Validates suspicious URLs.
        """
        # A non-URL scores 0 risk and used to come back valid; anything without
        # a dotted host is rejected before the heuristics run.
        host = urlparse(url if "://" in url else f"http://{url}").netloc
        if "." not in host.split(":")[0].strip("."):
            return {"valid": False, "confidence": 0.0, "reason": "Not a URL"}

        risk_score = 0
        reasons = []

        # Check IP address
        if re.search(r"://\d+\.\d+\.\d+\.\d+", url):
            risk_score += 0.4
            reasons.append("IP address usage")
            
        # Check risky TLDs
        if re.search(r"\.(xyz|tk|ml|ga|cf|gq|top|buzz|cc)$", url, re.IGNORECASE):
            risk_score += 0.3
            reasons.append("Risky TLD")
            
        # Check for credential keywords
        if re.search(r"bank|verify|update|secure|login", url, re.IGNORECASE):
            risk_score += 0.2
            reasons.append("Phishing keywords in URL")
            
        # Check for bit.ly/shorteners
        if re.search(r"bit\.ly|tinyurl|is\.gd", url, re.IGNORECASE):
            risk_score += 0.1
            reasons.append("URL shortener used")

        confidence = min(0.5 + risk_score, 1.0)
        
        # If it matches known phishing patterns, high confidence
        if risk_score > 0:
             return {"valid": True, "confidence": confidence, "reason": ", ".join(reasons)}
             
        return {"valid": True, "confidence": 0.5, "reason": "URL detected but no specific phishing indicators"}
