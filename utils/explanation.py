import pandas as pd

class ThreatExplainer:
    """Generates structured threat narratives and automated recommendations."""

    @staticmethod
    def generate_explanation(row: pd.Series, rule_threats: list = None) -> dict:
        is_ml_anomaly = row.get('Is_Anomaly', 0) == 1
        has_rules = rule_threats and len(rule_threats) > 0

        
        if has_rules:
            primary_threat = rule_threats[0]['type']
            severity = rule_threats[0]['severity']
            reason = rule_threats[0]['details']
        elif is_ml_anomaly:
            primary_threat = "Unusual Behavior Anomaly (ML Flagged)"
            severity = "Medium"
            reason = (
                f"User '{row['Username']}' performed '{row['Action']}' from {row['Country']} ({row['IP']}). "
                "This behavior strays significantly from normal user activity baselines."
            )
        else:
            return {
                "is_threat": False,
                "threat_name": "Normal Traffic",
                "severity": "Low",
                "reason": "Activity aligns with normal baseline patterns.",
                "recommendation": "No action required."
            }

        if severity == "Critical":
            recommendation = (
                "🚨 **IMMEDIATE ACTION REQUIRED:**\n"
                "1. Temporarily revoke IAM credentials for this user.\n"
                "2. Terminate all active sessions.\n"
                "3. Block incoming traffic from IP in AWS Security Groups / WAF."
            )
        elif severity == "High":
            recommendation = (
                "⚠️ **HIGH PRIORITY:**\n"
                "1. Enforce Multi-Factor Authentication (MFA) reset.\n"
                "2. Add IP address to temporary blocklist.\n"
                "3. Audit recent API requests from this user."
            )
        else:
            recommendation = (
                "ℹ️ **RECOMMENDED AUDIT:**\n"
                "1. Notify user to confirm if action was authorized.\n"
                "2. Monitor account for additional anomaly events over the next 24 hours."
            )

        return {
            "is_threat": True,
            "threat_name": primary_threat,
            "severity": severity,
            "reason": reason,
            "recommendation": recommendation
        }