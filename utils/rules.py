import pandas as pd

class RuleEngine:
    """Deterministic security rules for cloud log analysis."""

    @staticmethod
    def evaluate_rules(row: pd.Series) -> list:
        threats = []

        
        if row.get('IP_Failed_Count_10m', 0) >= 5:
            threats.append({
                "type": "Brute Force Attack",
                "severity": "High",
                "rule": "RULE_01_BRUTE_FORCE",
                "details": f"Detected {row['IP_Failed_Count_10m']} failed login attempts within a 10-minute window from IP {row['IP']}."
            })

        
        if row.get('High_Risk_Action', 0) == 1 and row.get('Country') in ['Russia', 'China', 'Brazil']:
            threats.append({
                "type": "Suspicious Privilege Escalation / Deletion",
                "severity": "Critical",
                "rule": "RULE_02_GEO_PRIVILEGE",
                "details": f"Critical administrative action ({row['Action']}) executed from untrusted location ({row['Country']})."
            })

        
        if row.get('Action') == 'Login' and row.get('Status') == 'Success' and row.get('Country') in ['Russia', 'China']:
            threats.append({
                "type": "Impossible Travel / Suspicious Geo-Login",
                "severity": "High",
                "rule": "RULE_03_UNTRUSTED_GEO",
                "details": f"Successful login from high-risk origin ({row['Country']}) using IP {row['IP']}."
            })

        return threats