import streamlit as st
import pandas as pd
import os

from utils.preprocessing import LogPreprocessor
from utils.detector import CloudThreatDetector
from utils.rules import RuleEngine
from utils.explanation import ThreatExplainer

st.set_page_config(page_title="Threat Alerts | AI Cloud Threat Hunter", layout="wide", page_icon="🚨")

# Block access if unauthenticated
if not st.session_state.get("authenticated", False):
    st.warning("⚠️ Please authenticate on the main portal before accessing alert streams.")
    st.stop()

st.title("🚨 Critical Threat Alerts & SOC Analysis")
st.caption(f"Operator: **{st.session_state.get('user')}** | Access Tier: **{st.session_state.get('role').upper()}**")

if not os.path.exists("dataset/cloud_logs.csv"):
    st.warning("Main telemetry data initializing. Please visit the dashboard first.")
    st.stop()

@st.cache_data
def load_analyzed_data():
    df_raw = pd.read_csv("dataset/cloud_logs.csv")
    preprocessor = LogPreprocessor()
    df_proc = preprocessor.fit_transform(df_raw)
    X = preprocessor.get_feature_matrix(df_proc)

    detector = CloudThreatDetector()
    df_proc['Is_Anomaly'] = detector.load_and_predict(X)
    return df_proc

df = load_analyzed_data()

# Evaluate threats
alerts_list = []
for idx, row in df.iterrows():
    rule_threats = RuleEngine.evaluate_rules(row)
    if row['Is_Anomaly'] == 1 or len(rule_threats) > 0:
        explanation = ThreatExplainer.generate_explanation(row, rule_threats)
        alerts_list.append({
            "LogID": row['LogID'],
            "Timestamp": row['Timestamp'],
            "Username": row['Username'],
            "Action": row['Action'],
            "IP": row['IP'],
            "Country": row['Country'],
            "Threat": explanation['threat_name'],
            "Severity": explanation['severity'],
            "Reason": explanation['reason'],
            "Recommendation": explanation['recommendation']
        })

alerts_df = pd.DataFrame(alerts_list)

severity_filter = st.sidebar.multiselect(
    "Filter Severity:", 
    options=["Critical", "High", "Medium"], 
    default=["Critical", "High"]
)

filtered_alerts = alerts_df[alerts_df['Severity'].isin(severity_filter)] if severity_filter else alerts_df

st.subheader(f"Showing {len(filtered_alerts)} Active Security Alerts")

for _, alert in filtered_alerts.head(20).iterrows():
    severity_color = "🔴" if alert['Severity'] == "Critical" else ("🟠" if alert['Severity'] == "High" else "🟡")
    
    with st.expander(f"{severity_color} Alert #{alert['LogID']} - {alert['Threat']} ({alert['Severity']})"):
        c1, c2, c3, c4 = st.columns(4)
        c1.write(f"**User:** `{alert['Username']}`")
        c2.write(f"**Action:** `{alert['Action']}`")
        c3.write(f"**IP:** `{alert['IP']}`")
        c4.write(f"**Country:** {alert['Country']}")
        
        st.markdown(f"**Timestamp:** `{alert['Timestamp']}`")
        st.markdown(f"**📝 AI Threat Narrative:**\n{alert['Reason']}")
        st.info(alert['Recommendation'])