import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import pandas as pd
import plotly.express as px

from utils.auth_db import init_auth_db
from utils.login_view import render_login_page
from utils.generator import generate_cloud_logs
from utils.preprocessing import LogPreprocessor
from utils.detector import CloudThreatDetector

st.set_page_config(page_title="AI Cloud Threat Hunter", layout="wide", page_icon="🛡️")

# Initialize Auth Database
init_auth_db()

# Enforce Authentication Wall
if not st.session_state.get("authenticated", False):
    render_login_page()
    st.stop()

# --- TOP NAVIGATION & LOGOUT ---
col_head, col_btn = st.columns([6, 1])
with col_head:
    st.title("🛡️ AI Cloud Threat Hunter")
    st.caption(f"Logged in as: **{st.session_state.get('user', 'Unknown')}** ({st.session_state.get('role', 'user').upper()})")
with col_btn:
    if st.button("Logout", use_container_width=True):
        st.session_state["authenticated"] = False
        st.session_state["user"] = None
        st.session_state["role"] = None
        st.rerun()

# Ensure raw dataset and models exist
if not os.path.exists("dataset/cloud_logs.csv"):
    os.makedirs("dataset", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    with st.spinner("Generating initial 10,000 synthetic log records..."):
        generate_cloud_logs()

@st.cache_data
def load_and_process_data():
    df_raw = pd.read_csv("dataset/cloud_logs.csv")
    preprocessor = LogPreprocessor()
    df_proc = preprocessor.fit_transform(df_raw)
    X = preprocessor.get_feature_matrix(df_proc)
    
    detector = CloudThreatDetector(contamination=0.08)
    if not os.path.exists("models/isolation_forest.pkl"):
        detector.train(X)
    
    df_raw['Is_Anomaly'] = detector.load_and_predict(X)
    return df_raw

df = load_and_process_data()

# KPI Metric Row
total_logs = len(df)
threats_detected = int(df['Is_Anomaly'].sum())
threat_ratio = (threats_detected / total_logs) * 100 if total_logs > 0 else 0
failed_logins = int((df['Status'] == 'Failed').sum())

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Logs Processed", f"{total_logs:,}")
col2.metric("Threats Detected", f"{threats_detected:,}", delta=f"{threat_ratio:.1f}% rate", delta_color="inverse")
col3.metric("Failed Logins", f"{failed_logins:,}")
col4.metric("Active Protected Users", f"{df['Username'].nunique()}")

st.markdown("---")

# Visualizations Row
col_left, col_right = st.columns(2)
threat_df = df[df['Is_Anomaly'] == 1]

with col_left:
    st.subheader("🚨 Detected Threat Breakdown by Action")
    fig_action = px.bar(
        threat_df['Action'].value_counts().reset_index(),
        x='Action',
        y='count',
        labels={'count': 'Threat Count', 'Action': 'Cloud Action'},
        color='count',
        color_continuous_scale='Reds'
    )
    st.plotly_chart(fig_action, use_container_width=True)

with col_right:
    st.subheader("🌍 Anomalous Access Locations")
    fig_geo = px.choropleth(
        threat_df['Country'].value_counts().reset_index(),
        locations='Country',
        locationmode='country names',
        color='count',
        color_continuous_scale='OrRd',
        title="Threat Source Distribution"
    )
    st.plotly_chart(fig_geo, use_container_width=True)

st.markdown("---")

# Tabular Log Inspection
st.subheader("🔍 Identified Critical Threat Logs")
filter_user = st.multiselect("Filter by User:", options=df['Username'].unique(), default=[])

filtered_df = threat_df
if filter_user:
    filtered_df = filtered_df[filtered_df['Username'].isin(filter_user)]

st.dataframe(
    filtered_df[['LogID', 'Timestamp', 'Username', 'Action', 'IP', 'Country', 'Status']].head(100),
    use_container_width=True
)