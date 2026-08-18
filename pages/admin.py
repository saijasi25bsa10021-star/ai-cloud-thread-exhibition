import streamlit as st
import pandas as pd
from utils.auth_db import get_all_locked_users, admin_unlock_user

st.set_page_config(page_title="Admin Console | Account Control", layout="wide")

if not st.session_state.get("authenticated", False):
    st.warning("Please log in first.")
    st.stop()

if st.session_state.get("role") != "admin":
    st.error("⛔ Access Denied: Admin privileges required to view this panel.")
    st.stop()

st.title("⚙️ SOC Admin Access Control")
st.caption("Review locked user sessions, failed authentication alerts, and manually restore user accounts.")

locked_users = get_all_locked_users()

if not locked_users:
    st.success("✅ All accounts are active. No accounts currently locked.")
else:
    st.subheader("🚨 Locked Accounts Notification")
    for u in locked_users:
        with st.container():
            c1, c2, c3, c4 = st.columns([2, 2, 3, 2])
            c1.write(f"**User:** `{u['username']}`")
            c2.write(f"**Failed Attempts:** {u['failed_attempts']}")
            c3.write(f"**Locked Until:** {u['locked_until']}")
            if c4.button("🔓 Unlock Account", key=f"unlock_{u['username']}", use_container_width=True):
                admin_unlock_user(u['username'])
                st.success(f"Account `{u['username']}` unlocked successfully!")
                st.rerun()
        st.divider()