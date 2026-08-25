import streamlit as st
from utils.auth_db import authenticate_user

def render_login_page():
    # Cyber SOC CSS Styling
    st.markdown("""
        <style>
        .login-box {
            background: rgba(22, 27, 34, 0.85);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(56, 139, 253, 0.25);
            border-radius: 16px;
            padding: 30px;
            margin-top: 20px;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
        }
        .portal-choice-btn {
            text-align: center;
            margin-bottom: 20px;
        }
        .soc-badge {
            display: inline-block;
            background: rgba(56, 139, 253, 0.15);
            border: 1px solid rgba(56, 139, 253, 0.4);
            color: #58a6ff;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1.5px;
            border-radius: 20px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .soc-title {
            color: #f0f6fc;
            font-size: 24px;
            font-weight: 700;
            margin: 0;
        }
        .soc-subtitle {
            color: #8b949e;
            font-size: 13px;
            margin-top: 4px;
            margin-bottom: 20px;
        }
        </style>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.4, 1])
    with col2:
        st.markdown("""
            <div class="login-box">
                <span class="soc-badge">Cloud SIEM Access Gateway</span>
                <div class="soc-title">🛡️ AI Sentinel Threat Hunter</div>
                <div class="soc-subtitle">Select your authorization pathway to enter the console</div>
            </div>
        """, unsafe_allow_html=True)

        # Mode Selection: Analyst vs Admin
        portal_mode = st.radio(
            "Select Access Level:",
            options=["Security Analyst Portal", "Administrator Console"],
            horizontal=True
        )

        is_admin_mode = portal_mode == "Administrator Console"

        with st.form("auth_gateway_form"):
            st.markdown(f"#### {'⚙️ Admin Authentication' if is_admin_mode else '🔍 Analyst Authentication'}")
            
            default_user_hint = "admin" if is_admin_mode else "analyst_bob"
            username = st.text_input("Identity / Username", placeholder=f"e.g. {default_user_hint}")
            password = st.text_input("Passcode", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Authenticate Access", use_container_width=True)

            if submit:
                if not username or not password:
                    st.warning("⚠️ Please provide all credentials.")
                else:
                    success, role_or_msg = authenticate_user(username, password)
                    if success:
                        # Validate role matches chosen portal
                        if is_admin_mode and role_or_msg != "admin":
                            st.error("🛑 Access Denied: This account lacks administrative privileges.")
                        else:
                            st.session_state["authenticated"] = True
                            st.session_state["user"] = username
                            st.session_state["role"] = role_or_msg
                            st.rerun()
                    else:
                        st.error(f"🛑 {role_or_msg}")