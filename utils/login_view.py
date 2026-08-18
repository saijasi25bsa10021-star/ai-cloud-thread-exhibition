import streamlit as st
from utils.auth_db import authenticate_user

def render_login_page():
    # Inject Custom CSS Styling
    st.markdown("""
        <style>
            .login-card {
                background-color: #161b22;
                padding: 30px;
                border-radius: 12px;
                border: 1px solid #30363d;
                max-width: 450px;
                margin: auto;
                box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            }
            .login-header {
                text-align: center;
                color: #58a6ff;
                font-family: 'Segoe UI', sans-serif;
            }
            .sub-text {
                text-align: center;
                color: #8b949e;
                font-size: 14px;
                margin-bottom: 20px;
            }
        </style>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown('<div class="login-card"><h2 class="login-header">🛡️ SOC Portal Login</h2><p class="sub-text">AI Cloud Threat Hunter Access</p></div>', unsafe_allow_html=True)
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="e.g. admin or analyst_bob")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Authenticate", use_container_width=True)
            
            if submit:
                if not username or not password:
                    st.warning("Please provide both username and password.")
                else:
                    success, message = authenticate_user(username, password)
                    if success:
                        st.session_state["authenticated"] = True
                        st.session_state["user"] = username
                        st.session_state["role"] = message
                        st.success("Authentication successful! Loading portal...")
                        st.rerun()
                    else:
                        st.error(message)