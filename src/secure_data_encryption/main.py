import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import time

# ---------------------------- Session State Setup ----------------------------

if "vault" not in st.session_state:
    st.session_state.vault = {}

if "current_view" not in st.session_state:
    st.session_state.current_view = "dashboard"

if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = {}

if "is_verified" not in st.session_state:
    st.session_state.is_verified = False

if "post_login_redirect" not in st.session_state:
    st.session_state.post_login_redirect = False

# ---------------------------- Helper Functions ----------------------------

def compute_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def encrypt_message(message: str, user_key: str) -> tuple[str, str]:
    encryption_key = Fernet.generate_key()
    cipher = Fernet(encryption_key)
    encrypted_msg = cipher.encrypt(message.encode())
    return encrypted_msg.decode(), encryption_key.decode()

def decrypt_message(token: str, key: str) -> str:
    cipher = Fernet(key.encode())
    return cipher.decrypt(token.encode()).decode()

def navigate(view: str):
    st.session_state.current_view = view
    st.rerun()

# ---------------------------- Views ----------------------------

def dashboard():
    st.title("🛡️ Secure Message Vault")
    st.write("Choose an action to proceed:")

    if st.button("📝 Save a Message"):
        navigate("save")

    if st.button("🔐 Access Stored Message"):
        navigate("access")

def save_message():
    st.title("📝 Save a Message Securely")

    entry_id = st.text_input("Unique Identifier:")
    plain_text = st.text_area("Message to Encrypt:")
    secret_key = st.text_input("Create a Passkey:", type="password")

    if st.button("Save"):
        if not entry_id or not plain_text or not secret_key:
            st.warning("All fields must be filled.")
        elif entry_id in st.session_state.vault:
            st.error("Identifier already used!")
        else:
            encrypted_data, gen_key = encrypt_message(plain_text, secret_key)
            st.session_state.vault[entry_id] = {
                "cipher": encrypted_data,
                "key": gen_key,
                "hashed_key": compute_hash(secret_key)
            }
            st.success("Message securely saved!")

    if st.button("🔙 Return"):
        navigate("dashboard")

def access_message():
    st.title("🔐 Access Your Encrypted Message")

    entry_id = st.text_input("Enter Identifier:")
    user_key = st.text_input("Enter Passkey:", type="password")

    if entry_id not in st.session_state.vault:
        if st.button("Access"):
            st.error("No message found with this identifier.")
        return

    if st.session_state.login_attempts.get(entry_id, 0) >= 3 and not st.session_state.is_verified:
        navigate("verify")
        return

    if st.button("Access"):
        saved_record = st.session_state.vault[entry_id]
        if compute_hash(user_key) == saved_record["hashed_key"]:
            decrypted_msg = decrypt_message(saved_record["cipher"], saved_record["key"])
            st.success("Message Decrypted:")
            st.code(decrypted_msg)
            st.session_state.login_attempts[entry_id] = 0
        else:
            st.session_state.login_attempts[entry_id] = st.session_state.login_attempts.get(entry_id, 0) + 1
            count = st.session_state.login_attempts[entry_id]
            if count >= 3:
                st.error("Too many wrong attempts. Verification needed.")
                navigate("verify")
            else:
                st.error(f"Wrong passkey. Attempt {count}/3.")

    if st.button("🔙 Return"):
        navigate("dashboard")

def login_verification():
    st.title("🔐 Admin Verification Required")
    st.warning("Multiple failed attempts detected. Re-authentication is required.")

    admin_user = st.text_input("Username")
    admin_pass = st.text_input("Password", type="password")

    if st.button("Verify"):
        if admin_user == "admin" and admin_pass == "admin123":
            st.success("Verification successful.")
            st.session_state.is_verified = True
            st.session_state.post_login_redirect = True
            time.sleep(1)
            navigate("access")
        else:
            st.error("Incorrect login credentials.")

# ---------------------------- Auto Redirect ----------------------------

if st.session_state.post_login_redirect:
    st.session_state.post_login_redirect = False
    navigate("access")

# ---------------------------- View Router ----------------------------

page = st.session_state.current_view

if page == "dashboard":
    dashboard()
elif page == "save":
    save_message()
elif page == "access":
    if not st.session_state.is_verified and any(x >= 3 for x in st.session_state.login_attempts.values()):
        navigate("verify")
    else:
        access_message()
elif page == "verify":
    login_verification()
