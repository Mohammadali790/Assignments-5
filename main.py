import streamlit as st
from cryptography.fernet import Fernet
import hashlib

stored_data = {}
max_attempts = 3

if 'login_status' not in st.session_state:
    st.session_state.login_status = True
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
if 'fernet' not in st.session_state:
    st.session_state.fernet = Fernet(st.session_state.key)

fernet = st.session_state.fernet

# ---------- Helper Functions ----------
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()

def show_login():
    st.title("🔒 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.success("Reauthorized successfully.")
            st.session_state.attempts = 0
            st.session_state.login_status = True
        else:
            st.error("Incorrect credentials.")

# ---------- Pages ----------
def home_page():
    st.title("🔐 Secure Data Storage")
    st.write("Choose an option below:")
    st.button("Insert Data", on_click=lambda: st.session_state.update(page="insert"))
    st.button("Retrieve Data", on_click=lambda: st.session_state.update(page="retrieve"))

def insert_data():
    st.title("📥 Store Your Data Securely")
    user_key = st.text_input("Enter a unique name for your data:")
    text = st.text_area("Enter text to store:")
    passkey = st.text_input("Create a passkey:", type='password')

    if st.button("Store"):
        if user_key in stored_data:
            st.warning("That key already exists. Use a different name.")
        else:
            hashed_key = hash_passkey(passkey)
            encrypted_text = encrypt_text(text)
            stored_data[user_key] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_key
            }
            st.success("Data stored securely!")

def retrieve_data():
    st.title("📤 Retrieve Your Data")

    if st.session_state.attempts >= max_attempts:
        st.session_state.login_status = False
        return

    user_key = st.text_input("Enter your data name:")
    passkey = st.text_input("Enter your passkey:", type='password')

    if st.button("Retrieve"):
        if user_key in stored_data:
            stored_entry = stored_data[user_key]
            hashed_input = hash_passkey(passkey)
            if hashed_input == stored_entry["passkey"]:
                decrypted_text = decrypt_text(stored_entry["encrypted_text"])
                st.success("Data retrieved successfully:")
                st.code(decrypted_text)
                st.session_state.attempts = 0  # reset on success
            else:
                st.session_state.attempts += 1
                st.error(f"Incorrect passkey. Attempts left: {max_attempts - st.session_state.attempts}")
        else:
            st.warning("Data not found.")

def run_app():
    if not st.session_state.login_status:
        show_login()
        return

    if 'page' not in st.session_state:
        st.session_state.page = 'home'

    if st.session_state.page == 'home':
        home_page()
    elif st.session_state.page == 'insert':
        insert_data()
        if st.button("⬅ Back to Home"):
            st.session_state.page = 'home'
    elif st.session_state.page == 'retrieve':
        retrieve_data()
        if st.button("⬅ Back to Home"):
            st.session_state.page = 'home'

run_app()
