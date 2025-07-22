import streamlit as st
from cryptography.fernet import Fernet

st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒", layout="centered")
st.title("🔒 Secure Data Encryption / Decryption System")

# Generate or use static key
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

fernet = Fernet(st.session_state.fernet_key)

mode = st.sidebar.radio("Select Mode", ("Encrypt Text", "Decrypt Text"))

if mode == "Encrypt Text":
    st.header("🔐 Encrypt your data")
    plain_text = st.text_area("Enter text to encrypt:")

    if st.button("Encrypt"):
        if not plain_text.strip():
            st.warning("Please enter some text to encrypt!")
        else:
            encrypted = fernet.encrypt(plain_text.encode())
            st.success("Encryption successful!")
            st.code(encrypted.decode())

            st.download_button(
                label="💾 Download Encrypted Data",
                data=encrypted,
                file_name="encrypted_data.txt",
                mime="text/plain"
            )

elif mode == "Decrypt Text":
    st.header("🔑 Decrypt your data")
    uploaded_file = st.file_uploader("Upload the encrypted file", type=["txt"])

    if uploaded_file:
        encrypted_data = uploaded_file.read()

        try:
            decrypted = fernet.decrypt(encrypted_data)
            st.success("Decryption successful!")
            st.code(decrypted.decode())
        except Exception as e:
            st.error("Decryption failed. Are you sure you used the correct key?")
