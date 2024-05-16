import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


# Function to encrypt messages using the provided public key (RSA)
def encrypt_message_rsa(public_key, message):
    try:
        key_size = public_key.size_in_bytes()
        max_chunk_size = key_size - 42
        chunks = [
            message[i : i + max_chunk_size]
            for i in range(0, len(message), max_chunk_size)
        ]
        encrypted_chunks = []
        cipher = PKCS1_OAEP.new(public_key)
        for chunk in chunks:
            encrypted_chunk = cipher.encrypt(chunk.encode())
            encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode())
        delimiter = "|"
        encrypted_message = delimiter.join(encrypted_chunks)
        return True, encrypted_message
    except Exception as e:
        return False, str(e)


# Function to decrypt messages using the provided private key (RSA)
def decrypt_message_rsa(private_key, encrypted_message):
    try:
        cipher = PKCS1_OAEP.new(private_key)
        encrypted_chunks = encrypted_message.split("|")
        decrypted_chunks = []
        for chunk in encrypted_chunks:
            decrypted_chunk = cipher.decrypt(base64.b64decode(chunk))
            decrypted_chunks.append(decrypted_chunk)
        decrypted_message = b"".join(decrypted_chunks)
        return True, decrypted_message.decode()
    except Exception as e:
        return False, str(e)


# Function to generate RSA keys
def generate_rsa_keys(key_size=2048):
    try:
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return True, private_key, public_key
    except Exception as e:
        return False, str(e), None


# Generate AES Key and IV
def generate_aes_key_iv(key_size=256):
    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(AES.block_size)
    return key, iv


# AES Encryption
def aes_encrypt(key, iv, message):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        encrypted_message = base64.b64encode(ct_bytes).decode()
        return True, encrypted_message
    except Exception as e:
        return False, str(e)


# AES Decryption
def aes_decrypt(key, iv, encrypted_message):
    try:
        ct = base64.b64decode(encrypted_message)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return True, pt.decode()
    except Exception as e:
        return False, str(e)


# Helper function for message input
def get_message_from_user(input_type, file_uploader_key, text_area_key):
    if input_type == "Type":
        message = st.text_area("Type your message here:", key=text_area_key)
        return message.encode("utf-8") if message else None
    elif input_type == "Upload":
        uploaded_file = st.file_uploader(
            "Or upload a .txt file:", type=["txt"], key=file_uploader_key
        )
        if uploaded_file is not None:
            return uploaded_file.getvalue()
    return None


# Streamlit UI
st.sidebar.title("Navigation")
app_mode = st.sidebar.selectbox(
    "Choose the app mode",
    [
        "Home",
        "Generate RSA Keys",
        "RSA Encrypt Message",
        "RSA Decrypt Message",
        "AES Encryption",
        "AES Decryption",
    ],
)

if app_mode == "Home":
    st.title("RSA & AES Encryption/Decryption App")
    st.write(
        "Welcome to the RSA & AES Encryption/Decryption App. Please select an option from the navigation bar to start."
    )

elif app_mode == "Generate RSA Keys":
    st.title("Generate RSA Keys")
    key_size_option = st.selectbox("Select Key Size", [2048, 3072, 4096], index=0)
    if st.button("Generate Keys"):
        with st.spinner("Generating RSA Keys..."):
            success, private_key, public_key = generate_rsa_keys(
                key_size=key_size_option
            )
        if success:
            st.success("Keys generated successfully!")
            st.text_area("Public Key", public_key.decode("utf-8"), height=250)
            st.download_button(
                "Download Public Key", public_key, "public_key.pem", "text/plain"
            )
            st.text_area("Private Key", private_key.decode("utf-8"), height=250)
            st.download_button(
                "Download Private Key", private_key, "private_key.pem", "text/plain"
            )
            st.warning(
                "Remember to store your private key in a secure location. It is crucial for decrypting your messages and must be kept confidential."
            )
        else:
            st.error("Failed to generate keys.")

elif app_mode in ["RSA Encrypt Message", "RSA Decrypt Message"]:
    pub_key = (
        st.file_uploader("Upload RSA Public Key", type=["pem"])
        if app_mode == "RSA Encrypt Message"
        else None
    )
    priv_key = (
        st.file_uploader("Upload RSA Private Key", type=["pem"])
        if app_mode == "RSA Decrypt Message"
        else None
    )
    input_type = st.radio("Message input method:", ("Type", "Upload"), index=0)
    message = get_message_from_user(input_type, "file_uploader", "text_area")

    if message:
        if app_mode == "RSA Encrypt Message" and pub_key:
            public_key = RSA.import_key(pub_key.getvalue())
            success, result = encrypt_message_rsa(public_key, message.decode("utf-8"))
        elif app_mode == "RSA Decrypt Message" and priv_key:
            private_key = RSA.import_key(priv_key.getvalue())
            success, result = decrypt_message_rsa(private_key, message.decode("utf-8"))
        else:
            success, result = False, "Required key not provided."

        if success:
            st.text_area("Result", result, height=100)
            st.download_button("Download Result", result, "result.txt", "text/plain")
        else:
            st.error(f"Operation failed: {result}")

elif app_mode == "AES Encryption":
    st.title("AES Encryption")
    key_size_option = st.selectbox("Select AES Key Size", [128, 192, 256], index=2)
    if st.button("Generate AES Key and IV"):
        key, iv = generate_aes_key_iv(key_size=key_size_option)
        st.session_state["aes_key"] = key
        st.session_state["aes_iv"] = iv
        st.text_area("AES Key (Base64)", base64.b64encode(key).decode(), height=100)
        st.text_area("AES IV (Base64)", base64.b64encode(iv).decode(), height=100)

    message = st.text_area("Type your message here for AES encryption:")
    if message and st.button("Encrypt with AES"):
        if "aes_key" in st.session_state and "aes_iv" in st.session_state:
            success, encrypted_message = aes_encrypt(
                st.session_state["aes_key"], st.session_state["aes_iv"], message
            )
            if success:
                st.text_area("Encrypted Message", encrypted_message, height=100)
                st.download_button(
                    "Download Encrypted Message",
                    encrypted_message,
                    "encrypted_message.txt",
                    "text/plain",
                )
            else:
                st.error(f"Encryption failed: {encrypted_message}")
        else:
            st.error("AES Key and IV are required for encryption.")

elif app_mode == "AES Decryption":
    st.title("AES Decryption")
    aes_key = st.text_input("Enter AES Key (Base64):")
    aes_iv = st.text_input("Enter AES IV (Base64):")
    encrypted_message = st.text_area("Enter the encrypted message:")
    if st.button("Decrypt with AES"):
        try:
            key = base64.b64decode(aes_key)
            iv = base64.b64decode(aes_iv)
            success, decrypted_message = aes_decrypt(key, iv, encrypted_message)
            if success:
                st.text_area("Decrypted Message", decrypted_message, height=100)
                st.download_button(
                    "Download Decrypted Message",
                    decrypted_message,
                    "decrypted_message.txt",
                    "text/plain",
                )
            else:
                st.error(f"Decryption failed: {decrypted_message}")
        except Exception as e:
            st.error(f"Error: {str(e)}")
