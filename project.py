from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64
import streamlit as st


# Constants
KEYS_FOLDER = "asymmetric_keys"

# Ensure the keys folder exists
if not os.path.exists(KEYS_FOLDER):
    os.makedirs(KEYS_FOLDER) 
# AES Helper Functions
def generate_aes_key():
    """Generates a random AES key and IV."""
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV
    return aes_key, iv

def generate_rsa_key_pair():
    """Generates an RSA key pair (private and public keys)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Change this to 3072 or 4096 for larger keys if needed
    )
    public_key = private_key.public_key()
    return private_key, public_key

def aes_encrypt(aes_key, iv, plaintext):
    """Encrypts the plaintext using AES (CBC mode)."""
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_decrypt(aes_key, iv, ciphertext):
    """Decrypts the ciphertext using AES (CBC mode)."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

# Hybrid Encryption Functions
def hybrid_encrypt(public_key, plaintext):
    """Encrypts a message using hybrid encryption (RSA + AES)."""
    aes_key, iv = generate_aes_key()
    encrypted_message = aes_encrypt(aes_key, iv, plaintext)
    
    # Encrypt AES key with RSA public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


    return base64.b64encode(iv + encrypted_key + encrypted_message).decode()

def load_public_key_from_file(uploaded_file):
    """Loads an RSA public key from an uploaded PEM file."""
    key_data = uploaded_file.getvalue()  # Get the file content as bytes
    public_key = serialization.load_pem_public_key(
        key_data,
        backend=default_backend(),
    )
    return public_key
def load_key_from_file(uploaded_file):
    """Loads an RSA private key from an uploaded PEM file."""
    key_data = uploaded_file.getvalue()  # Get the file content as bytes
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,  # Add a password here if the private key is encrypted
        backend=default_backend(),
    )
    return private_key
 
def save_keys_to_file(user_id, private_key, public_key):
    """Saves the RSA key pair to files."""
    private_key_file = os.path.join(KEYS_FOLDER, f"{user_id}_private_key.pem")
    public_key_file = os.path.join(KEYS_FOLDER, f"{user_id}_public_key.pem")

    with open(private_key_file, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(public_key_file, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key_file, public_key_file


def hybrid_decrypt(private_key, encrypted_data):
    """Decrypts a message using hybrid decryption (RSA + AES)."""
    encrypted_data = base64.b64decode(encrypted_data)
    
    # Extract IV, encrypted AES key, and encrypted message
    iv = encrypted_data[:16]
    encrypted_key = encrypted_data[16:16 + private_key.key_size // 8]
    encrypted_message = encrypted_data[16 + private_key.key_size // 8:]
    
    # Decrypt AES key with RSA private key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    
    # Decrypt the message with AES
    return aes_decrypt(aes_key, iv, encrypted_message)


# Streamlit Integration
st.title("Hybrid Encryption and Decryption")

user_id = st.text_input("Enter your User ID:", placeholder="E.g., user1")

if user_id:
    key_choice = st.radio("Choose a key option:", ["Generate Key Pair", "Use Existing Keys"])

    if key_choice == "Generate Key Pair":
        private_key, public_key = generate_rsa_key_pair()
        priv_path, pub_path = save_keys_to_file(user_id, private_key, public_key)
        st.success(f"Key pair generated and saved:\nPrivate Key: {priv_path}\nPublic Key: {pub_path}")

    elif key_choice == "Use Existing Keys":
        private_key_file = st.file_uploader("Upload your private key (PEM format):", type="pem")
        public_key_file = st.file_uploader("Upload the public key (PEM format):", type="pem")

        private_key = load_key_from_file(private_key_file) if private_key_file else None
        public_key = load_key_from_file(public_key_file) if public_key_file else None

    user_action = st.radio("Choose an action:", ["Encrypt", "Decrypt"])

    if user_action == "Encrypt":
        if public_key:
            plain_text = st.text_area("Enter the message to encrypt:")
            if plain_text:
                encrypted_message = hybrid_encrypt(public_key, plain_text)
                st.write("**Encrypted Message (Base64):**")
                st.code(encrypted_message, language="plaintext")
        else:
            st.warning("Please upload or generate a public key.")

    elif user_action == "Decrypt":
        if private_key:
            encrypted_text = st.text_area("Enter the encrypted message (Base64):")
            if encrypted_text:
                try:
                    decrypted_message = hybrid_decrypt(private_key, encrypted_text)
                    st.write("**Decrypted Message:**")
                    st.code(decrypted_message, language="plaintext")
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
        else:
            st.warning("Please upload or generate a private key.")
else:
    st.write("Please enter your User ID to proceed.")
