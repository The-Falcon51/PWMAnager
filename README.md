# PWMAnager

import os
import hashlib
import requests
from cryptography.fernet import Fernet
import logging
import base64

# Set up basic logging
logging.basicConfig(level=logging.INFO, 
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler()])

# Read critical configurations from environment variables
# Ensure that API keys and secrets are set in the environment and not hard-coded!
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
# The encryption key for Fernet should be kept secret!
FERNET_KEY = os.getenv("FERNET_KEY")  
if not FERNET_KEY:
    # Generate a new key (In production, generate and keep it in secure storage)
    FERNET_KEY = Fernet.generate_key().decode()
    logging.info("No FERNET_KEY found in env, generated a new one. Save this securely!")
cipher = Fernet(FERNET_KEY.encode())

# SECURITY: Ensure a high iteration count and sufficient randomness for salted hashing.
def hash_password(password: str) -> bytes:
    """Hash a password using PBKDF2-HMAC-SHA512 with a random salt."""
    salt = os.urandom(32)  # Generate a 32-byte salt
    # 100,000 rounds is a common default; adjust as needed.
    key = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 100000)
    # Store salt and the hash; use base64 encoding for storage-friendly format.
    return base64.b64encode(salt + key)

def verify_password(stored_hash: bytes, password: str) -> bool:
    """Verify an input password against the stored base64-encoded salt+hash."""
    stored_hash = base64.b64decode(stored_hash)
    salt = stored_hash[:32]
    stored_key = stored_hash[32:]
    new_key = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 100000)
    return new_key == stored_key

def encrypt_password(hashed_password: bytes) -> bytes:
    """Encrypt the hashed password using AES-256 (Fernet)."""
    return cipher.encrypt(hashed_password)

def decrypt_password(encrypted_hash: bytes) -> bytes:
    """Decrypt the stored encrypted hash."""
    return cipher.decrypt(encrypted_hash)

def check_password_leak(password: str) -> bool:
    """
    Check if the given password was compromised by querying 
    the Have I Been Pwned API using a k-Anonymity model.
    """
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        response = requests.get(f"{HIBP_API_URL}{prefix}", timeout=10)
        if response.status_code != 200:
            logging.error("Error querying HIBP API.")
            return False
        # Compare the suffix against the returned list
        leaks = response.text.splitlines()
        for line in leaks:
            leaked_suffix, count = line.split(":")
            if leaked_suffix.strip() == suffix:
                logging.warning(f"Password compromised {count} times!")
                return True
        return False
    except Exception as e:
        logging.error(f"Error during leak check: {e}")
        return False

def store_password(service: str, plain_password: str) -> dict:
    """
    In a zero-knowledge model, only store an encrypted hash of the password.
    Returns a dictionary containing the service name and encrypted hash.
    """
    hashed = hash_password(plain_password)
    encrypted = encrypt_password(hashed)
    # In a real application, this data would be saved in a secure database.
    data = {"service": service, "encrypted_password": encrypted.decode()}
    logging.info(f"Password for {service} stored securely.")
    return data

def retrieve_password(service_data: dict, plain_password: str) -> bool:
    """
    Verify the provided plain password against the stored encrypted hash.
    Returns True if verification succeeds.
    """
    encrypted = service_data.get("encrypted_password").encode()
    decrypted_hash = decrypt_password(encrypted)
    is_valid = verify_password(decrypted_hash, plain_password)
    if is_valid:
        logging.info("Password verification succeeded.")
    else:
        logging.info("Password verification failed.")
    return is_valid

# Example usage
if __name__ == "__main__":
    service_name = "example.com"
    user_password = "MySecurePass123!"

    # Check if the password appears in any leak databases
    if check_password_leak(user_password):
        logging.warning("The provided password has been compromised. Please change it immediately!")
    else:
        logging.info("The provided password appears safe.")

    # Store the password securely
    stored_data = store_password(service_name, user_password)
    # For demonstration, try retrieving/verifying the password back
    verification = retrieve_password(stored_data, user_password)
    logging.info(f"Password verification result: {verification}")
