import sqlite3
import secrets
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
import cryptography

# Utility function to generate a random strong password
def generate_password(length=10):
    alphabet = string.digits  # Restricting to digits only for master password
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Function to derive a key from the master password
def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# Encrypt data using AES
from cryptography.hazmat.primitives import padding

def encrypt_data(key: bytes, data: str) -> tuple:
    iv = os.urandom(16)  # 16 bytes IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Use padding module to pad the data to AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the iv and encrypted data as base64 encoded
    return b64encode(iv).decode(), b64encode(encrypted_data).decode()

# Decrypt data using AES
def decrypt_data(key: bytes, iv: str, encrypted_data: str) -> str:
    iv = b64decode(iv)
    encrypted_data = b64decode(encrypted_data)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Use unpadder to remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return unpadded_data.decode()

# Create the SQLite database for storing passwords
def create_db():
    try:
        conn = sqlite3.connect('password_manager.db')
        c = conn.cursor()
        # Create table with salt, iv, and encrypted_password columns
        c.execute(''' 
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT,
                username TEXT,
                salt BLOB,
                iv TEXT,
                encrypted_password TEXT
            )
        ''')
        conn.commit()
        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"Database error: {e}")

# Add a password to the database
def add_password(website, username, password, master_password):
    salt = os.urandom(16)  # Random salt for key derivation
    key = derive_key(master_password, salt)
    iv, encrypted_password = encrypt_data(key, password)
    
    try:
        conn = sqlite3.connect('password_manager.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO credentials (website, username, salt, iv, encrypted_password)
            VALUES (?, ?, ?, ?, ?)
        ''', (website, username, b64encode(salt).decode(), iv, encrypted_password))
        conn.commit()
        conn.close()
        print("Password saved securely.")
    except sqlite3.DatabaseError as e:
        print(f"Error saving password: {e}")

# Retrieve a password from the database
def get_password(website, username, master_password):
    try:
        conn = sqlite3.connect('password_manager.db')
        c = conn.cursor()
        c.execute('''
            SELECT salt, iv, encrypted_password FROM credentials WHERE website = ? AND username = ?
        ''', (website, username))
        
        result = c.fetchone()
        conn.close()
        
        if result:
            salt, iv, encrypted_password = result
            salt = b64decode(salt)  # Decode salt from base64
            key = derive_key(master_password, salt)
            decrypted_password = decrypt_data(key, iv, encrypted_password)
            return decrypted_password
        else:
            print("No password found for that website/username.")
            return None
    except sqlite3.DatabaseError as e:
        print(f"Database error: {e}")
        return None

# Function to validate the length of the master password (digits only, 6 digits)
def validate_master_password(master_password):
    if len(master_password) != 6 or not master_password.isdigit():
        print("Master password must be exactly 6 digits!")
        return False
    return True

# Main user interface
def main():
    print("Welcome to your Advanced Password Manager!")

    # Ask for the master password
    while True:
        master_password = input("Enter your 6-digit Master Password: ")

        # Validate the length and digits of the master password
        if validate_master_password(master_password):
            break
    
    create_db()  # Ensure database is created on first run
    
    while True:
        print("\nSelect an option:")
        print("1. Add a password")
        print("2. Get a password")
        print("3. Generate a new password")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            add_password(website, username, password, master_password)
            print("Password saved securely.")
        
        elif choice == "2":
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            retrieved_password = get_password(website, username, master_password)
            
            if retrieved_password:
                print(f"Password for {website} ({username}): {retrieved_password}")
            else:
                print("No password found.")
        
        elif choice == "3":
            print("Generated password:", generate_password())
        
        elif choice == "4":
            print("Exiting password manager.")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
