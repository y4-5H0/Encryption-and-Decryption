import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Function to generate a key from a password
def generate_key(password: str) -> bytes:
    password_bytes = password.encode()
    salt = os.urandom(16)  # Generate a random salt
    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
    return base64.urlsafe_b64encode(key)  # Return only the key, not the salt

# Function to encrypt a file using a password
def encrypt_file_with_password(file_path: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        original = file.read()
    
    encrypted = fernet.encrypt(original)
    
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

# Function to decrypt a file using a password
def decrypt_file_with_password(file_path: str, password: str):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as enc_file:
        encrypted = enc_file.read()
    
    decrypted = fernet.decrypt(encrypted)
    
    with open(file_path[:-4], 'wb') as dec_file:  # Remove .enc extension
        dec_file.write(decrypted)

# Function to generate a public/private key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Save the private key
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # Add this line
        ))
    
    # Save the public key
    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Function to encrypt a file using a public key
def encrypt_file_with_key(file_path: str, public_key_path: str):
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    with open(file_path, 'rb') as file:
        original = file.read()
    
    encrypted = public_key.encrypt(
        original,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

# Function to decrypt a file using a private key
def decrypt_file_with_key(file_path: str, private_key_path: str):
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open(file_path, 'rb') as enc_file:
        encrypted = enc_file.read()
    
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(file_path[:-4], 'wb') as dec_file:  # Remove .enc extension
        dec_file.write(decrypted)

# Main function to run the program
def main():
    print("Starting the File Encryption/Decryption Tool...")  # Initial debugging statement
    while True:
        print("\nFile Encryption/Decryption Tool")
        print("1. Encrypt file with password")
        print("2. Decrypt file with password")
        print("3. Generate public/private key pair")
        print("4. Encrypt file with public key")
        print("5. Decrypt file with private key")
        print("6. Exit")
        
        choice = input("Choose an option: ")
        print(f"You chose option: {choice}")  # Debugging statement
        
        if choice == '1':
            print("Encrypting file with password...")  # Debugging statement
            file_path = input("Enter the file path to encrypt: ")
            password = input("Enter the password: ")
            encrypt_file_with_password(file_path, password)
            print(f"File '{file_path}' encrypted successfully.")
        
        elif choice == '2':
            print("Decrypting file with password...")  # Debugging statement
            file_path = input("Enter the file path to decrypt: ")
            password = input("Enter the password: ")
            decrypt_file_with_password(file_path, password)
            print(f"File '{file_path}' decrypted successfully.")
        
        elif choice == '3':
            print("Generating public/private key pair...")  # Debugging statement
            generate_key_pair()
            print("Public/private key pair generated successfully.")
        
        elif choice == '4':
            print("Encrypting file with public key...")  # Debugging statement
            file_path = input("Enter the file path to encrypt: ")
            public_key_path = input("Enter the public key file path: ")
            encrypt_file_with_key(file_path, public_key_path)
            print(f"File '{file_path}' encrypted with public key successfully.")
        
        elif choice == '5':
            print("Decrypting file with private key...")  # Debugging statement
            file_path = input("Enter the file path to decrypt: ")
            private_key_path = input("Enter the private key file path: ")
            decrypt_file_with_key(file_path, private_key_path)
            print(f"File '{file_path}' decrypted with private key successfully.")
        
        elif choice == '6':
            print("Exiting the program.")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
