import os # For checking file existence or operating system
import json # For reading/writing JSON data
import hashlib # For hashing the master password
import getpass # For secure password input (no echo in terminal)
from cryptography.fernet import Fernet # For encrypting/decrypting the password vault
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Derives a Fernet key from the master password using PBKDF2HMAC.
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #uses SHA256 hashing algorithm
        length=32, # The output key will be 32 bytes (what Fernet requires)
        salt=salt, # Salt ensures unique keys even with same password
        iterations=100000, # More iterations = more secure (but slower)
        backend=default_backend() # Required setup
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def main():
    # (BEMO) Big Encryption Management Operator Introduction
    print("Hello User this is BEMO your password encrypting companion!! :)")

    hash_file = "master_password.hash"
    vault_file = "vault.encrypted"

    # TODO: Add logic to check for master password file and proceed accordingly
    if not os.path.exists(hash_file):
        print("No master password found what the heck! Let's create one.")
        master_password = getpass.getpass("Create a master password: ")
        confirm_password = getpass.getpass("Confirm your master password: ")
        
        if master_password != confirm_password:
            print("Passwords do not match. Exiting. ")
            return
    
        # Hash and store the master password
        hashed_password = hashlib.sha256(master_password. encode()).hexdigest()
        with open(hash_file, "w") as f:
            f.write(hashed_password)
            
        #Generate and store a salt for encryption
        salt = os.urandom(16)
        with open("salt.bin", "wb") as f:
            f.write(salt)
        
        #Create an empty ecrypted vault
        key = derive_key(master_password, salt)
        vault = {}
        encrypted_vault = Fernet(key).encrypt(json.dumps(vault).encode())
        with open(vault_file, "wb") as f:
            f.write(encrypted_vault)
            
        print("Master password set and vault created successfully!")
        
    else:
        # Master password file exists - verify the user
        master_password = getpass.getpass("Enter your master password: ")
        hashed_input = hashlib.sha256(master_password.encode()).hexdigest()

        with open(hash_file, "r") as f:
            stored_hash = f.read()
        
        if hashed_input != stored_hash:
            print("Incorrect master password. Access denied.")
            return # This is important to output what you wanted it to print
        
        with open("salt.bin", "rb") as f:
            salt = f.read()
            
        key = derive_key(master_password, salt)
        
        if os.path.exists(vault_file):    
            with open(vault_file, "rb") as f:
                encrypted_data = f.read()    
            try:
                decrypted_data = Fernet(key). decrypt(encrypted_data)
                vault = json.loads(decrypted_data.decode())
                print("Vault unlocked!")
            except:
                print("Failed to decrypt vault. Wrong password or corrupted file.")
                return
            
        else:
            vault = {}
            print("Vault not found. Starting with an empty vault.")
            
   #TODO: Add a Command Line Interface (CLI) menu 
    print("BEMO has unlocked your vault!")
    
    while True:
        print("\nOptions:")
        print("1. Add new entry")
        print("2. View vault")
        print("3. Exit")
        print("4. Delete item in vault")
        choice = input("Choose an option: ")
    
        if choice == "1":
            service = input("Enter service name (e.g., Gmail): ")
            username = input("Enter Username: ")
            password = getpass.getpass("Enter password: ")
            vault[service] = {"username": username, "password": password}
            print(f"{service} added to vault.")
        
        elif choice == "2":
            if not vault:
                print("Vault is empty.")
            else:
                for service, creds in vault.items():
                    print(f"\nService: {service}")  
                    print(f"Username: {creds['username']}")   
                    print(f"Password: {creds['password']}")   
            
        elif choice == "3":
            # Encrypt and save the updated vault
            encrypted_vault = Fernet(key).encrypt(json.dumps(vault).encode())
            with open(vault_file, "wb") as f:
                f.write(encrypted_vault)
            print("Vault saved. Goodbye!")
            break
        
        elif choice == "4":
            # Delete a specific service 
            confirm = input("Are you sure you want to delete a specific item in the vault? ")
            
            if confirm.lower() == "yes":
                service_to_delete = input("Enter the service name you want to delete: ")
                if service_to_delete in vault:
                    del vault[service_to_delete]
                    encrypted_vault = Fernet(key).encrypt(json.dumps(vault).encode())
                    with open(vault_file, "wb") as f:
                        f.write(encrypted_vault)
                    print(f"{service_to_delete} has been deleted from the vault.")
            else:
                print("Service not found.")
        
        else:
            print("Invalid option. This is interesting try again.")
        
if __name__ == "__main__":
    main()
