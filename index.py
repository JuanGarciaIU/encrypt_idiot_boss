import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load old private key
with open('old_private_key.pem', 'rb') as key_file:
    old_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load new public key
with open('new_public_key.pem', 'rb') as key_file:
    new_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Ensure new_user_profiles directory exists
new_user_profiles_dir = 'new_user_profiles'
if not os.path.exists(new_user_profiles_dir):
    os.makedirs(new_user_profiles_dir)

# Iterate over files in user_profiles directory
user_profiles_dir = 'user_profiles'
customer_files = os.listdir(user_profiles_dir)
for customer_file in customer_files:
    with open(os.path.join(user_profiles_dir, customer_file), 'rb') as file:
        encrypted_data = file.read()

    # Decode Base64 encoded encrypted data
    encrypted_data_decoded = base64.b64decode(encrypted_data)

    # Decrypt data using old private key
    decrypted_data = old_private_key.decrypt(
        encrypted_data_decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encrypt decrypted data using new public key
    encrypted_data_new = new_public_key.encrypt(
        decrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encode encrypted data with Base64
    encrypted_data_new_base64 = base64.b64encode(encrypted_data_new)

    # Save newly-encrypted data into a file in new_user_profiles directory
    new_customer_file = os.path.join(new_user_profiles_dir, customer_file)
    with open(new_customer_file, 'wb') as file:
        file.write(encrypted_data_new_base64)

    print(f"Encryption complete. New user profile saved at: {new_customer_file}")

print("All files encrypted and saved.")
