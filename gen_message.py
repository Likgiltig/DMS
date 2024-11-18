import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def encrypt_message(message, public_key):
    """Encrypts a message using a public key."""
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    print("Encrypted message with key")
    return encrypted_message

def load_public_key(filename):
    """Load the public key."""
    with open(filename, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    print(f"Loaded public key {filename}")
    return public_key

def save_message(message, filename):
    """Encodes the message and saves to a file."""
    # Encode the encrypted message in base64
    encoded_message = base64.b64encode(encrypted_message).decode('utf-8')

    # Save the encoded message to a file
    with open(filename, "w") as f:
        f.write(encoded_message)
    print(f"Encrypted message saved to {filename}")

# Get the message
message = input("Enter the secret message: ")

# Encrypt the message
public_key = load_public_key('public_key.pem')
encrypted_message = encrypt_message(message, public_key)

# Save the massage
save_message(encrypted_message, 'encrypted_message.txt')