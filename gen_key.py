import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size=2048):
    """Generate a new RSA keypair with specified key size."""
    print(f"Generating {key_size}-bit RSA keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("RSA keypair generated successfully!")
    return private_key, public_key

def save_keys(private_key, public_key, private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """Save RSA keys to files."""
    # Save private key
    print(f"Saving private key to {private_key_path}...")
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    # Save public key
    print(f"Saving public key to {public_key_path}...")
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("Keys saved successfully!")

private_key, public_key = generate_rsa_keypair()
save_keys(private_key, public_key)