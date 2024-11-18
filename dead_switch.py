import os, sys, time, signal, base64, random, string, secrets, hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def fail():
    """Function that runs on any security failure"""
    print("Failure function activation")
    sys.exit(1)

def success():
    """Function that runs on success"""
    print("Success function activation")
    os.remove(MESSAGE_FILE)

def generate_secret(length=16, complexity=None):
    """Generate a secure password using entropy-enhanced seed."""
    # Default complexity configuration
    default_complexity = {
        'uppercase': True,
        'lowercase': True,
        'digits': True,
        'special_chars': True,
        'exclude_ambiguous': True
    }
    
    # Merge default and user-provided complexity
    if complexity:
        default_complexity.update(complexity)
    
    # Define character sets
    char_sets = {
        'uppercase': string.ascii_uppercase,
        'lowercase': string.ascii_lowercase,
        'digits': string.digits,
        'special_chars': '!@#$%^&*()-_=+[]{}|;:,.<>?'
    }
    
    # Exclude ambiguous characters if specified
    if default_complexity.get('exclude_ambiguous'):
        char_sets['uppercase'] = char_sets['uppercase'].replace('I', '').replace('O', '')
        char_sets['lowercase'] = char_sets['lowercase'].replace('l', '').replace('o', '')
        char_sets['digits'] = char_sets['digits'].replace('0', '').replace('1', '')
    
    # Generate entropy-enhanced seed
    additional_entropy = os.urandom(32)
    seed = hashlib.pbkdf2_hmac('sha256', additional_entropy, os.urandom(16), 100000, dklen=32)
    
    # Combine character sets based on complexity
    available_chars = ''.join([char_sets[key] for key, value in default_complexity.items()if value and key in char_sets])
    
    # Ensure at least one character from each required set
    password_chars = []
    for key, char_set in char_sets.items():
        if default_complexity.get(key):
            password_chars.append(secrets.choice(char_set))
    
    # Fill remaining password length with random characters
    remaining_length = length - len(password_chars)
    password_chars.extend(secrets.choice(available_chars) for _ in range(remaining_length))
    
    # Shuffle the password characters
    secrets.SystemRandom().shuffle(password_chars)
    
    secret = ''.join(password_chars)
    with open("secret.txt", "w") as f:
        f.write(secret)
    return secret

def signal_handler(signum, frame):
    """Handle external termination signals"""
    print(f"\nReceived signal: {signum} {frame}")
    fail()

def setup_signal_handlers():
    """Setup handlers for various termination signals"""
    # Handle termination signals
    try:
        signal.signal(signal.SIGTERM, signal_handler)  # Handle kill
    except (AttributeError, ValueError):
        pass  # SIGTERM might not be available on Windows
        
    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C (available on all platforms)
    
    # Set up platform-specific signals
    if os.name != 'nt':  # If not Windows
        try:
            signal.signal(signal.SIGHUP, signal_handler)   # Handle terminal close
        except (AttributeError, ValueError):
            pass

def decrypt_message(encrypted_text, key_file):
    """Decrypt a base64 encoded message using the private key"""
    try:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        encrypted_bytes = base64.b64decode(encrypted_text)
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except:
        print('Decryption failed')
        fail()

def check_time(target_time):
    """Check if current time matches target time"""
    current = time.strftime("%H:%M:%S")
    print(current)
    return current.startswith(target_time) and current.endswith("00")

def verify_files():
    """Verify that required files exist"""
    if not os.path.exists(KEY_FILE) or not os.path.exists(MESSAGE_FILE):
        print('Missing files')
        fail()

def main():
    # Set up signal handlers
    setup_signal_handlers()
    
    try:
        while True:
            if check_time(TARGET_TIME):
                try:
                    verify_files()
                    with open(MESSAGE_FILE, "r") as f:
                        encrypted_text = f.read()
                    decrypted = decrypt_message(encrypted_text, KEY_FILE)
                    if decrypted != SECRET:
                        print('Wrong secret')
                        fail()
                    else:
                        success()                  
                except:
                    fail()
            time.sleep(1)
    except Exception as e:
        print(e)
        fail()

# Configuration
TARGET_TIME = "13:30"
SECRET = generate_secret()
KEY_FILE = "private_key.pem"
MESSAGE_FILE = "encrypted_message.txt"

main()