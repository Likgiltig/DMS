## Dead Man's Switch (DMS)

This is a dead man's switch security project with three key scripts:

1. `gen_key.py`: Generates a RSA key pair (public and private keys)
   - Creates 2048-bit RSA keys
   - Saves private and public keys to PEM files

2. `gen_message.py`: Encrypting a secret message
   - Prompts user to input a secret message
   - Requires:
     * Public key file
   - Encrypts the message using the public key
   - Saves the encrypted message to a file

3. `dead_switch.py`: The main security mechanism
   - Monitors system at a specific time
   - Requires:
     * Encrypted message file
     * Private key file
   - Decrypts message and checks against a randomly generated secret
   - If decryption fails or secret is incorrect, triggers a fail mechanism
   - If successful, deletes the message file

**Usage workflow:**
1. Run `gen_key.py` to generate private/public keys.
2. Run `dead_switch.py` which will generate a secret and save it to a text file, after which it will start the security mechanism.
3. Run `gen_message.py` to encrypt a secret message, it should be the same as the one that `dead_switch.py` generated.

**Security features:**
- Uses asymmetric encryption
- Cryptographically secure random number generation
- Entropy-enhanced secret creation
- Implements signal handlers to check unexpected termination of the script
- Has built-in failure and success states

**Footnote:**
This project could be used for time-sensitive information release or as a dead man's switch, currently its functions for success and failure do nothing. Asymmetric encryption was used for the intent to have this project running on multiple computers.
