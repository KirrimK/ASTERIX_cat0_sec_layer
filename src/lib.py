"""
ASTERIX Cat0 Security Layer
Library

A library used by all modules
"""

from nacl import signing, public
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
import os
import logging

def load_IEK_from_file(filepath: str) -> bytes:
    """
    Loads the Initiation Encryption Key from a file.
    """
    iek = None
    with open(filepath, 'rb') as file:
        iek = file.read()
    return iek

def fernet_generate_iek(filepath: str) -> None:
    """
    Generates a random Initiation Encryption Key and saves it to a file
    """
    with open(filepath, 'wb') as file:
        file.write(Fernet.generate_key())

def fernet_iek_cipher(iek: bytes, plaintext: bytes) -> bytes:
    """
    Ciphers the plaintext using the provided IEK (using the Fernet Cipher)
    Returns the ciphertext
    """
    f = Fernet(iek)
    return f.encrypt(plaintext)

def fernet_iek_decipher(iek: bytes, ciphertext: bytes) -> bytes|None:
    """
    Deciphers the ciphertext using the provided IEK.
    Returns the plaintext if all provided arguments are correct, otherwise returns None
    """
    f = Fernet(iek)
    try:
        return f.decrypt(ciphertext)
    except Exception as e:
        logging.error(e)
        return None

def eddsa_generate() -> tuple[signing.SigningKey, signing.VerifyKey]:
    """
    Generates a random ED25519 keypair.
    Returns the generated private and public key.
    """
    signkey = signing.SigningKey.generate()
    return (signkey, signkey.verify_key)

def eddsa_sign(signkey: signing.SigningKey, content: bytes) -> bytes:
    """
    Signs the content using the ED25519 signing algorithm and the provided signing key.
    Returns the resulting signature.
    """
    return signkey.sign(content).signature

def eddsa_verify(verifykey: signing.VerifyKey, signature: bytes, plaintext: bytes) -> bool:
    """
    Verifies the ED25519 signature associated with a plaintext using a verifying key.
    Returns True if the verification was successful.
    """
    try:
        verifykey.verify(plaintext, signature)
        return True
    except Exception as e:
        logging.error(e)
        return False

def curve_encr(verifykey: signing.VerifyKey, content: bytes) -> bytes:
    """
    Encrypts the content with the content's recipient's public key
    Returns the ciphertext
    """
    publkey = verifykey.to_curve25519_public_key()
    box = public.SealedBox(publkey)
    return box.encrypt(content)

def curve_decr(signkey: signing.SigningKey, ciphertext: bytes) -> bytes|None:
    """
    Decrypts the ciphertext with the agent's own private key
    Returns the plaintext or None if the process failed
    """
    privkey = signkey.to_curve25519_private_key()
    box = public.SealedBox(privkey)
    try:
        return box.decrypt(ciphertext)
    except Exception as e:
        logging.error(e)
        return None

def hmac_generate() -> bytes:
    """
    Generates a random 20-bytes secret.
    Returns the generated secret.
    """
    return os.urandom(20)

def hmac_sign(key: bytes, content: bytes) -> bytes:
    """
    Signs the SHA-1 hash of the content using the provided key.
    Returns the signature.
    """
    h = hmac.HMAC(key, hashes.SHA1())
    h.update(content)
    return h.finalize()

def hmac_verify(key, message, signature) -> bool:
    """
    Verifies the authenticity and integrity of the message and its signature using the provided key.
    Returns True if the verification was successful.
    """
    h = hmac.HMAC(key, hashes.SHA1())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except Exception as e:
        logging.error(e)
        return False

# Launching the lib file as a standalone allows the easy creation of a new IEK
if __name__ == "__main__":
    fernet_generate_iek(input("Enter the filepath to save the new IEK: "))
