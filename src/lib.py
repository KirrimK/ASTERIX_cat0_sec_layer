"""
ASTERIX Cat0 Security Layer
Library

A library used by all modules
"""

from nacl import signing
from cryptography.hazmat.primitives import hashes, hmac
import os
from Crypto.Cipher import AES
import time

IEK = None

def load_IEK_from_file(filepath: str) -> None:
    """
    Loads the Initiation Encryption Key from a file and installs it.
    Should be run only once at the start of the agent.
    """
    global IEK
    with open(filepath, 'rb') as file:
        IEK = file.read()

def aes_iek_cipher(plaintext: bytes) -> bytes:
    """
    Encrypts the plaintext (supposedly a public key in our use cases)
    using AES 128-bit encryption and the IEK.
    Returns the resulting ciphertext.
    Fails if the IEK isn't set.
    """
    global IEK
    cipher = AES.new(IEK, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def aes_iek_decipher(nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts the plaintext (supposedly a public key in our use cases)
    using AES 128-bit encryption and the IEK.
    Returns the resulting plaintext.
    Fails if the IEK isn't set.
    """
    global IEK
    cipher = AES.new(IEK, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        # succeeds if message is authentic
        return plaintext
    except ValueError:
        # fails if message has been tampered with
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
    except Exception:
        return False

def hmac_generate() -> bytes:
    """
    Generates a random 20-bytes secret.
    Returns the generated secret.
    """
    return os.urandom(20)

def hmac_sign(key: bytes, content: bytes) -> bytes:
    """
    Signs the SHA-1 hash of the content using the provided key.
    Returns the plaintext and its signature attached.
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
    except Exception:
        return False