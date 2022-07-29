"""
ASTERIX Cat0 Security Layer
Library

A library used by all modules
"""

#from nacl import public # modules to precise later
#from cryptography.hazmat.primitives import hashes, hmac
import os
#import Crypto # for AES-128 encryption
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
    pass

def aes_iek_decipher(ciphertext: bytes) -> bytes:
    """
    Decrypts the plaintext (supposedly a public key in our use cases)
    using AES 128-bit encryption and the IEK.
    Returns the resulting plaintext.
    Fails if the IEK isn't set.
    """
    pass

def eddsa_generate() -> tuple[object, object]: # TODO: precise type hints of tuple
    """
    Generates a random ED25519 keypair.
    Returns the generated private and public key.
    """
    pass

def eddsa_sign(signkey, content: bytes) -> bytes: # TODO: precise type hint of signkey
    """
    Signs the content using the ED25519 signing algorithm and the provided signing key.
    Returns the resulting signature.
    """
    pass

def eddsa_verify(verifykey, signature: bytes, plaintext: bytes) -> bool:
    # TODO: precise type hint of verifykey
    """
    Verifies the ED25519 signature associated with a plaintext using a verifying key.
    Returns True if the verification was successful.
    """
    pass

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
    pass

def hmac_verify(key, signed_message) -> bool:
    """
    Verifies the authenticity and integrity of the signed message using the provided key.
    Returns True if the verification was successful.
    """
    pass