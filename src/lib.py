"""
ASTERIX Cat0 Security Layer
Library

A library used by all modules
"""

from nacl import signing
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
import os
import requests

def load_IEK_from_file(filepath: str) -> bytes:
    """
    Loads the Initiation Encryption Key from a file and installs it.
    Should be run only once at the start of the agent.
    """
    iek = None
    with open(filepath, 'rb') as file:
        iek = file.read()
    return iek

# def aes_iek_cipher(iek: bytes, plaintext: bytes) -> bytes:
#     """
#     Encrypts the plaintext (supposedly a public key in our use cases)
#     using AES 128-bit encryption and the IEK.
#     Returns the resulting ciphertext.
#     """
#     cipher = AES.new(iek, AES.MODE_EAX)
#     ciphertext, tag = cipher.encrypt_and_digest(plaintext)
#     nonce = cipher.nonce
#     print("---\nplaintext: "+str(plaintext))
#     print("nonce: "+str(nonce))
#     print("tag: "+str(tag))
#     print("ciphertext: "+str(ciphertext))
#     print("---")
#     return nonce + tag + ciphertext

# def aes_iek_decipher(iek: bytes, nonce_tag_ciphertext: bytes) -> bytes|None:
#     """
#     Decrypts the plaintext (supposedly a public key in our use cases)
#     using AES 128-bit encryption and the IEK.
#     Returns the resulting plaintext.
#     """
#     nonce = nonce_tag_ciphertext[:16]
#     tag = nonce_tag_ciphertext[16:32]
#     ciphertext = nonce_tag_ciphertext[32:]
#     cipher = AES.new(iek, AES.MODE_EAX, nonce=nonce)
#     plaintext = cipher.decrypt(ciphertext)
#     print("---\nplaintext: "+str(plaintext))
#     print("nonce: "+str(nonce))
#     print("tag: "+str(tag))
#     print("ciphertext: "+str(ciphertext))
#     print("---")
#     try:
#         cipher.verify(tag)
#         # succeeds if message is authentic
#         return plaintext
#     except Exception as e:
#         # fails if message has been tampered with
#         print(e)
#         return None

def fernet_iek_cipher(iek: bytes, plaintext: bytes) -> bytes:
    f = Fernet(iek)
    return f.encrypt(plaintext)

def fernet_iek_decipher(iek: bytes, ciphertext: bytes) -> bytes|None:
    f = Fernet(iek)
    try:
        return f.decrypt(ciphertext)
    except Exception as e:
        print(e)
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

def get_ca_public_key(iek: bytes, ca_addr: str, ca_port: int) -> signing.VerifyKey|None:
    """Contacts the CA server to get its public key"""
    try:
        response = requests.get("http://"+ca_addr+":"+str(ca_port)+"/public")
        if response.status_code == 200:
            resp_bytes = bytes.fromhex(response.text)
            decr_key = fernet_iek_decipher(iek, resp_bytes)
            return signing.VerifyKey(decr_key)
        return None
    except Exception as e:
        print(e)
        return None

def send_key_ca_validation(iek: bytes, group_verifykey: signing.VerifyKey, verifykey: signing.VerifyKey, ca_addr: str, ca_port: int) -> bytes|None:
    """Sends the sensor's public key for validation from the CA
    Returns the key and its signature made by CA keypair
    Returns None if the process has failed"""
    try:
        response = requests.get("http://"+ca_addr+":"+str(ca_port)+"/sign?key="+fernet_iek_cipher(iek, verifykey._key).hex())
        if response.status_code == 200:
            resp_bytes = bytes.fromhex(response.text)
            decr_signedmsg = fernet_iek_decipher(iek, resp_bytes)
            msg = decr_signedmsg[:-64]
            signature = decr_signedmsg[-64:]
            ver = eddsa_verify(group_verifykey, signature, msg)
            if ver:
                return resp_bytes
        return None
    except Exception as e:
        print(e)
        return None