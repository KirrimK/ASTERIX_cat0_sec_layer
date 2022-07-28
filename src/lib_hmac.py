from cryptography.hazmat.primitives import hashes, hmac
import os

# generates a key
# out: secret (bytes): the secret key
def gen_secret():
    return os.urandom(20)

# returns the signature of a message
# in: message (bytes): the message to sign
# in: secret (bytes): the secret key to use
# out: signature (bytes): the signature
def sign_sha1(message: bytes, secret: bytes):
    h = hmac.HMAC(secret, hashes.SHA1())
    h.update(message)
    return h.finalize()

# verifies the signature of a message
# in: signature (bytes): the signature to verify
# in: message (bytes): the message to verify
# in: secret (bytes): the secret key to use
def verify_sha1(signature: bytes, message: bytes, secret: bytes):
    h = hmac.HMAC(secret, hashes.SHA1())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except Exception:
        return False

# creates a message made of the original message, the signature
# in: message (bytes): the message to sign
# in: secret (bytes): the secret key to use
# out: message_with_signature_and_key (bytes): the message with the signature
def sign_and_assemble_message_sha1(message: bytes, secret: bytes):
    return message + sign_sha1(message, secret)

# separates the message, the signature and the hash of the secret key from a message, gets the key from the key dictionnary and verifies the signature
# in: big_message (bytes): the message to disassemble and verify
# in: secret (bytes): the secret key to use
# out: message (bytes): the message
# out: is_verified (bool): True if the signature is valid and the integrity of the message is ok, False otherwise
def disassemble_and_verify_msg_sha1(big_message: bytes, secret: bytes):
    message = big_message[:48]
    signature = big_message[48:]
    is_verified = verify_sha1(signature, message, secret)
    return message, is_verified