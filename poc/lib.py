from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import hashlib

# generates a keypair
# out: private_key (SigningKey): the private key
# out: public_key (VerifyKey): the public key
def keypair_generator():
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    return private_key, public_key

# returns the hash of the public key
# in: pub_key (VerifyKey): the public key to hash
# out: pub_key_hash (bytes): the hash of the public key
def key_hash1(key: VerifyKey):
    return hashlib.sha1(key._key).digest()

# returns the signature of a message
# in: message (bytes): the message to sign
# in: pkey (SigningKey): the private key to use
# out: signature (bytes): the signature
def sign_message(message: bytes, pkey: SigningKey):
    return pkey.sign(message).signature

# verifies the signature of a message
# in: signature (bytes): the signature to verify
# in: message (bytes): the message to verify
# in: pkey (VerifyKey): the public key to use
# out: is_verified (bool): True if the signature is valid and the integrity of the message is ok, False otherwise
def verify_message(signature: bytes, message: bytes, pkey: VerifyKey):
    try:
        pkey.verify(message, signature)
        return True
    except BadSignatureError:
        return False

# creates a message made of the original message, the signature and the sha1 hash of the public key concatenated
# in: message (bytes): the message to sign
# in: pkey (SigningKey): the private key to use
# in: pub (VerifyKey): the public key to use
# out: message_with_signature_and_key_hash (bytes): the message with the signature and the public key hash
def sign_and_assemble_message_hash1_key(message: bytes, pkey: SigningKey, pub: VerifyKey):
    return message + pkey.sign(message).signature + key_hash1(pub)

# separates the message, the signature and the hash of the public key from a message, gets the keys from the key dictionnary and verifies the signature
# in: key_dict (dict): the key dictionnary
# in: big_message (bytes): the message to disassemble and verify
# out: message (bytes): the message
# out: is_verified (bool): True if the signature is valid and the integrity of the message is ok, False otherwise
def dissassemble_and_verify_msg_hash_key(key_dict: dict, big_message: bytes):
    message = big_message[:48]
    signature = big_message[48:48+64]
    pub_key_hash = big_message[48+64:]
    pub_key = key_dict.get(pub_key_hash, None)
    if pub_key is None:
        print("Public key not found") # TODO: raise exception or log error
        return False, message
    is_verified = verify_message(signature, message, VerifyKey(pub_key))
    return message, is_verified
