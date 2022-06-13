from nacl.signing import SigningKey, VerifyKey
import nacl.public
from nacl.exceptions import BadSignatureError
import hashlib

from cryptography.hazmat.primitives import hashes, hmac
import os

######### ED25519 Signature #########

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
def key_hash3_224(key: VerifyKey):
    return hashlib.sha3_224(key._key).digest()

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

# creates a message made of the original message, the signature and the public key concatenated
# in: message (bytes): the message to sign
# in: pkey (SigningKey): the private key to use
# in: pub (VerifyKey): the public key to use
# out: message_with_signature_and_key (bytes): the message with the signature and the public key
def sign_and_assemble_message_key(message: bytes, pkey: SigningKey, pub: VerifyKey):
    return message + pkey.sign(message).signature + pub._key

# creates a message made of the original message, the signature and the sha3_224 hash of the public key concatenated
# in: message (bytes): the message to sign
# in: pkey (SigningKey): the private key to use
# in: pub (VerifyKey): the public key to use
# out: message_with_signature_and_key_hash (bytes): the message with the signature and the public key hash
def sign_and_assemble_message_hash3_224_key(message: bytes, pkey: SigningKey, pub: VerifyKey):
    return message + pkey.sign(message).signature + hashlib.sha3_224(pub._key).digest()

# creates a message made of the original message, the signature and the sha1 hash of the public key concatenated
# in: message (bytes): the message to sign
# in: pkey (SigningKey): the private key to use
# in: pub (VerifyKey): the public key to use
# out: message_with_signature_and_key_hash (bytes): the message with the signature and the public key hash
def sign_and_assemble_message_hash1_key(message: bytes, pkey: SigningKey, pub: VerifyKey):
    return message + pkey.sign(message).signature + key_hash1(pub)

# separates the message, the signature and the public key from a message and verifies the signature
# in: message (bytes): the message to disassemble and verify
# out: is_verified (bool): True if the signature is valid and the integrity of the message is ok, False otherwise
# out: message (bytes): the message
def disassemble_and_verify_msg_raw_key(big_message: bytes):
    message = big_message[:48]
    signature = big_message[48:48+64]
    pub_key = big_message[48+64:]
    is_verified = verify_message(signature, message, VerifyKey(pub_key))
    return message, is_verified

# separates the message, the signature and the hash of the public key from a message, gets the keys from the key dictionnary and verifies the signature
# in: key_dict (dict): the key dictionnary
# in: big_message (bytes): the message to disassemble and verify
# out: message (bytes): the message
# out: is_verified (bool): True if the signature is valid and the integrity of the message is ok, False otherwise
def dissassemble_and_verify_msg_hash3_224_key(key_dict: dict, big_message: bytes):
    message = big_message[:48]
    signature = big_message[48:48+64]
    pub_key_hash = big_message[48+64:]
    pub_key = key_dict.get(pub_key_hash, None)
    if pub_key is None:
        print("Public key not found") # TODO: raise exception or log error
        return False, message
    is_verified = verify_message(signature, message, VerifyKey(pub_key))
    return message, is_verified

########## HMAC Signature ##########

def gen_secret():
    return os.urandom(20)

def sign_sha1(message: bytes, secret: bytes):
    h = hmac.HMAC(secret, hashes.SHA1())
    h.update(message)
    return h.finalize()

def verify_sha1(signature: bytes, message: bytes, secret: bytes):
    h = hmac.HMAC(secret, hashes.SHA1())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except Exception as e:
        print(e)
        return False

def hash_sha1(bts: bytes):
    return hashlib.sha1(bts).digest()

def sign_and_assemble_message_sha1_raw(message: bytes, secret: bytes):
    return message + sign_sha1(message, secret) + secret

def sign_and_assemble_message_sha1_hash(message: bytes, secret: bytes):
    return message + sign_sha1(message, secret) + hash_sha1(secret)

def disassemble_and_verify_msg_sha1_raw(big_message: bytes):
    message = big_message[:48]
    signature = big_message[48:48+20]
    secret = big_message[48+20:]
    is_verified = verify_sha1(signature, message, secret)
    return message, is_verified

def disassemble_and_verify_msg_sha1_hash(big_message: bytes, key_dict: dict):
    message = big_message[:48]
    signature = big_message[48:48+20]
    secret_hash = big_message[48+20:]
    secret = key_dict.get(secret_hash, None)
    if secret is None:
        print("Secret key not found") # TODO: raise exception or log error
        return False, message
    is_verified = verify_sha1(signature, message, secret)
    return message, is_verified

if __name__ == '__main__':
    message = bytearray(48)
    message[:11] = b"Hello World"
    message[45:] = b'fin'
    message_bytes = bytes(message)
    print("                     Message: "+ str(message_bytes)+ "\n\\ of size: "+str(len(message_bytes)))
    print("--- ED25519 Signature ---")
    pri, pub = keypair_generator() # generation of the keypair
    key_dict = {key_hash3_224(pub): pub._key} # the key dictionnary
    big_msg = sign_and_assemble_message_key(message_bytes, pri, pub)
    print("       Big message (raw_key): "+ str(big_msg)+ "\n\\ of size: "+str(len(big_msg)))
    message_from_disassemble, is_verified = disassemble_and_verify_msg_raw_key(big_msg)
    print("      Disassembled (raw_key): "+ str(message_from_disassemble)+ "\n\\ of size: "+str(len(message_from_disassemble)))
    big_msg_hash = sign_and_assemble_message_hash3_224_key(message_bytes, pri, pub)
    print(" Big message (hash3_224_key): "+ str(big_msg_hash)+ "\n\\ of size: "+str(len(big_msg_hash)))
    message_from_disassemble_hash, is_verified_hash = dissassemble_and_verify_msg_hash3_224_key(key_dict, big_msg_hash)
    print("Disassembled (hash3_224_key): "+ str(message_from_disassemble_hash)+ "\n\\ of size: "+str(len(message_from_disassemble_hash)))
    big_msg_hash1 = sign_and_assemble_message_hash1_key(message_bytes, pri, pub)
    print("Big message (hash1_key): "+ str(big_msg_hash1)+ "\n\\ of size: "+str(len(big_msg_hash1)))
    print("--- HMAC Signature ---")
    key = gen_secret()
    hmac_dict = {hash_sha1(key): key}
    big_hmac = sign_and_assemble_message_sha1_raw(message_bytes, key)
    print("      Big message (sha1_raw): "+ str(big_hmac)+ "\n\\ of size: "+str(len(big_hmac)))
    message_from_disassemble_sha1, is_verified_sha1 = disassemble_and_verify_msg_sha1_raw(big_hmac)
    print("     Disassembled (sha1_raw): "+ str(message_from_disassemble_sha1)+ "\n\\ of size: "+str(len(message_from_disassemble_sha1)))
    big_hmac_hash = sign_and_assemble_message_sha1_hash(message_bytes, key)
    print("Big message (sha1_hash): "+ str(big_hmac_hash)+ "\n\\ of size: "+str(len(big_hmac_hash)))
    message_from_disassemble_sha1_hash, is_verified_sha1_hash = disassemble_and_verify_msg_sha1_hash(big_hmac_hash, hmac_dict)
    print("Disassembled (sha1_hash): "+ str(message_from_disassemble_sha1_hash)+ "\n\\ of size: "+str(len(message_from_disassemble_sha1_hash)))
