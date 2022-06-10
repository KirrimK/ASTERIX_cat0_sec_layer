import base64
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from nacl.exceptions import BadSignatureError
from nacl.encoding import Base64Encoder
import random
import time
import hashlib

def send(message):
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    public_key64 = public_key.encode(encoder=Base64Encoder)
    hashed = hashlib.sha256(message)
    signedHash = private_key.sign(hashed.digest(), encoder=Base64Encoder)
    return message + public_key64 + signedHash

def receive(message):
    #Slice the received message in 3 parts: core message/public key/signed hash

    recmessage = message[:48]
    recPubKey = message[48:92]
    recPKey = VerifyKey(recPubKey, encoder=Base64Encoder)
    recSignedHash = message[92:]

    #Separate the signed hash into hash and siganture

    recSignedHashB = base64.b64decode((recSignedHash))
    recSign = recSignedHashB[:64]
    recHash = recSignedHashB[64:]

    # verify integrity
    integrity = hashlib.sha256(recmessage).digest() == recHash

    # verify authenticity
    authenticity = recPKey.verify(recSignedHashB) == recHash

    print("Integrity: {}\nAuthenticity: {}".format(integrity,authenticity))

if __name__ == '__main__':
    message = random.randbytes(48)
    ToSend = send(message)
    receive(ToSend)





