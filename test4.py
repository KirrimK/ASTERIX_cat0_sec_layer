import base64
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from nacl.exceptions import BadSignatureError
from nacl.encoding import Base64Encoder
import random
import time
import hashlib

ORIG_FILE_LCT = 'tests/radarI&A.txt'

def radar(n):
    with open(ORIG_FILE_LCT, 'wb+') as rad:
        for _ in range(n):
            temp = random.randbytes(48)
            rad.write(base64.b64encode(temp))
            rad.write(b'\n')


def sign(message, pkey):
    return pkey.sign(message)

def send(message, public_key, private_key):
    public_key64 = public_key.encode(encoder=Base64Encoder)
    hashed = hashlib.sha256(message)
    signedHash = private_key.sign(hashed.digest(), encoder=Base64Encoder)
    return message + public_key64 + signedHash

def receive(message):
    #Slice the received message in 3 parts: core message/public key/signed hash

    recmessage = message[:64]
    recPubKey = message[64:108]
    recPKey = VerifyKey(recPubKey, encoder=Base64Encoder)
    recSignedHash = message[108:]

    #Separate the signed hash into hash and siganture

    recSignedHashB = base64.b64decode((recSignedHash))
    recSign = recSignedHashB[:64]
    recHash = recSignedHashB[64:]

    # verify integrity
    integrity = hashlib.sha256(recmessage).digest() == recHash

    # verify authenticity
    authenticity = recPKey.verify(recSignedHashB) == recHash

    #print("Integrity: {}\nAuthenticity: {}".format(integrity,authenticity))
    return (integrity and authenticity)

if __name__ == '__main__':
    nb = 10000
    radar(nb)
    private_key = SigningKey.generate()
    with open('tests/privateKeyI&A.txt', 'wb+') as prKey:
        prKey.write(private_key.encode(encoder=Base64Encoder))
    public_key = private_key.verify_key
    with open('tests/publicKeyI&A.txt', 'wb+') as puKey:
        puKey.write(public_key.encode(encoder=Base64Encoder))

    tic = time.process_time()

    with open(ORIG_FILE_LCT, 'rb+') as f:
        with open('tests/sentI&A.txt', 'wb+') as fic:
            fic.truncate()
            for line in f:
                lineCleanedBytes = line.strip()
                signed = send(lineCleanedBytes, public_key, private_key)
                fic.write(signed)
                fic.write(b'\n')

    tac = time.process_time()

    sucess = 0

    with open('tests/sentI&A.txt', 'rb+') as f2:
        for line in f2:
            lineCleanedb = line.strip()
            try:
                if (receive(lineCleanedb)):
                    sucess += 1
            except BadSignatureError:
                print('Wrong signature')

    toc = time.process_time()
    print("Sucess {} on {}".format(sucess, nb))

    print('Signing time: {} ms\n'.format((tac - tic) * 1000))
    print('Decoding time: {} ms\n'.format((toc - tac) * 1000))
    print('Total time: {} ms\n'.format((toc - tic) * 1000))
    print('Signing average time: {} ms\n'.format(((tac - tic) / nb) * 1000))
    print('Decoding average time: {} ms\n'.format(((toc - tac) / nb) * 1000))
    print('Both average time: {} ms\n'.format(((toc - tic) / nb) * 1000))







