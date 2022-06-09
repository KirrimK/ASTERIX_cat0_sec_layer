import base64
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import Base64Encoder
import random
import time

ORIG_FILE_LCT = 'tests/radar.txt'

def radar(n):
    with open(ORIG_FILE_LCT, 'wb+') as rad:
        for _ in range(n):
            temp = random.randbytes(48)
            rad.write(base64.b64encode(temp))
            rad.write(b'\n')


def sign(message, pkey):
    return pkey.sign(message)

if __name__ == '__main__':
    private_key = SigningKey.generate()
    with open('tests/privateKey.txt', 'wb+') as prKey:
        prKey.write(private_key.encode(encoder=Base64Encoder))
    public_key = private_key.verify_key
    with open('tests/publicKey.txt', 'wb+') as puKey:
        puKey.write(public_key.encode(encoder=Base64Encoder))
    lst_message = radar(1000)
    tic = time.process_time()

    with open(ORIG_FILE_LCT, 'rb+') as f:
        with open('tests/signed.txt', 'wb+') as fic:
            fic.truncate()
            for line in f:
                lineCleanedBytes = line.strip()
                signed = private_key.sign(lineCleanedBytes, encoder=Base64Encoder)
                fic.write(signed)
                fic.write(b'\n')

    tac = time.process_time()

    with open('tests/signed.txt', 'rb+') as f2:
        for line in f2:
            lineCleanedb = line.strip()

            try:
                public_key.verify(lineCleanedb, encoder=Base64Encoder)
            except BadSignatureError:
                print('Wrong signature')

    toc = time.process_time()
    print('Signing time: {} ms\n'.format((tac-tic)*1000))
    print('Decoding time: {} ms\n'.format( (toc - tac) * 1000) )
    print('Total time: {} ms\n'.format( (toc - tic) * 1000) )
    print('Signing average time: {} ms\n'.format( ((tac - tic) / 1000)* 1000) )
    print('Decoding average time: {} ms\n'.format( ((toc - tac) / 1000) * 1000) )
    print('Both average time: {} ms\n'.format( ((toc - tic) / 1000) * 1000) )




