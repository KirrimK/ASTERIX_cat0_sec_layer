import base64
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError
import random
import time

def radar(n):
    res = []
    for _ in range(n):
        res.append(bytes((''.join(str(random.randint(0, 1)) for _ in range(48))), encoding="utf-8"))
    return res

def sign(message, pkey):
    return pkey.sign(message).signature

if __name__ == '__main__':
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    lst_message = radar(10000)
    lst_signed = []
    tic = time.process_time()
    for m in lst_message:
        signed = sign(m, private_key)
        lst_signed.append(signed)
    tac = time.process_time()
    for i,s in enumerate(lst_signed):
        try:
            public_key.verify(lst_message[i], s)
        except BadSignatureError:
            print('Wrong signature')
    toc = time.process_time()
    print('Signing time: {} ms\n'.format((tac-tic)*1000))
    print('Decoding time: {} ms\n'.format( (toc - tac) * 1000) )
    print('Total time: {} ms\n'.format( (toc - tic) * 1000) )
    print('Signing average time: {} ms\n'.format( ((tac - tic) / 10000)* 1000) )
    print('Decoding average time: {} ms\n'.format( ((toc - tac) / 10000) * 1000) )
    print('Both average time: {} ms\n'.format( ((toc - tic) / 10000) * 1000) )





