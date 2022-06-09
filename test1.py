import base64
import ed25519
import random
import time

def radar(n):
    asterix_msg_size = 48
    res = []
    for _ in range(n):
        res.append(random.randbytes(asterix_msg_size))
    return res

def sign(message, pkey):
    return pkey.sign(message)

if __name__ == '__main__':
    private_key, public_key = ed25519.create_keypair()
    lst_message = radar(1000)
    lst_signed = []
    tic = time.process_time()
    for m in lst_message:
        signed = sign(m, private_key)
        lst_signed.append(signed)
    tac = time.process_time()
    for i,s in enumerate(lst_signed):
        try:
            public_key.verify(s, lst_message[i])
        except ed25519.BadSignatureError:
            print('Wrong signature')
    toc = time.process_time()
    print('Signing time: {} ms\n'.format((tac-tic)*1000))
    print('Decoding time: {} ms\n'.format( (toc - tac) * 1000) )
    print('Total time: {} ms\n'.format( (toc - tic) * 1000) )
    print('Signing average time: {} ms\n'.format( ((tac - tic) / 1000)* 1000) )
    print('Decoding average time: {} ms\n'.format( ((toc - tac) / 1000) * 1000) )
    print('Both average time: {} ms\n'.format( ((toc - tic) / 1000) * 1000) )





