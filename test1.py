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

def sign(message: bytes, pkey: ed25519.SigningKey):
    return pkey.sign(message)

if __name__ == '__main__':
    private_key, public_key = ed25519.create_keypair()
    number = 10000
    lst_message = radar(number)
    lst_signed = []
    global_start_time = time.process_time()
    max_sign_time = 0
    max_verify_time = 0
    for m in lst_message:
        local_sign_start = time.process_time()
        signed = sign(m, private_key)
        max_sign_time = max(max_sign_time, time.process_time() - local_sign_start)
        lst_signed.append(signed)
    global_all_signed_time = time.process_time()
    for i,s in enumerate(lst_signed):
        try:
            local_verify_start = time.process_time()
            public_key.verify(s, lst_message[i])
            max_verify_time = max(max_verify_time, time.process_time() - local_verify_start)
        except ed25519.BadSignatureError:
            print('Wrong signature')
    global_all_verified_time = time.process_time()
    print('Signing time: {} ms'.format((global_all_signed_time-global_start_time)*1000))
    print('Decoding time: {} ms'.format( (global_all_verified_time - global_all_signed_time) * 1000) )
    print('Total time: {} ms\n'.format( (global_all_verified_time - global_start_time) * 1000) )
    print('Signing average time: {} ms'.format( ((global_all_signed_time - global_start_time) / number)* 1000) )
    print('Decoding average time: {} ms'.format( ((global_all_verified_time - global_all_signed_time) / number) * 1000) )
    print('Both average time: {} ms\n'.format( ((global_all_verified_time - global_start_time) / number) * 1000) )
    print('Max signing time: {} ms'.format( max_sign_time * 1000))
    print('Max verify time: {} ms'.format( max_verify_time * 1000))
