#Encryption_test.py
#This script is made to test the encryption of Asterix messages with the PyNaCl library

#Using the Public Key Encryption in the pynacl documentation
import nacl.utils
from nacl.public import PrivateKey, Box

#To generate random 48 bytes messages
import random

#To establish time performance of the code execution
import time as t

import nacl.utils
from nacl.public import PrivateKey, Box

def radar(n : int):
    asterix_msg_size = 48
    res = []
    for _ in range(n):
        res.append(random.randbytes(asterix_msg_size))
    return res

if __name__ == '__main__':
    n = 1000
    start_code = t.time()
    messages=radar(n)
    for msg in messages :
        start_iteration=t.time()
        # Generate Sender's private key, which must be kept secret
        sk_sender = PrivateKey.generate()

        # Sender's public key can be given to anyone wishing to send to the 
        #   Sender an encrypted message
        pk_sender = sk_sender.public_key

        # Receiver does the same and then Receiver and Sender exchange public keys
        sk_receiver = PrivateKey.generate()
        pk_receiver= sk_receiver.public_key

        # Sender wishes to send Receiver  an encrypted message so the Sender must make a Box with
        #   his private key and Receiver's public key
        sender_box = Box(sk_sender, pk_receiver)

        # This is our message to send, it must be a bytestring as Box will treat it
        #   as just a binary blob of data.

        message = msg
        

        # Encrypt our message, it will be exactly 40 bytes longer than the
        #   original message as it stores authentication information and the
        #   nonce alongside it.
        encrypted = sender_box.encrypt(message)

        # Receiver creates a second box with his private key to decrypt the message
        receiver_box = Box(sk_receiver, pk_sender)

        # Decrypt our message, an exception will be raised if the encryption was
        #   tampered with or there was otherwise an error.
        plaintext = receiver_box.decrypt(encrypted)
        #print(plaintext)
        end_iteration=t.time()
    end_code = t.time()

    print('Total time: {} ms\n'.format( (end_code - start_code) * 1000) )
    print('Decoding average time: {} ms\n'.format( ((end_iteration - start_iteration) / n) * 1000) )
