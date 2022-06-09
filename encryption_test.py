#Encryption_test.py
#This script is made to test the encryption of Asterix messages with the PyNaCl library

#Using the Public Key Encryption in the pynacl documentation
import nacl.utils
from nacl.public import PrivateKey, Box

#To generate random 48 bytes messages
import random

#To establish time performance of the code execution
import time

def radar(n):
    asterix_msg_size = 48
    res = []
    for _ in range(n):
        res.append(random.randbytes(asterix_msg_size))
    return res

if __name__ == '__main__':
    import nacl.utils
from nacl.public import PrivateKey, Box

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

list_msgs = radar(10)
message = list_msgs[0]
