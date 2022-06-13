import main
import socket
import random
import time

UDP_IP = "192.168.1.172"
UDP_PORT = 42069

N=100000


sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
key = bytes(20)

start=time.time()
while(N>0):                    
    message=random.randbytes(48)
    #print("message : {}".format(message))
    #print("key: {}".format(key))
    big_msg = main.sign_and_assemble_message_sha1_hash(message, key)
    #print("big_msg: {}".format(big_msg))
    #print("len(big_msg): {}".format(len(big_msg)))
    sock.sendto(big_msg, (UDP_IP, UDP_PORT))
    N=N-1
end=time.time()

print("Temps total d'envoi pour 1000 messages : {} ms".format((end-start)*1000))