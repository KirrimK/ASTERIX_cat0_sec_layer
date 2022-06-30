#Client UDP recevant les messages Asterix et contactant le serveur


import socket
from time import time
import lib_hmac
import nacl.public as public
import struct

import select

#Creation du socket
CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 42069

multicast_group = "224.1.1.1"
radar_adress = ('',10000)

sock1= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind(radar_adress)
group = socket.inet_aton(multicast_group)
mreq=struct.pack('4sL',group,socket.INADDR_ANY)
sock1.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)

sock2= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock2.bind((CLIENT_IP,CLIENT_PORT))

secret = bytes(20)

private_key = public.PrivateKey(bytes(32))
public_key = private_key.public_key
print("This client's public key is: {}".format(public_key))

#Boucle de process
while True:
    #Reception des messages du radar
    ready_socks,_,_ = select.select([sock1, sock2], [], [])
    for sock in ready_socks:
        data, addr = sock.recvfrom(1024)
        if sock == sock1:
            if data :
                start=time()
                msg,flag=lib_hmac.disassemble_and_verify_msg_sha1(data, secret)
                print(("[VERIFIED] " if flag else "[UNVERIFIED] ")+str(msg)+(" (temps:{})".format(time()-start)))
        elif sock == sock2:
            if data:
                pub_key = data[-32:]
                enc_secret = data[:-32]
                decr_box = public.Box(private_key, public.PublicKey(pub_key))
                secret = decr_box.decrypt(enc_secret)
                print("[UPDATED KEY]")
