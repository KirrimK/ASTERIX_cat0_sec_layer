#Client UDP recevant les messages Asterix et contactant le serveur


import socket
from time import time
import lib_hmac
import struct
import threading



#Creation du socket
CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 42069

IP_SERVEUR="192.168.1.193"
SERVEUR_PORT= 42070

multicast_group = "224.1.1.1"
radar_adress = ('',10000)

sock1= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind(radar_adress)
group = socket.inet_aton(multicast_group)
mreq=struct.pack('4sL',group,socket.INADDR_ANY)
sock1.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)

sock2= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock2.bind((CLIENT_IP,SERVEUR_PORT))


#Stockage des hashs des clés publiques
messages_list = []
secret = bytes(20)

STOP_UPDATE_THREAD = False

def update_key():
    while not STOP_UPDATE_THREAD:
        data, addr = sock2.recvfrom(1024)
        # decipher message and extract symmetric key
        # secret = ...

thd = threading.Thread(target=update_key)
thd.start()

#Boucle de process
try:
    while True:
        #Reception des messages du radar
        data, addr = sock1.recvfrom(1024)
        if data :
            start=time()
            msg,flag=lib_hmac.disassemble_and_verify_msg_sha1(data, secret)
            print(("[VERIFIED] " if flag else "[UNVERIFIED] ")+str(msg)+(" (temps:{})".format(time()-start)))
except KeyboardInterrupt:
    STOP_UPDATE_THREAD = True
    thd.join()
    sock1.close()
    sock2.close()
    print("Quitted")