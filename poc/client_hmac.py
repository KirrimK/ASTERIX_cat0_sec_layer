#Client multicast utilisant les clé symétriques
#Client UDP recevant les messages Asterix et contactant le serveur


import socket
from time import time
import lib_hmac
import struct

#Creation du socket
multicast_group = "224.1.1.1"
radar_adress = ('',10000)

sock1= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind(radar_adress)
group = socket.inet_aton(multicast_group)
mreq=struct.pack('4sL',group,socket.INADDR_ANY)
sock1.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)

#Clé symétrique
SECRET = bytes(20)

#Boucle de process
while True:
    #Reception des messages du radar
    data, addr = sock1.recvfrom(1024)
    if data :
        start=time()
        msg,flag=lib_hmac.disassemble_and_verify_msg_sha1(data,SECRET)
        print(("[VERIFIED] " +"temps:{}".format(time()-start)if flag else "[UNVERIFIED] ")+str(msg))

