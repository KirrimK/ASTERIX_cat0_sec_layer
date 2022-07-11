#Client UDP recevant les messages Asterix et contactant le serveur


import socket
from time import time
import lib_hmac
import nacl.public as public
import struct
import json

import select

private_key = public.PrivateKey(bytes(32))
public_key = private_key.public_key
print("This client's public key is: {}".format(public_key._public_key.hex()))

SECRETS = {}
PUBLIC_KEYS = {}
SOCKETS = []

cfp = input("Config file path:")
cj: dict = json.load(open(cfp, "r"))

for elt in cj["list_multicast"]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', elt["port"]))
    group = socket.inet_aton(elt["ip"])
    mreq=struct.pack('4sL',group,socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
    SOCKETS.append(sock)
    print("[Client] Will listen on multicast group ({}:{})".format(elt["ip"], elt["port"]))

for elt in cj["list_radars"]:
    PUBLIC_KEYS[elt["ip"]] = bytes(bytearray.fromhex(elt["pubkey"]))
    print("[Client] Will get secrets from radar {}:{}".format(elt["ip"], elt["pubkey"]))

SOCK_KEYS = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCK_KEYS.bind((cj["bound_ip"], cj["bound_port"]))

SOCKETS.append(SOCK_KEYS)

#Boucle de process
while True:
    #Reception des messages du radar
    ready_socks,_,_ = select.select(SOCKETS, [], [])
    for sock in ready_socks:
        data, (addr, _) = sock.recvfrom(1024)
        if sock == SOCK_KEYS:
            if data:
                decr_box = public.Box(private_key, public.PublicKey(PUBLIC_KEYS[addr]))
                secret = decr_box.decrypt(data)
                print("[UPDATED KEY]")
        else:
            if data :
                start=time()
                msg,flag=lib_hmac.disassemble_and_verify_msg_sha1(data, secret)
                print(("[VERIFIED] " if flag else "[UNVERIFIED] ")+str(msg)+(" (temps:{})".format(time()-start)))
