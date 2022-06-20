#Client UDP recevant les messages Asterix et contactant le serveur


import socket
from time import time
import lib



#Creation du socket
CLIENT_IP = "192.168.1.248"
CLIENT_PORT = 42069

IP_SERVEUR="127.0.0.1"
SERVEUR_PORT= 42070

TIME_BETWEEN_UPDATES = 15 #seconds

sock1= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind((CLIENT_IP, CLIENT_PORT))

sock2= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock2.bind((CLIENT_IP,SERVEUR_PORT))
sock2.settimeout(5)


#Stockage des hashs des clés publiques
messages_list = []
key_dict = {}
dict_hash = lib.sha1_of_dict(key_dict)

def update_keylist():
    dict_hash = lib.sha1_of_dict(key_dict)
    #Contacter serveur pour mettre à jour dictionnaire des clés
    print("[UPDATING KEY LIST]")
    sock2.sendto(dict_hash, (IP_SERVEUR, SERVEUR_PORT))
    try:
        data2, (_, _) = sock2.recvfrom(2048) # TODO: check if sending address is the server address, otherwise ignore message
        print("\\ Received data of length {} bytes".format(len(data2)))
        if data2[0] == 0 and data2[1:] == dict_hash:
            print("\\ Key list already up to date")
        else:
            print("\\ Key list to update")
            key_dict.clear() #purge old keys
            for i in range(data2[0]): #update keys
                key   = data2[1+i*(20+32)+20:1+i*(20+32)+32+20]
                hash_ = data2[1+i*(20+32)   :1+i*(20+32)+20]
                key_verif = lib.VerifyKey(key)
                verif_hash = lib.key_hash1(key_verif)
                if verif_hash != hash_:
                    print(f"  \\ Integrity check failed, ignoring key number {i}:\n    -- {verif_hash} vs {hash_}")
                else:
                    key_dict[hash_] = key
                    print(f"  \\ Added key number {i} to key list (length {len(key)})")
            dict_hash = lib.sha1_of_dict(key_dict)
    except TimeoutError:
        print("Waited 5 seconds to key server response, carrying on")


update_keylist()
last_client_update = time()
#Boucle de process
while True:
    #Reception des messages du radar
    data, addr = sock1.recvfrom(1024)
    if time() - last_client_update >= TIME_BETWEEN_UPDATES:
        update_keylist()
        last_client_update = time()
    if data :
        msg,flag=lib.dissassemble_and_verify_msg_hash_key(key_dict, data)
        print(("[VERIFIED] " if flag else "[UNVERIFIED] ")+str(msg))


    






