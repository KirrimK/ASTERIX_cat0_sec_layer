#Client UDP recevant les messages Asterix et contactant le serveur


import socket
import lib

#Nb de messages 
NB=1000

#Creation du socket
CLIENT_IP = "192.168.1.174"
CLIENT_PORT = 42069

IP_SERVEUR="192.168.1.172"
SERVEUR_PORT= 42069

IP_RADAR="192.168.1.172"
RADAR_PORT= 42070


sock1= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind((CLIENT_IP, CLIENT_PORT))

sock2= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


#Stockage des hashs des clés publiques
messages_list = []
key_dict = {}


#Boucle de process
while True:
    #Reception des messages du radar
    data, addr = sock1.recvfrom(1024)
    if data : 
        pub_key_hash = data[48+64:]
        key_dict[pub_key_hash] = "NULL"
        messages_list.append(pub_key_hash)
    #Contacter serveur pour demande clé publique
    for hash in key_dict:
        sock2.sendto(pub_key_hash, (IP_SERVEUR, SERVEUR_PORT))
        data2,addr = sock2.recvfrom(1024)
        if data2:
            header = data2[0]
            hash = data2[1]
            pkey = data2[2]
            if header == b'\x01':
                key_dict[hash]=pkey
    
    for i in range(NB):
        lib.dissassemble_and_verify_msg_hash_key(key_dict, messages_list[i])


    






