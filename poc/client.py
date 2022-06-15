#Client UDP recevant les messages Asterix et contactant le serveur


import socket
import lib

#Nb de messages 
NB=1

#Creation du socket
CLIENT_IP = "192.168.1.174"
CLIENT_PORT = 42069

IP_SERVEUR="127.0.0.1"
SERVEUR_PORT= 42070


sock1= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind((CLIENT_IP, CLIENT_PORT))

sock2= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock2.bind((CLIENT_IP,SERVEUR_PORT))



#Stockage des hashs des clés publiques
messages_list = []
key_dict = {}


#Boucle de process
while True:
    #Reception des messages du radar
    data, addr = sock1.recvfrom(1024)
    if data : 
        print(data)
        pub_key_hash = data[48+64:]
        print("Length of hash: "+str(len(pub_key_hash)))
        print(pub_key_hash)
        key_dict[pub_key_hash] = "NULL"
        messages_list.append(data)
    #Contacter serveur pour demande clé publique
    for hash in key_dict:
        sock2.sendto(hash, (IP_SERVEUR, SERVEUR_PORT))
        print("Sent hash to server")
        data2,addr = sock2.recvfrom(1024)
        if data2:
            print(data2)
            header = data2[0]
            hash = data2[1]
            pkey = data2[2]
            if header == b'\x01':
                key_dict[hash]=pkey
    
    for i in range(NB):
        print(lib.dissassemble_and_verify_msg_hash_key(key_dict, messages_list[i]))


    






