#Client UDP recevant les messages Asterix et contactant le serveur


import socket
import lib



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
        print("data : "+str(data))
        pub_key_hash = data[48+64:]
        print("Length of hash: "+str(len(pub_key_hash)))
        print(pub_key_hash)
        key_dict[pub_key_hash] = "NULL"
        messages_list.append(data)
    #Contacter serveur pour demande clé publique
    for hash in key_dict:
        print("hash : "+str(hash))
        sock2.sendto(hash, (IP_SERVEUR, SERVEUR_PORT))
        print("Sent hash to server")
        data2,addr = sock2.recvfrom(1024)
        if data2:
            print("data2 : "+str(data2)+"len: "+str(len(data2)))
            header = data2[0]
            print("header : "+str(header))
            hash = data2[1:21]
            print("hash : "+str(hash))
            pkey = data2[21:]
            print("pkey : "+str(pkey)+"len: "+str(len(pkey)))
            if header == 1:
                key_dict[hash]=pkey
                print(key_dict[hash])
            else :
                print("No key found")
    
    for big_message in messages_list:
        msg,flag=lib.dissassemble_and_verify_msg_hash_key(key_dict, big_message)
        if flag :
            print("Message "+str(msg)+" has been verified")
        else:
            print("Message "+str(msg)+" could not been verified")


    






