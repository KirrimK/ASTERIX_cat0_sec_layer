import lib_hmac
import socket
import struct
import time
import nacl.public as public
import threading
import json

SECRETS = {}
END_THREAD = False




dict_multicast = {}
list_thds = []

private_key = public.PrivateKey(bytes(32))
public_key = private_key.public_key



cfp = input("Config file path:")
cj: list = json.load(open(cfp, "r"))

print("ip et port socket_key: {} {}".format(cj[0]["bound_ip"],cj[0]["bound_port"]))






def update_key_thread(key_serv_ip: str, key_serv_pub_key: bytes, sock: socket.socket,socket_key : socket.socket, list_recs: list):
    
    

    

    global SECRETS
    global END_THREAD
    print("Starting update key thread")
    while not END_THREAD:
        socket_dispatch=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn,addr=socket_key.accept()
            
            data= conn.recv(1024)
            if not data:
                break
            conn.sendall(b'Merci serveur pour la cle')
            conn.close()
            print(repr(data))
            # decipher message and extract symmetric key
            decr_box = public.Box(private_key, public.PublicKey(key_serv_pub_key))
            SECRETS[key_serv_ip] = decr_box.decrypt(data)
            print("[UPDATED KEY, REDISPATCHING]")
            for (ip, port, pub_key) in list_recs:
                print("ip et port pour socket_dispatch : {} {}".format(ip,port))
                
                try:
                    socket_dispatch.connect((str(ip),int(port)))
                    agent_box = public.Box(private_key, public.PublicKey(pub_key))
                    box_to_send=agent_box.encrypt(SECRETS[key_serv_ip])
                    socket_dispatch.sendall(box_to_send)
                    data=socket_dispatch.recv(1024)
                    socket_dispatch.close()
                except Exception as e:
                    print(e)
                    pass
                print(repr(data))
        except TimeoutError:
            pass

    
    print("Ending update key thread")

for elt in cj:
    print("[Radar] Adding user group from config")

    SOCKET_KEY= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCKET_KEY.bind((elt["bound_ip"], elt["bound_port"]))
    SOCKET_KEY.listen(10)


    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    #sock.bind((elt["bound_ip"], elt["bound_port"]))
    print("\\ Binding to {}:{}".format(elt["bound_ip"], elt["bound_port"]))
    dict_multicast[elt["key_server"]["ip"]] = ((elt["recipients"]["multicast_ip"], elt["recipients"]["multicast_port"]))
    print("\\ Adding multicast group {} <-> ({}:{})".format(elt["key_server"]["ip"], elt["recipients"]["multicast_ip"], elt["recipients"]["multicast_port"]))

    

    loc_list = [].copy()
    for rec in elt["recipients"]["list_pubkeys"]:
        loc_list.append((rec["ip"], rec["port"], bytes(bytearray.fromhex(rec["pubkey"]))))
        print("  \\ Client ({}:{}) pubkey: {}".format(rec["ip"], rec["port"], rec["pubkey"]))
    thd_loc = threading.Thread(target=update_key_thread, args=(elt["key_server"]["ip"], bytes(bytearray.fromhex(rec["pubkey"])),sock,SOCKET_KEY, loc_list))
    thd_loc.start()
    list_thds.append(thd_loc)


print("RADAR Simulator:")
print("Type messages to send to multicast group (q to quit):")
done = False
while not done:
    print("> ", end="")
    message = "q"
    try:
        message = input()
    except EOFError:
        print("EOF'd, quitting")
    if message == "q":
        done = True
    else:
        try:
            message_ba = bytearray(48)
            message_ba[:min(len(message), 48)] = bytes(message, "ascii")[:min(len(message), 48)]
            message_bytes = bytes(message_ba)
            for key_serv_ip, multicast_group in dict_multicast.items():
                if SECRETS.get(key_serv_ip, None) is not None:
                    start = time.time()
                    big_msg = lib_hmac.sign_and_assemble_message_sha1(message_bytes, SECRETS[key_serv_ip])
                    sock.sendto(big_msg, multicast_group)
                    print("-- sent to group [{}]".format(key_serv_ip)+" (temps : {})".format(time.time()-start))
        except KeyboardInterrupt:
            print("Interrupted, quitting")
            done = True
        except Exception as e:
            print("Error: "+str(e))
END_THREAD = True
for thd in list_thds:
    thd.join()
