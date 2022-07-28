"""
Asterix security layer radar
A config file is used to define usergroups that are made of a list of clients, and a key server.
For each usergroup, the radar binds a socket to a certain ip address to receive keys from the key server.
Those keys are forwarded (encrypted) to the clients and used to sign messages sent in the usergroup via udp multicast.
"""

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

def update_key_thread(key_serv_ip: str, key_serv_pub_key: bytes, sock: socket.socket, list_recs: list):
    global SECRETS
    global END_THREAD
    print("Starting update key thread")
    while not END_THREAD:
        try:
            data, addr = sock.recvfrom(1024)
            # decipher message and extract symmetric key
            decr_box = public.Box(private_key, public.PublicKey(key_serv_pub_key))
            SECRETS[key_serv_ip] = decr_box.decrypt(data)
            print("[UPDATED KEY, REDISPATCHING]")
            for (ip, port, pub_key) in list_recs:
                agent_box = public.Box(private_key, public.PublicKey(pub_key))
                sock.sendto(agent_box.encrypt(SECRETS[key_serv_ip]), (ip, port))
        except TimeoutError:
            pass
    print("Ending update key thread")

for elt in cj:
    print("[Radar] Adding user group from config")
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.bind((elt["bound_ip"], elt["bound_port"]))
    print("\\ Binding to {}:{}".format(elt["bound_ip"], elt["bound_port"]))
    dict_multicast[elt["key_server"]["ip"]] = ((elt["recipients"]["multicast_ip"], elt["recipients"]["multicast_port"]))
    print("\\ Adding multicast group {} <-> ({}:{})".format(elt["key_server"]["ip"], elt["recipients"]["multicast_ip"], elt["recipients"]["multicast_port"]))
    loc_list = [].copy()
    for rec in elt["recipients"]["list_pubkeys"]:
        loc_list.append((rec["ip"], rec["port"], bytes(bytearray.fromhex(rec["pubkey"]))))
        print("  \\ Client ({}:{}) pubkey: {}".format(rec["ip"], rec["port"], rec["pubkey"]))
    thd_loc = threading.Thread(target=update_key_thread, args=(elt["key_server"]["ip"], bytes(bytearray.fromhex(rec["pubkey"])),sock,loc_list))
    thd_loc.start()
    list_thds.append(thd_loc)


print("RADAR Simulator:")
print("Type messages to send to multicast groups (q to quit):")
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
