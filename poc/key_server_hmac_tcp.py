import random
import nacl.public as public
import time
import socket
import json


secret = bytes(20)

private_key = public.PrivateKey(bytes(32))
public_key = private_key.public_key

print("This key server's public key is: {}".format(public_key._public_key.hex()))

list_of_radars= {}

cfp = input("Config file path:")
cj: dict = json.load(open(cfp, "r"))
for elt in cj["list_radars"]:
    list_of_radars[(elt["ip"], int(elt["port"]))] = bytes(bytearray.fromhex(elt["pubkey"]))
    print("Radar ({}:{}) pubkey: {}".format(elt["ip"], elt["port"], elt["pubkey"]))
    print("list of radar : {}".format(list_of_radars))

UPDATE_INTERVAL = 15
last_update = 0




random.seed(time.time())
while True:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    time.sleep(0.5)
    if time.time() - last_update > UPDATE_INTERVAL:
        last_update = time.time()
        secret = random.randbytes(20)
        print(f"[{last_update}] UPDATING KEY")
        for agent, pub_key in list_of_radars.items():
            
            try:
                print("trying to connect to agent {}".format(agent))
                sock.connect(agent)
                sock.settimeout(None)
           
            # cipher the key or whatever and send to the agent, along with own public key
                agent_box = public.Box(private_key, public.PublicKey(pub_key))
           
                sock.sendall(agent_box.encrypt(secret))
                print("sent to {}".format(agent))
                data=sock.recv(1024)
                print(repr(data))
                sock.close()
            except Exception as e :
                print(e)
                pass
            

            
            
        print("\\ Overall took {} seconds".format(str(time.time() - last_update)[:6]))

