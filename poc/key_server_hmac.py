"""
Asterix security layer key server
Using a config file, it sends keys to known radars periodically.
"""

import random
import nacl.public as public
import time
import socket
import json
import lib_hmac

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

UPDATE_INTERVAL = 15

last_update = 0
random.seed(time.time())
while True:
    time.sleep(0.5)
    if time.time() - last_update > UPDATE_INTERVAL:
        last_update = time.time()
        secret = lib_hmac.gen_secret()
        print(f"[{last_update}] UPDATING KEY")
        for agent, pub_key in list_of_radars.items():
            # cipher the key or whatever and send to the agent, along with own public key
            agent_box = public.Box(private_key, public.PublicKey(pub_key))
            sock.sendto(agent_box.encrypt(secret), agent)
        print("\\ Overall took {} seconds".format(str(time.time() - last_update)[:6]))
