import random
import lib_hmac
import nacl
import time
import socket

UDP_IP = "192.168.1.193"
UDP_PORT = 42070

CLIENT_PORT = 42070

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

secret = bytes(20)

private_key = nacl.public.PrivateKey.generate()
public_key = private_key.public_key

print("This key server's public key is: {}".format(public_key.hex()))

list_of_all_agents_and_their_public_keys = {}

UPDATE_INTERVAL = 60

last_update = time.time()
while True:
    if time.time() - last_update > UPDATE_INTERVAL:
        last_update = time.time()
        secret = random.randbytes(20)
        for agent_ip, pub_key in list_of_all_agents_and_their_public_keys.items():
            # cipher the key or whatever and send to the agent, along with own public key
            agent_box = nacl.public.Box(private_key, nacl.public.PublicKey(pub_key))
            sock.sendto(agent_box.encrypt(secret)+pub_key, (agent_ip, 42069))

