import random
import nacl.public as public
import time
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
secret = bytes(20)

private_key = public.PrivateKey(bytes(32))
public_key = private_key.public_key

print("This key server's public key is: {}".format(public_key))

list_of_all_agents_and_their_public_keys = {
    ("127.0.0.1", 42069): public_key.encode(),
    ("127.0.0.1", 42070): public_key.encode(),
}

UPDATE_INTERVAL = 60

last_update = 0
random.seed(time.time())
while True:
    time.sleep(0.5)
    if time.time() - last_update > UPDATE_INTERVAL:
        last_update = time.time()
        secret = random.randbytes(20)
        print(f"[{last_update}] UPDATING KEY")
        for agent, pub_key in list_of_all_agents_and_their_public_keys.items():
            # cipher the key or whatever and send to the agent, along with own public key
            agent_box = public.Box(private_key, public.PublicKey(pub_key))
            print(f"\\ sending to {agent}")
            sock.sendto(agent_box.encrypt(secret)+pub_key, agent)

