"""
ASTERIX Cat0 Security Layer
Sender Gateway

The Sender Gateway is the component of the system that adds a layer of authentication to all ASTERIX
packets emitted by a sensor (such as a radar).
It communicates with its clients to send signed messages and update the secret used for validation

It uses georgesmakrakis implemention of TESLA protocol for authentification.
(needs to add synchronisation protocol)
"""

import threading
import lib, json
import sys
import socket, struct
import time
import logging
import TESLA.main_RFC as tesla
from math import ceil, floor
from time import time # perf_counter, sleep

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)
logging.info("Started Sender gateway")

# getting configuration from files
config: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")

MULTICAST_IP: str = config["multicast_ip"]
MULTICAST_PORT: int = config["multicast_port"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")

logging.info("Configuration successfully loaded")

###Socket send multicast
mt_g = (MULTICAST_IP, MULTICAST_PORT)
sockmts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmts.settimeout(60)
ttl = struct.pack('b',1)
sockmts.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

###socket receive multicast
server_address = ('', 10001)
sockmtr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmtr.bind(server_address)
group = socket.inet_aton(MULTICAST_IP)
mreq = struct.pack('4sl', group, socket.INADDR_ANY)
sockmtr.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

###Sender object
private_seed = b"Hello world"
N = 10
rate = 3
upper_bound_network_delay = 4

sender = tesla.sender_setup(private_seed=private_seed, key_chain_length=N, rate=rate, upper_bound_network_delay=upper_bound_network_delay)
max_key = sender.key_chain[len(sender.key_chain)-1]

###Syncronisation
def syncro(max_key, T_int, T0, chain_lenght, disclosure_delay):
    try:
        while True:
            print('hi')
            nonce, address = sockmtr.recv(2048)
            logging.info(f"Received nonce from receiver at {address}")
            sender_time = time()
            payload = struct.pack('8iiiiif', nonce, max_key, T_int, T0, chain_lenght, disclosure_delay, sender_time)
            sockmts.sendto(payload, (MULTICAST_IP,MULTICAST_PORT))
            logging.info("Sent sender time and necessary information to receiver at {add}")
    except Exception as e:
        print(e)
            
thd_syncro = threading.Thread(target=syncro, args=(max_key, sender.T_int, sender.T0, N, sender.d))
thd_syncro.start()


