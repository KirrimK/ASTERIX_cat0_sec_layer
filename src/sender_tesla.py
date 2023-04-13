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
from time import time, sleep # perf_counter, sleep

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)
logging.info("Started Sender gateway")

# getting configuration from files
config: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")

MULTICAST_IP: str = config["multicast_ip"]
MULTICAST_PORT: int = config["multicast_port"]
INTERFACE_IP: str = config["interface_ip"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")
logging.info(f"Interface ip is: {INTERFACE_IP}")
logging.info("Configuration successfully loaded")


###Socket send multicast
mt_g = (MULTICAST_IP, MULTICAST_PORT)
sockmts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sockmts.settimeout(0.2)
ttl = struct.pack('b',1)
sockmts.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(INTERFACE_IP))

###socket receive multicast
server_address = (MULTICAST_IP, MULTICAST_PORT)
sockmtr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
try:
    sockmtr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
except AttributeError:
    pass
sockmtr.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
sockmtr.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

sockmtr.bind(server_address)
sockmtr.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(INTERFACE_IP))
sockmtr.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(MULTICAST_IP)+ socket.inet_aton(INTERFACE_IP))

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
            nonce, address = sockmtr.recvfrom(2048)
            print(nonce)
            if nonce[:5] == b'Nonce':
                logging.info(f"Received nonce from receiver at {address}")
                sender_time = time()
                payload = nonce + bytes(max_key, 'utf-8') + struct.pack('ifiif', T_int, T0, chain_lenght, disclosure_delay, sender_time)
                print(payload)
                sockmts.sendto(payload, (MULTICAST_IP,MULTICAST_PORT))
                logging.info(f"Sent sender time and necessary information to receiver at {address}")
            sleep(1)
            nonce = b''
    except Exception as e:
        print(e)
            
thd_syncro = threading.Thread(target=syncro, args=(max_key, sender.T_int, sender.T0, N, sender.d))
thd_syncro.start()


