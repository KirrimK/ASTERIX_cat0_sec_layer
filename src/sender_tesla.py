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

BOUND_IP: str = config["bound_ip"]
BOUND_PORT: int = config["bound_port"]
logging.info(f"Binding to IP addr {BOUND_IP}:{str(BOUND_PORT)} for keys")

MULTICAST_IP: str = config["multicast_ip"]
MULTICAST_PORT: int = config["multicast_port"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")

SELF_EXT_IP: str = config["self_ext_ip"]
logging.info(f"Own IP address should be {SELF_EXT_IP}")

GATEWAY = config["mode"]=="gateway"
logging.info("Gateway mode engaged" if GATEWAY else "Gateway mode disengaged")

if GATEWAY:
    LEGACY_IP = config["legacy_input_mcast_ip"]
    LEGACY_PORT = int(config["legacy_input_mcast_port"])
    logging.info(f"Gateway legacy traffic will be taken from multicast {LEGACY_IP}:{str(LEGACY_PORT)}")

GROUPS: list[dict] = config["user_groups"]
for group in GROUPS:
    logging.info("Start of group information")
    group["iek"] = lib.load_IEK_from_file(group["iek_path"])
    logging.info("Group IEK located at "+group["iek_path"])
    group["secret"] = lib.hmac_generate()
    for user in group["expected_receivers"]:
        logging.info("Expecting receiver at "+user["ip"]+":"+str(user["port"]))
    logging.info("Group secure traffic will be sent to multicast "+group["asterix_multicast_ip"]+":"+str(group["asterix_multicast_port"]))
    logging.info("End of group information")
# -----

logging.info("Configuration successfully loaded")

###Socket
sockmt = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
sockmt.settimeout(0.5)

###Sender object
private_seed = b"Hello world"
N = 10
rate = 3
upper_bound_network_delay = 4

sender = tesla.sender_setup(private_seed=private_seed, key_chain_length=N, rate=rate, upper_bound_network_delay=upper_bound_network_delay)
max_key = sender.key_chain[len(sender.key_chain)-1]

###Syncronisation
def syncro(max_key, T_int, T0, chain_lenght, disclosure_delay, sockmt):
    sock = socket.socket()
    try:
        sock.bind((BOUND_IP, BOUND_PORT))
        sock.listen()
        while True:
                client, (address, port) = sock.accept()
                data = client.recv(2048)
                logging.info(f"Received nonce from receiver at {address}")
                nonce = client.recv(2048)
                sender_time = time()
                sockmt.sendto((nonce, max_key, T_int, T0, chain_lenght, disclosure_delay, sender_time), (group["asterix_multicast_ip"], group["asterix_multicast_port"]))
                logging.info("Sent sender time and necessary information to receiver at {add}")
    except Exception as e:
        print(e)
    sock.close()
            



