"""
ASTERIX Cat0 Security Layer
Receiver Gateway

The Receiver Gateway processes all inbound ASTERIX traffic to verify if the messages have been signed by
a legitimate sensor.
This version uses georgesmakrakis implemention of TESLA protocol for authentification.
(needs to add synchronisation protocol)
"""

import lib, json
import sys
import socket, struct
import threading
import logging
from math import ceil, floor
from time import time, sleep
import TESLA.main_RFC as tesla
import secrets

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)

logging.info("Started Receiver Gateway")
# getting configuration from files
CONFIG: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")


MULTICAST_IP: str = CONFIG["multicast_ip"]
MULTICAST_PORT: int = CONFIG["multicast_port"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")


logging.info("Configuration successfully loaded")

###Socket send multicast
mt_g = (MULTICAST_IP, MULTICAST_PORT)
sockmts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmts.settimeout(0.5)
ttl = struct.pack('b',1)
sockmts.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

###socket receive multicast
server_address = ('', 10001)
sockmtr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmtr.bind(server_address)
group = socket.inet_aton(MULTICAST_IP)
mreq = struct.pack('4sl', group, socket.INADDR_ANY)
sockmtr.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

MAX_KEY: str | None = None
T_INT: int
T0: float
CHAIN_LENGHT: int
DISCLOSURE_DELAY: int
SENDER_TIME: float
TIME_RESP: float
NONCE = bytes(secrets.token_hex(16), 'utf-8')

def syncro_resp():
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE
    try:
        while True:
                nonce_resp, address = sockmtr.recv(2048)
                logging.info(f"Received response to nonce from sender at {address}")
                if isinstance(nonce_resp, (tuple)) and nonce_resp[0] == NONCE: 
                    TIME_RESP = time()
                    MAX_KEY = str(nonce_resp[1]) 
                    T_INT = int(nonce_resp[2]) 
                    T0 = float(nonce_resp[3]) 
                    CHAIN_LENGHT = int(nonce_resp[4]) 
                    DISCLOSURE_DELAY = int(nonce_resp[5]) 
                    SENDER_TIME = float(nonce_resp[6]) 
                    logging.info("Successfully receive parameters from sender at {address}")
    except Exception as e:
        print(e)
    logging.info("Socket timed out")

thd_syncro = threading.Thread(target=syncro_resp)
thd_syncro.start()

def syncro_init(nonce):
    receiver_time = time()
    sockmts.sendto(nonce, (MULTICAST_IP,MULTICAST_PORT))
    logging.info("Sent nonce to sender")
    return receiver_time

def syncro():
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE
    receiver_time = syncro_init(NONCE)
    while MAX_KEY == None:
        sleep(1)
    D_t = SENDER_TIME - receiver_time + 0.1
    sender_interval = floor((time()* 1000 - T0) * 1.0 / T_INT)
    receiver = tesla.boostrap_receiver(last_key=MAX_KEY, T_int=T_INT, T0 = T0,
                                        chain_length=CHAIN_LENGHT, disclosure_delay=DISCLOSURE_DELAY,
                                          sender_interval=sender_interval, D_t=D_t)
    return receiver

syncro()
     








