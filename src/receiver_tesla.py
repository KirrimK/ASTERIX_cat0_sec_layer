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
from time import time
import TESLA.main_RFC as tesla
import secrets

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)

logging.info("Started Receiver Gateway")
# getting configuration from files
CONFIG: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")

BOUND_IP: str = CONFIG["bound_ip"]
BOUND_PORT: int = CONFIG["bound_port"]
logging.info(f"Binding to IP addr {BOUND_IP}:{str(BOUND_PORT)} for keys")

MULTICAST_IP: str = CONFIG["multicast_ip"]
MULTICAST_PORT: int = CONFIG["multicast_port"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")

SELF_EXT_IP: str = CONFIG["self_ext_ip"]
logging.info(f"Own IP address should be {SELF_EXT_IP}")

GATEWAY = CONFIG["mode"]=="gateway"
logging.info("Gateway mode engaged" if GATEWAY else "Gateway mode disengaged")

if GATEWAY:
    LEGACY_IP = CONFIG["legacy_output_mcast_ip"]
    LEGACY_PORT = CONFIG["legacy_output_mcast_port"]
    logging.info(f"Gateway traffic will be relayed to multicast {LEGACY_IP}:{str(LEGACY_PORT)}")

    RELAY_OK = CONFIG["actions"]["sign_ok"]=="relay"
    logging.info("Rule (sign_ok -> "+ ("relay)" if RELAY_OK else "drop)"))
    RELAY_NO = CONFIG["actions"]["sign_no"]=="relay"
    logging.info("Rule (sign_no -> "+ ("relay)" if RELAY_NO else "drop)"))
    RELAY_NO_SEC = CONFIG["actions"]["no_sec"]=="relay"
    logging.info("Rule (no HMAC key -> "+ ("relay)" if RELAY_NO_SEC else "drop)"))
# -----

logging.info("Configuration successfully loaded")

sockmt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmt.bind(('', MULTICAST_PORT))
groupmt = socket.inet_aton(MULTICAST_IP)
mreq=struct.pack('4sL',groupmt,socket.INADDR_ANY)
sockmt.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)

sockmtgate = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
sockmtgate.settimeout(0.5)

MAX_KEY: str | None = None
T_INT: int
T0: float
CHAIN_LENGHT: int
DISCLOSURE_DELAY: int
SENDER_TIME: float
TIME_RESP: float
NONCE = secrets.token_hex(16)

def syncro_resp(nonce):
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE
    sock = socket.socket()
    try:
        sock.bind((BOUND_IP, BOUND_PORT))
        sock.listen()
        bool = True
        while bool:
                sender, (address, port) = sock.accept()
                data = sender.recv(2048)
                logging.info(f"Received response to nonce from sender at {address}")
                nonce_resp = sender.recv(2048)
                if nonce_resp[0] == NONCE:
                    TIME_RESP = time()
                    MAX_KEY = str(nonce_resp[1])
                    T_INT = int(nonce_resp[2])
                    T0 = float(nonce_resp[3])
                    CHAIN_LENGHT = int(nonce_resp[4])
                    DISCLOSURE_DELAY = int(nonce_resp[5])
                    SENDER_TIME = float(nonce_resp[6])
    except Exception as e:
        print(e)
    sock.close()
    logging.info("Successfully receive parameters from sender at {address}")

thd_syncro = threading.Thread(target=syncro_resp)
thd_syncro.start()

def syncro_init(nonce):
    receiver_time = time()
    sockmt.sendto(nonce, (LEGACY_IP, LEGACY_PORT))
    logging.info("Sent nonce to sender")
    return receiver_time

def syncro():
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE
    receiver_time = syncro_init(NONCE)
    while MAX_KEY == None:
        time.sleep(0.1)
    D_t = SENDER_TIME - receiver_time + 0.1
    sender_interval = floor((time()* 1000 - T0) * 1.0 / T_INT)
    receiver = tesla.boostrap_receiver(last_key=MAX_KEY, T_int=T_INT, T0 = T0,
                                        chain_length=CHAIN_LENGHT, disclosure_delay=DISCLOSURE_DELAY,
                                          sender_interval=sender_interval, D_t=D_t)
    return receiver


     








