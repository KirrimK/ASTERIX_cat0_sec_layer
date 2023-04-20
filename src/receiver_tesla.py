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
INTERFACE_IP: str = CONFIG["interface_ip"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")
logging.info(f"")

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

MAX_KEY: str | None = None
T_INT: float
T0: float
CHAIN_LENGHT: int
DISCLOSURE_DELAY: int
SENDER_TIME: float
TIME_RESP: float
NONCE = bytes(secrets.token_hex(16), 'utf-8')

def listen():
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE
    try:
        while True:
                message, address = sockmtr.recvfrom(2048)
                if message[:32] == NONCE: 
                    logging.info(f"Received response to nonce from sender at {address}")
                    TIME_RESP = time()
                    MAX_KEY = str(message[32:64+32], 'utf-8') 
                    other_values =struct.unpack('ffiif', message[64+32:])
                    T_INT = float(other_values[0]) 
                    T0 = float(other_values[1]) 
                    CHAIN_LENGHT = int(other_values[2]) 
                    DISCLOSURE_DELAY = int(other_values[3]) 
                    SENDER_TIME = float(other_values[4]) 
                    logging.info(f"Successfully receive parameters from sender at {address}")
                elif message[:6] == b'Update':
                    logging.info(f"Updating key chain")
                    updated_T = struct.unpack('ff', message[38:])
                    tesla.update_receiver(last_key=str(message[6:38]),T_int=float(updated_T[0]), T0=float(updated_T[1]), sender_interval=floor(((time()+receiver.D_t)-float(updated_T[1])) /  float(updated_T[0])), receiver=receiver)
                    sockmts.sendto(b'Updated' + NONCE, (MULTICAST_IP,MULTICAST_PORT))
                elif len(message)>=100:
                    disclosed_key_index = message[-4:]
                    disclosed_key = message[-68:-4]
                    hmac = message[-100:-68]
                    mes = message[:-100]
                    packet = (mes, hmac, str(disclosed_key, encoding='utf-8'), int.from_bytes(disclosed_key_index, 'big'))
                    print(packet)
                    tesla.receive_message(packet=packet, receiver_obj=receiver)
    except Exception as e:
        print(e)
    logging.info("Socket timed out")

thd_syncro = threading.Thread(target=listen)
thd_syncro.start()

def syncro_init():
    receiver_time = time()
    global NONCE, MULTICAST_IP, MULTICAST_PORT
    sockmts.sendto(b'Nonce' + NONCE, (MULTICAST_IP,MULTICAST_PORT))
    logging.info(f"Sent nonce {NONCE} to sender")
    return receiver_time

def syncro():
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE
    receiver_time = syncro_init()
    while MAX_KEY == None:
        sleep(1)    
    D_t = SENDER_TIME - receiver_time + 0.1
    sender_interval = floor((time()* 1000 - T0) * 1.0 / T_INT)
    receiver = tesla.boostrap_receiver(last_key=MAX_KEY, T_int=T_INT, T0 = T0,
                                        chain_length=CHAIN_LENGHT, disclosure_delay=DISCLOSURE_DELAY,
                                          sender_interval=sender_interval, D_t=D_t)
    return receiver

receiver = syncro()
print(receiver.__dict__)



     








