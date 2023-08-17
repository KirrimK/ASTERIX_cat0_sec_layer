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
TCP_PORT: int = config["tcp_port"]
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

###socket TCP for time synchronization, and key chain update for receivers.

socktcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socktcp.bind(INTERFACE_IP, TCP_PORT)
socktcp.listen(1)


MAX_KEY: str | None = None
T_INT: float
T0: float
CHAIN_LENGHT: int
DISCLOSURE_DELAY: int
SENDER_TIME: float
TIME_RESP: float
NONCE = bytes(secrets.token_hex(16), 'utf-8')
TIME_START : float | None = None
TIME_END: float | None = None
LIST_TIME= []
TRIES = 0

DICT_KNOWN_SENDER = {}

def listen():
    global MAX_KEY, T_INT, T0, CHAIN_LENGHT, DISCLOSURE_DELAY, SENDER_TIME, TIME_RESP, NONCE, TIME_START, TIME_END, LIST_TIME, TRIES
    try:
        while True:
                message, address = sockmtr.recvfrom(2048)
                if message[:18] == b'ReplySenderRequest':
                    sender_addr = address
                    socktcp.send(b'hello')

                if message[:32] == NONCE:
                    logging.info(f"Received response to nonce from sender at {address}")
                    TIME_RESP = time()
                    MAX_KEY = str(message[32:64+32], 'utf-8') 
                    other_values =struct.unpack('ddiid', message[64+32:])
                    T_INT = float(other_values[0]) 
                    T0 = float(other_values[1]) 
                    CHAIN_LENGHT = int(other_values[2]) 
                    DISCLOSURE_DELAY = int(other_values[3]) 
                    SENDER_TIME = float(other_values[4]) 
                    logging.info(f"Successfully receive parameters from sender at {address}")
                elif message[:6] == b'Update':
                    #logging.info(f"Updating key chain")
                    nonce = message[6:38]
                    updated_T = struct.unpack('dd', message[38+64:])
                    tesla.update_receiver(last_key=str(message[38:38+64], encoding='utf-8'),T_int=float(updated_T[0]), T0=float(updated_T[1]), sender_interval=floor(((time()+receiver.D_t)-float(updated_T[1])) /  float(updated_T[0])), receiver=receiver)
                    sockmts.sendto(b'ConfirmUpdateDone' + nonce, (MULTICAST_IP,MULTICAST_PORT))
                elif message[:3] == b'fin':
                    TIME_END = time()
                    assert TIME_END != None and TIME_START != None
                    tot_time = TIME_END-TIME_START
                    LIST_TIME.append(tot_time)
                    print(f"Average process time for one message at iteration {TRIES} is: {sum(LIST_TIME)/(TRIES*1000)}")
                    print(f"nb auth messages: {receiver.nb_authenticated_message}")
                    #print(f"Total time: {tot_time}, average time: {tot_time/10000}")
                elif message[:5] == b'start':
                    TIME_START = time()
                    TRIES += 1
                elif len(message)>=100:
                    recv_time = time()
                    disclosed_key_index = message[-4:]
                    disclosed_key = message[-68:-4]
                    hmac = message[-100:-68]
                    mes = message[:-100]
                    packet = (mes, hmac, str(disclosed_key, encoding='utf-8'), int.from_bytes(disclosed_key_index, 'big', signed=True))
                    #print(f"packet: {packet}")
                    tesla.receive_message(packet=packet, receiver_obj=receiver, time = recv_time)
    except Exception as e:
        print(e)
    logging.info("Socket timed out")


def find_sender():
    sockmts.sendto(b'WhoAreTheSenders?', (MULTICAST_IP,MULTICAST_PORT))

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
    print(f"D_t: {D_t}")
    sender_interval = floor((time()* 1000 - T0) * 1.0 / T_INT)
    receiver = tesla.boostrap_receiver(last_key=MAX_KEY, T_int=T_INT, T0 = T0,
                                        chain_length=CHAIN_LENGHT, disclosure_delay=DISCLOSURE_DELAY,
                                          sender_interval=sender_interval, D_t=D_t)
    return receiver


if __name__=='__main__':

    # start listening on socket sockmtr using a different thread
    thd_bootstrapping_receiver = threading.Thread(target=listen)
    thd_bootstrapping_receiver.start()

    # On user input, syncronize the receiver with a sender 
    print('press s to synchronize with sender')
    while True:
        key = input()
        if key == 's':
            find_sender()
            sleep(3)
            receiver = syncro()



     








