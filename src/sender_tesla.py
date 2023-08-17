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
import secrets

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)
logging.info("Started Sender gateway")

# getting configuration from files
config: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")

MULTICAST_IP: str = config["multicast_ip"]
MULTICAST_PORT: int = config["multicast_port"]
INTERFACE_IP: str = config["interface_ip"]
TCP_PORT: int = config["tcp_port"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")
logging.info(f"Interface ip is: {INTERFACE_IP}")
logging.info("Configuration successfully loaded")


###Socket send multicast UDP
sockmts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sockmts.settimeout(0.2)
ttl = struct.pack('b',1)
sockmts.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(INTERFACE_IP))

###socket receive multicast UDP
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
rate_seconds = 0.05
upper_bound_network_delay_seconds = 100
rtt_seconds = 1

sender = tesla.sender_setup(private_seed=private_seed, key_chain_length=N, rate_seconds=rate_seconds, upper_bound_network_delay_seconds=upper_bound_network_delay_seconds, rtt_seconds=rtt_seconds)
#max_key = sender.key_chain[len(sender.key_chain)-1]

###Global Variable
IS_UPDATING : bool = False
NONCE : str | None =  None
KNOWN_RECEIVERS : list[str] = []

###Syncronisation
def listenUDP(sender):
    global INTERFACE_IP
    try:
        while True:
            data, address = sockmtr.recvfrom(2048) 
            print(data)
            if data[:17] == b'WhoAreTheSenders?':
                payload = b'ReplySenderRequest'+ struct.pack('i', TCP_PORT)
                print(f"Payload : {payload}")
                sockmts.sendto(payload, (MULTICAST_IP,MULTICAST_PORT))
            if data[:5] == b'Nonce':
                logging.info(f"Received nonce from receiver at {address}")
                sender_time = time()
                payload = data[5:] + bytes(sender.key_chain[len(sender.key_chain)-1], 'utf-8') + struct.pack('ddiid', sender.T_int, sender.T0, sender.key_chain_lenght, sender.d, sender_time)
                sockmts.sendto(payload, (MULTICAST_IP,MULTICAST_PORT))
                logging.info(f"Sent sender time and necessary information to receiver at {address}")
            if data[:17] == b'ConfirmUpdateDone':
                if data[3:3+32] == NONCE:
                    IS_UPDATING = False
                    logging.info(f"Finished updating key chain")
            sleep(0.05/1000)
    except Exception as e:
        print(e)

def listenTCP():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socktcp:
        socktcp.bind((INTERFACE_IP, TCP_PORT))
        socktcp.listen()
        conn, addr = socktcp.accept()
        with conn:
            print(f"Connected by {addr}")
            while 1:
                data = conn.recv(1024)
                if not data: break
            print(f"Date: {data}")    
            


def send_tesla_packet(message: bytes):
    global IS_UPDATING, NONCE
    message_time = time()
    if message_time >= sender.last_T - sender.d * sender.T_int:
        tesla.renew_key_chain(sender, message_time)

        NONCE = bytes(secrets.token_hex(16), 'utf-8')
        #print(f"{NONCE}, {bytes(sender.key_chain[0], 'utf-8')}, {sender.T_int, sender.T0}")
        update_recv_packet = b"Update"+ NONCE + bytes(sender.key_chain[0], 'utf-8') + struct.pack("dd", sender.T_int, sender.T0)
        IS_UPDATING = True
        sockmts.sendto(update_recv_packet, (MULTICAST_IP,MULTICAST_PORT))
        while IS_UPDATING == True:
            sleep(0.01/1000)

        packet = tesla.send_message(message=b"Disclosing previous key chain", sender_obj=sender, end=True)
        packet_bytes = packet[0]+packet[1]+bytes(packet[2], 'utf-8')+ packet[3].to_bytes(4, byteorder='big',signed=True) # type: ignore
        sockmts.sendto(packet_bytes, (MULTICAST_IP,MULTICAST_PORT))

    tesla_packet = tesla.send_message(message=message, sender_obj=sender, end=False)
    #print(tesla_packet)
    #logging.info(f"Created tesla packet using the message {message}")
    tesla_packet_bytes = tesla_packet[0]+tesla_packet[1]+bytes(tesla_packet[2], 'utf-8')+ tesla_packet[3].to_bytes(4, byteorder='big', signed=True) # type: ignore
    sockmts.sendto(tesla_packet_bytes, (MULTICAST_IP,MULTICAST_PORT))
    #print("sent")

if __name__ == '__main__':

    # start listening on the socket using a different thread
    thd_listenning_UDP = threading.Thread(target=listenUDP, args=[sender])
    thd_listenning_UDP.start()

    thd_listenning_TCP = threading.Thread(target=listenTCP)
    thd_listenning_TCP.start()

    # On user input, send 10 times 10000 messages in multicast.
    print('press s to start sendin messages')
    while True:
        key = input()
        if key == 's':
            for a in range(10):
                send_tesla_packet(message=b'start')
                for i in range(10000):
                    send_tesla_packet(message=f"{i}".encode("utf-8"))
                    sleep(rate_seconds/1000)
                send_tesla_packet(message=b'fin')