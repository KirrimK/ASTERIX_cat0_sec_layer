"""
ASTERIX Cat0 Security Layer
Sender Gateway

The Sender Gateway is the component of the system that adds a layer of authentication to all ASTERIX
packets emitted by a sensor (such as a radar).
It communicates with its clients to send signed messages and update the secret used for validation
"""

import threading
import lib, json
import sys
import socket, struct
import time
import logging

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)

INTERVAL = 15
PRIVATEKEY, PUBLICKEY = lib.eddsa_generate()

logging.info("Started Sender gateway")

# getting configuration from files
config: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")

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

def refresh_keypair() -> None:
    """Updates the keypair,
    then sends the public key to all members of all groups using each group's IEK.
    get the key of each receiver in return"""
    global PRIVATEKEY, PUBLICKEY, GROUPS
    logging.info("Refreshing keypair")
    PRIVATEKEY, PUBLICKEY = lib.eddsa_generate() # generate keypair
    for group in GROUPS:
        payload = lib.fernet_iek_cipher(group["iek"], PUBLICKEY._key)
        for receiver in group["expected_receivers"]:
            try:
                group_sock = socket.socket()
                group_sock.settimeout(1)
                group_sock.connect((receiver["ip"], receiver["port"]))
                group_sock.send(b'k'+payload)
                ciph_data = group_sock.recv(2048)
                deciph_data = lib.fernet_iek_decipher(group["iek"], ciph_data)
                if deciph_data is None:
                    logging.error(f"Error while deciphering receiver {receiver}'s public key")
                else:
                    receiver["public"] = lib.signing.VerifyKey(deciph_data)
                    logging.info(f"Got receiver {receiver}'s public key")
                group_sock.close()
            except Exception as e:
                logging.error(f"error while sending key to receiver {receiver}: {e}")
        

def update_secret() -> None:
    """Updates the secret of the sensor and sends that update to its receivers across different user_groups"""
    global PRIVATEKEY, GROUPS
    logging.info("Updating secrets")
    for group in GROUPS:
        group["secret"] = lib.hmac_generate()
        payload = group["secret"] + lib.eddsa_sign(PRIVATEKEY, group["secret"])
        # send the secret to each receiver in group
        for receiver in group["expected_receivers"]:
            rpub = receiver.get("public", None)
            if rpub is None:
                logging.error(f"Did not have {receiver}'s pubkey")
            else:
                encr_payload = lib.curve_encr(rpub, payload)
                sock = socket.socket()
                sock.settimeout(1)
                try:
                    sock.connect((receiver["ip"], receiver["port"]))
                    sock.send(b's'+encr_payload)
                    sock.close()
                except Exception as e:
                    rip = receiver["ip"]
                    logging.error(f"Error while sending secret to receiver {rip}: {e}")

DONE = False

def auto_secret():
    global INTERVAL, DONE
    last = 0
    while not DONE:
        if (time.time() - last) >= INTERVAL:
            last = time.time()
            update_secret()

refresh_keypair()

thd_autosec = threading.Thread(target=auto_secret)
thd_autosec.start()

sockmt = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
sockmt.settimeout(0.5)

if GATEWAY:
    logging.info("Launched gateway mode")
    sockmtgate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockmtgate.bind(('', LEGACY_PORT)) # type: ignore
    groupmtgate = socket.inet_aton(LEGACY_IP) # type: ignore
    mreqgate=struct.pack('4sL',groupmtgate,socket.INADDR_ANY)
    sockmtgate.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreqgate)
    logging.info("Initialized receiver of raw messages")
    while True:
        data, (addr, _) = sockmtgate.recvfrom(1024)
        logging.info(f"Received message from {addr}. Signing and distributing")
        for group in GROUPS:
            sign = lib.hmac_sign(group["secret"], data)
            sockmt.sendto(data + sign, (group["asterix_multicast_ip"], group["asterix_multicast_port"]))
        logging.info("Message was distributed")
else:
    logging.info("Launched interactive mode")
    while not DONE:
        message = ""
        try:
            message = input("> ")
        except KeyboardInterrupt:
            DONE = True
            break
        if message == "q":
            DONE = True
            break
        if message == "#secret":
            update_secret()
            continue
        if message == "#key":
            refresh_keypair()
            continue
        message_ba = bytearray(48)
        message_ba[:min(len(message), 48)] = bytes(message, "utf-8")[:min(len(message), 48)]
        message_bytes = bytes(message_ba)
        logging.info(f"Sending message [{message_bytes}]")
        for group in GROUPS:
            sign = lib.hmac_sign(group["secret"], message_bytes)
            sockmt.sendto(message_bytes + sign, (group["asterix_multicast_ip"], group["asterix_multicast_port"]))
        logging.info("Message was sent")
    logging.info("Exiting interactive mode")

logging.info("Shutting down node")
