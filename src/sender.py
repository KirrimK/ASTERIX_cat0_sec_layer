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
import socket
import time

INTERVAL = 15
PRIVATEKEY, PUBLICKEY = lib.eddsa_generate()

# getting configuration from files
config: dict = json.load(open(sys.argv[1], "r"))
GROUPS: list[dict] = config["user_groups"]
for group in GROUPS:
    group["iek"] = lib.load_IEK_from_file(group["iek_path"])
    group["secret"] = lib.hmac_generate()
# -----

def refresh_keypair() -> None:
    """Updates the keypair,
    then sends the public key to all members of all groups using each group's IEK.
    get the key of each receiver in return"""
    global PRIVATEKEY, PUBLICKEY, GROUPS
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
                    print(f"Error while deciphering receiver {receiver}'s public key")
                else:
                    receiver["public"] = lib.signing.VerifyKey(deciph_data)
                    print(f"Got receiver {receiver}'s public key")
                group_sock.close()
            except Exception as e:
                print(e, f"error while sending key to receiver {receiver}")
        

def update_secret() -> None:
    """Updates the secret of the sensor and sends that update to its receivers across different user_groups"""
    global PRIVATEKEY, GROUPS
    print("[Sensor] Updating secrets")
    for group in GROUPS:
        group["secret"] = lib.hmac_generate()
        payload = group["secret"] + lib.eddsa_sign(PRIVATEKEY, group["secret"])
        # send the secret to each receiver in group
        for receiver in group["expected_receivers"]:
            rpub = receiver.get("public", None)
            if rpub is None:
                print(f"Did not have {receiver}'s pubkey")
            else:
                encr_payload = lib.eddsa_encr(rpub, payload)
                print("[Sensor] Sending Secret to "+str(receiver))
                sock = socket.socket()
                sock.settimeout(1)
                try:
                    sock.connect((receiver["ip"], receiver["port"]))
                    sock.send(b's'+encr_payload)
                    sock.close()
                except Exception as e:
                    print(e)

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
    message_ba[:min(len(message), 48)] = bytes(message, "ascii")[:min(len(message), 48)]
    message_bytes = bytes(message_ba)
    for group in GROUPS:
        sign = lib.hmac_sign(group["secret"], message_bytes)
        sockmt.sendto(message_bytes + sign, (group["asterix_multicast_ip"], group["asterix_multicast_port"]))
