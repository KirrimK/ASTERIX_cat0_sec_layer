"""
ASTERIX Cat0 Security Layer
Sensor Gateway

The Sensor Gateway is the component of the system that adds a layer of authentication to all ASTERIX
packets emitted by a sensor (such as a radar).
It communicates with the CA to validate its own key,
and with its clients to send signed messages and update the secret used for validation
"""

import lib, json
import sys
import threading
import socket

SIGNKEY, VERIFYKEY = lib.eddsa_generate()
SECRET = lib.hmac_generate()

# getting configuration from files
config: dict = json.load(open(sys.argv[1], "r"))
GROUPS: list[dict] = config["user_groups"]
for group in GROUPS:
    group["iek"] = lib.load_IEK_from_file(group["iek_path"])
# -----

def get_ca_pubkey(group: dict):
    ca_key = lib.get_ca_public_key(group["iek"], group["ca_ip"], group["ca_port"])
    if ca_key is None:
        print(f"[Sensor] Error while getting ({group['ca_ip']}) CA PubKey")
        return
    group["ca_pubkey"] = ca_key
    print(f"[Sensor] ({group['ca_ip']}) CA PubKey is {str(group['ca_pubkey'])}")

def validate_and_relay_keys(group: dict) -> None:
    """For a given usergroup, sends the verifykey to the group's CA,
    waits for verification and then sends to all receivers in usergroup"""
    global SIGNKEY, VERIFYKEY
    signedmsg = lib.send_key_ca_validation(group["iek"], group["ca_pubkey"], VERIFYKEY, group["ca_ip"], group["ca_port"])
    if signedmsg is None:
        print("[Sensor] Failed to get CA to authorise key")
        return
    print("[Sensor] CA authorised key: "+str(signedmsg))
    for receiver in group["expected_receivers"]:
        print("[Sensor] Sending Signed PubKey to "+str(receiver))
        sock = socket.socket()
        try:
            sock.connect((receiver["ip"], receiver["port"]))
            sock.send(b'k' + signedmsg)
            sock.close()
        except Exception as e:
            print(e)

def get_ca_pubkey_and_validate(group: dict):
    get_ca_pubkey(group)
    validate_and_relay_keys(group)

def refresh_keypair() -> None:
    """Updates the keypair,
    then performs validate_and_relay_keys for each user group (a thread per group)"""
    global SIGNKEY, VERIFYKEY, GROUPS
    SIGNKEY, VERIFYKEY = lib.eddsa_generate() # generate keypair
    print("[Sensor] Updated Keypair, validating and relaying...")
    thd_list = [threading.Thread(target=get_ca_pubkey_and_validate, args=(group,)) for group in GROUPS]
    for thd in thd_list:
        thd.start()
    for thd in thd_list:
        thd.join()

def update_secret() -> None:
    """Updates the secret of the sensor and sends that update to its receivers across different user_groups"""
    global SIGNKEY, GROUPS, SECRET
    SECRET = lib.hmac_generate()
    print("[Sensor] Updated Secret: "+str(SECRET))
    payload = lib.eddsa_sign(SIGNKEY, SECRET)
    for group in GROUPS:
        # send the secret to each receiver in group
        ciph_payload = lib.fernet_iek_cipher(group["iek"], SECRET + payload)
        for receiver in group["expected_receivers"]:
            print("[Sensor] Sending Secret to "+str(receiver))
            sock = socket.socket()
            try:
                sock.connect((receiver["ip"], receiver["port"]))
                sock.send(b's'+ciph_payload)
                sock.close()
            except Exception as e:
                print(e)

refresh_keypair()
update_secret()

sockmt = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
sockmt.settimeout(0.5)

DONE = False
while not DONE:
    message = ""
    try:
        message = input()
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
        sign = lib.hmac_sign(SECRET, message_bytes)
        sockmt.sendto(message_bytes + sign, (group["asterix_multicast_ip"], group["asterix_multicast_port"]))
