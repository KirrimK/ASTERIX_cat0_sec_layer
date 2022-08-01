"""
ASTERIX Cat0 Security Layer
Sensor Gateway

The Sensor Gateway is the component of the system that adds a layer of authentication to all ASTERIX
packets emitted by a sensor (such as a radar).
It communicates with the CA to validate its own key,
and with its clients to send signed messages and update the secret used for validation
"""

import lib, json
import threading
import socket
import requests

SIGNKEY: lib.signing.SigningKey = None
VERIFYKEY: lib.signing.VerifyKey = None
SECRET: bytes = None

# getting configuration from files
config: dict = json.loads(input("Config path?"))
GROUPS: list[dict] = config["user_groups"]
for group in GROUPS:
    group["iek"] = lib.load_IEK_from_file(group["iek_path"])
# -----

def validate_and_relay_keys(groupconfig: dict) -> None:
    """For a given usergroup, sends the verifykey to the group's CA,
    waits for verification and then sends to all receivers in usergroup"""
    global SIGNKEY, VERIFYKEY
    iek = group["iek"]
    msg = 0x0C + lib.aes_iek_cipher(iek, VERIFYKEY._key)
    pass

def refresh_keypair() -> None:
    """Updates the keypair,
    then performs validate_and_relay_keys for each user group (a thread per group)"""
    global SIGNKEY, VERIFYKEY, GROUPS
    SIGNKEY, VERIFYKEY = lib.eddsa_generate() # generate keypair
    thd_list = [threading.Thread(target=validate_and_relay_keys, args=(group,)) for group in GROUPS]
    for thd in thd_list:
        thd.run()

def update_secret() -> None:
    """Updates the secret of the sensor and sends that update to its receivers across different user_groups"""
    global SIGNKEY, GROUPS, SECRET
    SECRET = lib.hmac_generate()
    for group in GROUPS:
        # send the secret to each receiver in group
        pass


refresh_keypair()
update_secret()

DONE = False
while not done:
    print("> ", end="")
    message = "q"
    try:
        message = input()
    except EOFError:
        print("EOF'd, quitting")
    if message == "q":
        done = True
    else:
        pass
        # try:
        #     pass
        #     # message_ba = bytearray(48)
        #     # message_ba[:min(len(message), 48)] = bytes(message, "ascii")[:min(len(message), 48)]
        #     # message_bytes = bytes(message_ba)
        #     # for key_serv_ip, multicast_group in dict_multicast.items():
        #     #     if SECRETS.get(key_serv_ip, None) is not None:
        #     #         start = time.time()
        #     #         big_msg = lib_hmac.sign_and_assemble_message_sha1(message_bytes, SECRETS[key_serv_ip])
        #     #         sock.sendto(big_msg, multicast_group)
        #     #         print("-- sent to group [{}]".format(key_serv_ip)+" (temps : {})".format(time.time()-start))
        # except KeyboardInterrupt:
        #     print("Interrupted, quitting")
        #     done = True
        # except Exception as e:
        #     print("Error: "+str(e))

# -----