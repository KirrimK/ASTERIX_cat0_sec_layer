"""
ASTERIX Cat0 Security Layer
Receiver Gateway

The Receiver Gateway processes all inbound ASTERIX traffic to verify if the messages have been signed by
a legitimate sensor.
It receives a CA public key from the CA used to validate Sensor public keys,
and receives Sensor public keys used to verify the authenticity of secrets sent regularly by Sensors.
Those secrets are then used to verify the authenticity of each ASTERIX message sent by a sensor.
"""

import lib, json
import sys
import socket
import threading

# getting configuration from files
CONFIG: dict = json.load(open(sys.argv[1], "r"))
IEK: bytes = lib.load_IEK_from_file(CONFIG["iek_path"])
CA_IP: str = CONFIG["ca_ip"]
CA_PORT: int = CONFIG["ca_port"]
BOUND_IP: str = CONFIG["bound_ip"]
BOUND_PORT: int = CONFIG["bound_port"]
MULTICAST_IP: str = CONFIG["multicast_ip"]
MULTICAST_PORT: int = CONFIG["multicast_port"]
# -----

# request public key from CA
CA_VERIFYKEY: lib.signing.VerifyKey = lib.get_ca_public_key(IEK, CA_IP, CA_PORT)
if CA_VERIFYKEY is None:
    print("[Receiver] Error when tried to get CA's PubKey")
else:
    print("[Receiver] Got CA's PubKey: "+str(CA_VERIFYKEY))

SENSOR_KEYS: dict[str] = {}

def listen_sensor_keys():
    global SENSOR_KEYS, CA_VERIFYKEY
    sock = socket.socket()
    try:
        sock.bind((BOUND_IP, BOUND_PORT))
        sock.listen()
        while True:
            client, (address, port) = sock.accept()
            data = client.recv(2048)
            client.close()
            decr_signedmsg = lib.fernet_iek_decipher(IEK, data)
            msg = decr_signedmsg[:-64]
            signature = decr_signedmsg[-64:]
            if lib.eddsa_verify(CA_VERIFYKEY, signature, msg):
                SENSOR_KEYS[address] = lib.signing.VerifyKey(msg)
                print(f"[Receiver] Sensor ({address}) updated its PubKey")
            else:
                SENSOR_KEYS[address] = None
                print(f"[Receiver] Sensor ({address}) tried to update its key, but could not be trusted")
    except Exception as e:
        print(e)

thd = threading.Thread(target=listen_sensor_keys)
thd.run()

input()
