"""
ASTERIX Cat0 Security Layer
Receiver Gateway

The Receiver Gateway processes all inbound ASTERIX traffic to verify if the messages have been signed by
a legitimate sensor.
It receives a CA public key from the CA used to validate Sensor public keys,
and receives Sensor public keys used to verify the authenticity of secrets sent regularly by Sensors.
Those secrets are then used to verify the authenticity of each ASTERIX message sent by a sensor.
"""

from click import secho
import lib, json
import sys
import socket, struct
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
SENSOR_SECRETS: dict[str] = {}

def listen_sensor_keys_secrets():
    global SENSOR_KEYS, SENSOR_SECRETS, CA_VERIFYKEY
    sock = socket.socket()
    try:
        sock.bind((BOUND_IP, BOUND_PORT))
        sock.listen()
        while True:
            client, (address, port) = sock.accept()
            data = client.recv(2048)
            client.close()
            decr_signedmsg = lib.fernet_iek_decipher(IEK, data[1:])
            if decr_signedmsg is None:
                print("[Receiver] Error while deciphering the received message")
                continue
            msg = decr_signedmsg[:-64]
            signature = decr_signedmsg[-64:]
            if data[0] == 107:#b'k':
                if lib.eddsa_verify(CA_VERIFYKEY, signature, msg):
                    SENSOR_KEYS[address] = lib.signing.VerifyKey(msg)
                    print(f"[Receiver] Sensor ({address}) updated its PubKey")
                else:
                    SENSOR_KEYS[address] = None
                    print(f"[Receiver] Sensor ({address}) tried to update its key, but could not be trusted")
            if data[0] == 115:#b's':
                if lib.eddsa_verify(SENSOR_KEYS[address], signature, msg):
                    print(f"[Receiver] Sensor ({address}) updated its secret: {msg}")
                    SENSOR_SECRETS[address] = msg
                else:
                    print(f"[Receiver] Sensor ({address}) failed to update its secret")
    except Exception as e:
        print(e)
    sock.close()

thd = threading.Thread(target=listen_sensor_keys_secrets)
thd.start()

sockmt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmt.bind(('', MULTICAST_PORT))
groupmt = socket.inet_aton(MULTICAST_IP)
mreq=struct.pack('4sL',groupmt,socket.INADDR_ANY)
sockmt.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
while True:
    data, (addr, _) = sockmt.recvfrom(1024)
    msg = data[:48]
    sign = data[48:]
    sec = SENSOR_SECRETS.get(addr, None)
    if sec is None:
        print(f"Message from {addr}: "+str(msg)+" (unverified, no key)")
    else:
        print(f"Message from {addr}: "+str(msg)+(" (verified)" if lib.hmac_verify(sec, msg, sign) else " (unverified)"))
