"""
ASTERIX Cat0 Security Layer
Receiver Gateway

The Receiver Gateway processes all inbound ASTERIX traffic to verify if the messages have been signed by
a legitimate sensor.
It receives Sensor public keys used to verify the authenticity of secrets sent regularly by Sensors.
Those secrets are then used to verify the authenticity of each ASTERIX message sent by a sensor.
"""

import lib, json
import sys
import socket, struct
import threading

# getting configuration from files
CONFIG: dict = json.load(open(sys.argv[1], "r"))
IEK: bytes = lib.load_IEK_from_file(CONFIG["iek_path"])
BOUND_IP: str = CONFIG["bound_ip"]
BOUND_PORT: int = CONFIG["bound_port"]
MULTICAST_IP: str = CONFIG["multicast_ip"]
MULTICAST_PORT: int = CONFIG["multicast_port"]
SELF_EXT_IP: str = CONFIG["self_ext_ip"]
CA_IP: str = CONFIG["ca_ip"]
CA_PORT: int = CONFIG["ca_port"]
# -----

PRIVATEKEY, PUBLICKEY = lib.eddsa_generate()
SENSOR_KEYS: dict[str, bytes] = {}
SENSOR_SECRETS: dict[str, bytes] = {}

def listen_sensor_keys_secrets():
    global IEK, PRIVATEKEY, PUBLICKEY, SENSOR_KEYS, SENSOR_SECRETS
    sock = socket.socket()
    try:
        sock.bind((BOUND_IP, BOUND_PORT))
        sock.listen()
        while True:
            client, (address, port) = sock.accept()
            data = client.recv(2048)
            if data[0] == 107:#b'k':
                decr_key = lib.fernet_iek_decipher(IEK, data[1:])
                if decr_key is None:
                    print(f"[Receiver] {address} tried to update its PubKey but an error occured")
                else:
                    SENSOR_KEYS[address] = lib.signing.VerifyKey(decr_key)
                    print(f"[Receiver] {address} updated its PubKey")
                    ciph_data = lib.fernet_iek_cipher(IEK, PUBLICKEY._key)
                    if ciph_data is None:
                        print("[Receiver] Error while ciphering public key to send")
                    else:
                        client.send(ciph_data)
            elif data[0] == 115:#b's':
                signed_key = lib.eddsa_decr(PRIVATEKEY, data[1:])
                if signed_key is None:
                    print(f"[Receiver] {address} tried to update its HMAC key but decrypting with own private key failed")
                else:
                    hmac_key = signed_key[:-64]
                    signature = signed_key[-64:]
                    if lib.eddsa_verify(SENSOR_KEYS[address], signature, hmac_key):
                        SENSOR_SECRETS[address] = hmac_key
                        print(f"[Receiver] {address} updated its HMAC key")
                    else:
                        print(f"[Receiver] {address} tried to update its HMAC key but verifying the signature failed")
            client.close()
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
    if SELF_EXT_IP == addr:
        sec = SENSOR_SECRETS.get("127.0.0.1", None)
    else:
        sec = SENSOR_SECRETS.get(addr, None)
    if sec is None:
        print(f"Message from {addr}: "+str(msg)+" (unverified, no key)")
    else:
        print(f"Message from {addr}: "+str(msg)+(" (verified)" if lib.hmac_verify(sec, msg, sign) else " (unverified)"))
