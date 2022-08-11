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
import logging

logging.basicConfig(stream=sys.stdout, format="[%(asctime)s][%(levelname)s] - %(message)s", level=logging.INFO)

# getting configuration from files
CONFIG: dict = json.load(open(sys.argv[1], "r"))
logging.info(f"Loaded configuration from \"{sys.argv[1]}\"")

IEK: bytes = lib.load_IEK_from_file(CONFIG["iek_path"])
logging.info("Loaded IEK from "+CONFIG["iek_path"])

BOUND_IP: str = CONFIG["bound_ip"]
BOUND_PORT: int = CONFIG["bound_port"]
logging.info(f"Binding to IP addr {BOUND_IP}:{str(BOUND_PORT)} for keys")

MULTICAST_IP: str = CONFIG["multicast_ip"]
MULTICAST_PORT: int = CONFIG["multicast_port"]
logging.info(f"Listening for secure messages on IP addr {MULTICAST_IP}:{str(MULTICAST_PORT)}")

SELF_EXT_IP: str = CONFIG["self_ext_ip"]
logging.info(f"Own IP address should be {SELF_EXT_IP}")

CA_IP: str = CONFIG["ca_ip"]
CA_PORT: int = CONFIG["ca_port"]
logging.info(f"CA will be contacted at {CA_IP}:{str(CA_PORT)}")

GATEWAY = CONFIG["mode"]=="gateway"
logging.info("Gateway mode engaged" if GATEWAY else "Gateway mode disengaged")

if GATEWAY:
    LEGACY_IP = CONFIG["legacy_output_mcast_ip"]
    LEGACY_PORT = CONFIG["legacy_output_mcast_port"]
    logging.info(f"Gateway traffic will be relayed to multicast {LEGACY_IP}:{str(LEGACY_PORT)}")

    RELAY_OK = CONFIG["actions"]["sign_ok"]=="relay"
    logging.info("Rule (sign_ok -> "+ ("relay)" if RELAY_OK else "drop)"))
    RELAY_NO = CONFIG["actions"]["sign_no"]=="relay"
    logging.info("Rule (sign_no -> "+ ("relay)" if RELAY_NO else "drop)"))
    RELAY_NO_SEC = CONFIG["actions"]["no_sec"]=="relay"
    logging.info("Rule (no HMAC key -> "+ ("relay)" if RELAY_NO_SEC else "drop)"))
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
                    logging.error(f"Sensor at {address} tried to update its PubKey but an error occured")
                else:
                    SENSOR_KEYS[address] = lib.signing.VerifyKey(decr_key)
                    logging.info(f"Sensor at {address} updated its PubKey successfully")
                    ciph_data = lib.fernet_iek_cipher(IEK, PUBLICKEY._key)
                    if ciph_data is None:
                        logging.error(f"Error while ciphering own PubKey for sending to {address}. Sending empty response.")
                        client.send(bytes(0))
                    else:
                        logging.info(f"Sending own ciphered PubKey to {address}")
                        client.send(ciph_data)
            elif data[0] == 115:#b's':
                signed_key = lib.eddsa_decr(PRIVATEKEY, data[1:])
                if signed_key is None:
                    logging.error(f"Sensor at {address} tried to update its HMAC key but decrypting message failed")
                else:
                    hmac_key = signed_key[:-64]
                    signature = signed_key[-64:]
                    if lib.eddsa_verify(SENSOR_KEYS[address], signature, hmac_key):
                        SENSOR_SECRETS[address] = hmac_key
                        logging.info(f"Sensor at {address} updated its HMAC key successfully")
                    else:
                        logging.error(f"Sensor at {address} tried to update its HMAC key but verifying the signature failed")
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

sockmtgate = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
sockmtgate.settimeout(0.5)

while True:
    data, (addr, _) = sockmt.recvfrom(1024)
    msg = data[:-20]
    sign = data[-20:]
    if SELF_EXT_IP == addr:
        sec = SENSOR_SECRETS.get("127.0.0.1", None)
    else:
        sec = SENSOR_SECRETS.get(addr, None)
    if sec is None:
        if GATEWAY:
            if RELAY_NO_SEC:
                sockmtgate.sendto(msg, (LEGACY_IP, LEGACY_PORT))
                logging.info(f"Relayed message from {addr} (rule: (no HMAC key -> relay)")
            else:
                logging.info(f"Dropped message from {addr} (rule: (no HMAC key -> drop)")
        else:
            print(f"Message from {addr}: "+str(msg)+" (unverified, no HMAC key)")
    else:
        verif = lib.hmac_verify(sec, msg, sign)
        if GATEWAY:
            if verif:
                if RELAY_OK:
                    sockmtgate.sendto(msg, (LEGACY_IP, LEGACY_PORT))
                    logging.info(f"Relayed message from {addr} (rule: (sign_ok -> relay)")
                else:
                    logging.info(f"Dropped message from {addr} (rule: (sign_ok -> drop)")
            else:
                if RELAY_NO:
                    sockmtgate.sendto(msg, (LEGACY_IP, LEGACY_PORT))
                    logging.info(f"Relayed message from {addr} (rule: (sign_no -> relay)")
                else:
                    logging.info(f"Dropped message from {addr} (rule: (sign_no -> drop)")
        else:
            print(f"Message from {addr}: "+str(msg)+(" (verified)" if verif else " (unverified)"))
