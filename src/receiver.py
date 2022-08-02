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
    sys.exit(1)
print("[Receiver] Got CA's PubKey: "+str(CA_VERIFYKEY))

SENSOR_KEYS: dict[str] = {}
