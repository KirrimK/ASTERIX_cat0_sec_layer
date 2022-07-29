"""
ASTERIX Cat0 Security Layer
Receiver Gateway

The Receiver Gateway processes all inbound ASTERIX traffic to verify if the messages have been signed by
a legitimate sensor.
It receives a CA public key from the CA used to validate Sensor public keys,
and receives Sensor public keys used to verify the authenticity of secrets sent regularly by Sensors.
Those secrets are then used to verify the authenticity of each ASTERIX message sent by a sensor.
"""

import lib
