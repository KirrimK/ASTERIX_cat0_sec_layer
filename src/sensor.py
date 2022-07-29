"""
ASTERIX Cat0 Security Layer
Sensor Gateway

The Sensor Gateway is the component of the system that adds a layer of authentication to all ASTERIX
packets emitted by a sensor (such as a radar).
It communicates with the CA to validate its own key,
and with its clients to send signed messages and update the secret used for validation
"""

import lib
