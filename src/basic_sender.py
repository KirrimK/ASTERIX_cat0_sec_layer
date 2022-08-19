"""
ASTERIX Cat0 Security Layer
Basic Sender

The basic sender plays the role of a legacy system that is not compatible with the security layer without a gateway.
Its only role is to send messages over UDP multicast, as a basic ASTERIX radar should.
"""

import socket
MULTICAST_IP = input("multicast ip?")
MULTICAST_PORT = int(input("multicast port?"))

sockmt = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
sockmt.settimeout(0.5)
DONE = False
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
    sockmt.sendto(bytes(message, "utf-8"), (MULTICAST_IP, MULTICAST_PORT))
