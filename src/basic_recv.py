"""
ASTERIX Cat0 Security Layer
Basic Receiver

The basic receiver plays the role of a legacy system that is not compatible with the security layer without a gateway.
Its only role is to receive messages over UDP multicast, as a basic ASTERIX endpoint should.
"""

import socket, struct

MULTICAST_IP = input("multicast ip?")
MULTICAST_PORT = int(input("multicast port?"))

sockmt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockmt.bind(('', MULTICAST_PORT))
groupmt = socket.inet_aton(MULTICAST_IP)
mreq=struct.pack('4sL',groupmt,socket.INADDR_ANY)
sockmt.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
while True:
    data, (addr, _) = sockmt.recvfrom(1024)
    try:
        dd = data.decode("utf-8")
        print(f"Received message from {addr}: {dd}")
    except:
        print(f"Message from {addr}: "+str(data))
