import lib_hmac
import socket
import struct

multicast_group = ("224.1.1.1",10000)


sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

sock.settimeout(0.2)
tt1 = struct.pack('b',1)
sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,tt1)

SECRET = bytes(20)

print("RADAR Simulator:")

print("Type messages to send to multicast group (q to quit):")
done = False
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
        try:
            message_ba = bytearray(48)
            message_ba[:min(len(message), 48)] = bytes(message, "ascii")[:min(len(message), 48)]
            message_bytes = bytes(message_ba)
            big_msg = lib_hmac.sign_and_assemble_message_sha1(message_bytes, SECRET)
            sock.sendto(big_msg, multicast_group)
            print("-- sent")
        except KeyboardInterrupt:
            print("Interrupted, quitting")
            done = True
        except Exception as e:
            print("Error: "+str(e))
