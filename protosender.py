import main
import socket

UDP_IP = "192.168.1.174"
UDP_PORT = 42069
message = bytearray(48)
message[:11] = b"Hello World"
message[45:] = b'fin'

print("message: %s" % message)

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

key = bytes(20)
print("key: {}".format(key))
big_msg = main.sign_and_assemble_message_sha1_hash(message, key)
print("big_msg: {}".format(big_msg))
print("len(big_msg): {}".format(len(big_msg)))
sock.sendto(big_msg, (UDP_IP, UDP_PORT))