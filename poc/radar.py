import base64
import lib
import socket

print("Enter IP of client:")
CLI_IP = input()
print("Enter port of client:")
CLI_PORT = int(input())
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
pri, pub = lib.keypair_generator()
print("This radar's public key:"+str(base64.b64encode(pub._key)))

done = False
while not done:
    print("> ", end="")
    message = input()
    if message == "q":
        done = True
    else:
        message_ba = bytearray(48)
        message_ba[:min(len(message), 48)] = bytes(message, "ascii")[:min(len(message), 48)]
        message_bytes = bytes(message_ba)
        big_msg = lib.sign_and_assemble_message_hash1_key(message_bytes, pri, pub)
        print("Sending: "+str(big_msg)+"\n\\of len "+str(len(big_msg)))
        sock.sendto(big_msg, (CLI_IP, CLI_PORT))
        print("Sent")
