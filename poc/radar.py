import lib
import socket

IP_RADAR="192.168.1.248"
RADAR_PORT= 42071



sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

sock.bind((IP_RADAR, RADAR_PORT))

print("Enter IP of key server (127.0.0.1):")
IP_SER = input()
SER_IP = "127.0.0.1" if IP_SER == "" else str(IP_SER)
print("Enter port of key server (42070):")
PORT_SER = input()
SER_PORT = 42070 if PORT_SER == "" else int(PORT_SER)
pri, pub = lib.keypair_generator()

hash_pub = lib.key_hash1(pub)

payload = pub._key+hash_pub+b'\x01'
print(len(payload))

sock.sendto(payload, (SER_IP, SER_PORT))
print("Sent key to key server")

print(f"Enter IP of client ({IP_RADAR}):")
IP_CLI = input()
CLI_IP = IP_RADAR if IP_CLI == "" else str(IP_CLI)
print("Enter port of client (42069):")
PORT = input()
CLI_PORT = 42069 if PORT == "" else int(PORT)


done = False
try:
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
except Exception as e:
    print("Error: "+str(e))
finally:
    print("Quitting radar, sending key deactivation message to server")
    payload = pub._key+hash_pub+b'\x00'
    sock.sendto(payload, (SER_IP, SER_PORT))
    print("sent, quitting")
