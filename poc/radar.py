import lib
import socket
import struct

IP_RADAR="192.168.1.193"
RADAR_PORT= 42071

multicast_group = ("224.1.1.1",10000)


sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

sock.settimeout(0.2)
tt1 = struct.pack('b',1)
sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,tt1)


print("RADAR Simulator:")
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

print("Type messages to send to client (q to quit):")
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
            big_msg = lib.sign_and_assemble_message_hash1_key(message_bytes, pri, pub)
            sock.sendto(big_msg, multicast_group)
            print("-- sent")
        except KeyboardInterrupt:
            print("Interrupted, quitting")
            done = True
        except Exception as e:
            print("Error: "+str(e))

payload = pub._key+hash_pub+b'\x00'
sock.sendto(payload, (SER_IP, SER_PORT))
print("Sent deactivation message to key server, quitting.")
