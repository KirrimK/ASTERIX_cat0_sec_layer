import lib_hmac
import socket
import struct
import time
import nacl.public as public
import threading

IP_RADAR= "127.0.0.1"
PORT_RADAR = 42070

multicast_group = ("224.1.1.1",10000)


sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

sock.settimeout(0.2)
tt1 = struct.pack('b',1)
sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,tt1)


sock2 = socket.socket(socket.AF_INET, # Internet
                      socket.SOCK_DGRAM) # UDP
sock2.bind((IP_RADAR, PORT_RADAR))

SECRET = bytes(20)
END_THREAD = False

private_key = public.PrivateKey(bytes(32))
public_key = private_key.public_key

def update_key_thread():
    global SECRET
    global END_THREAD
    print("Starting update key thread")
    while not END_THREAD:
        data, addr = sock2.recvfrom(1024)
        # decipher message and extract symmetric key
        # secret = ...
        pub_key = data[-32:]
        enc_secret = data[:-32]
        decr_box = public.Box(private_key, public.PublicKey(pub_key))
        SECRET = decr_box.decrypt(enc_secret)
        print("[UPDATED KEY]")
    print("Ending update key thread")

thd = threading.Thread(target=update_key_thread)
thd.start()

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
            start = time.time()
            message_ba = bytearray(48)
            message_ba[:min(len(message), 48)] = bytes(message, "ascii")[:min(len(message), 48)]
            message_bytes = bytes(message_ba)
            big_msg = lib_hmac.sign_and_assemble_message_sha1(message_bytes, SECRET)
            sock.sendto(big_msg, multicast_group)
            print("-- sent"+" (temps : {})".format(time.time()-start))
        except KeyboardInterrupt:
            print("Interrupted, quitting")
            done = True
        except Exception as e:
            print("Error: "+str(e))
END_THREAD = True
thd.join()
