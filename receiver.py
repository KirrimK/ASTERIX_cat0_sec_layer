import main
import socket

UDP_IP = "192.168.1.172"
UDP_PORT = 42069

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

key = bytes(20)
print("key: {}".format(key))
key_dict = {main.hash_sha1(key): key}

while True:
    data, addr = sock.recvfrom(1024)
    try:
        print("received message from {}: {}".format(addr, data))
        print("\\ of len: "+ str(len(data)))
        ok, decoded = main.disassemble_and_verify_msg_sha1_hash(data, key_dict)
        print("decoded message: {}".format(decoded))
        if ok:
            print("message verified")
        else:
            print("message not verified")
    except Exception as e:
        print(e)
