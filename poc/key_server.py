import lib
import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 42070

CLIENT_PORT = 42069

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

key_dict = {}

while True:
    data, (addr, port) = sock.recvfrom(1024)
    print(len(data))
    if len(data) == 32+20+1: #radar add key
        hash_ = data[32:32+20]
        
        new_key = lib.VerifyKey(data[:32])
        is_ok = data[20+32]
        comp_hash = lib.key_hash1(new_key)
        
        if comp_hash != hash_:
            print("key integrity problem")
        else:
            if is_ok == 1:
                key_dict[hash_] = new_key
                print("radar key added")
            else:
                key_dict.pop(hash_)
                print("radar key removed")
    elif len(data) == 20: #client asking hash of key
        hash_ = data[:20]
        print(hash_)
        key_opt = key_dict.get(hash_, None)
        if key_opt is None:
            payload = b'\x00'+hash_+bytes(32)
            sock.send(payload, (addr, 42070))
        else:
            payload = b'\x01'+hash_+key_opt
            sock.send(payload, (addr, 42070))
    else:
        print("rubbish message: "+str(data))
