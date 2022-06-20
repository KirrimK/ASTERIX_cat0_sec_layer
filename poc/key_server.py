import lib
import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 42070

CLIENT_PORT = 42070

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

key_dict: dict[bytes] = {}

dict_hash = lib.sha1_of_dict(key_dict)
while True:
    data, (addr, port) = sock.recvfrom(1024)
    print("Contacted by "+str(addr))
    if len(data) == 32+20+1: #radar add key
        hash_ = data[32:32+20]
        new_key = lib.VerifyKey(data[:32])
        is_ok = data[20+32]
        comp_hash = lib.key_hash1(new_key)
        if comp_hash != hash_:
            print("Key integrity problem")
        else:
            if is_ok == 1:
                key_dict[hash_] = new_key._key
                print("Radar key added")
            else:
                key_dict.pop(hash_)
                print("Radar key removed")
            dict_hash = lib.sha1_of_dict(key_dict)
    elif len(data) == 20: #client asking hash of key
        hash_ = data[:20]
        print("Received hash from client: {}".format(hash_))
        if dict_hash != hash_:
            print("List has changed since client last fetched, sending update")
            payload = len(key_dict.keys()).to_bytes(1, 'little')
            for key, value in key_dict.items():
                payload += key + value
            sock.sendto(payload, (addr, CLIENT_PORT))
        else:
            print("List is up to date")
            payload = b'\x00'+hash_
            sock.sendto(payload, (addr, CLIENT_PORT))
    else:
        print("rubbish message: "+str(data))
