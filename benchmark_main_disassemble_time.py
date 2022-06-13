import main
import random
import time

def graph_results(list_times: list, list_hash_times: list, list_hmac: list, list_hash_hmac: list):
    import matplotlib.pyplot as plt
    plt.plot(list_times, label='With raw_key')
    plt.plot(list_hash_times, label='With hash')
    plt.plot(list_hmac, label='With hmac')
    plt.plot(list_hash_hmac, label='With hash and hmac')
    plt.legend()
    plt.show()

if __name__ == '__main__':
    number = 10000
    print("Benchmark disassembly time")
    pri, pub = main.keypair_generator()
    key_dict = {main.key_hash3_224(pub): pub._key}
    list_times = []
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_key(msg, pri, pub)
        start = time.process_time()
        _, ok = main.disassemble_and_verify_msg_raw_key(big_msg)
        list_times.append(time.process_time() - start)
        if not ok:
            counter_no_ok += 1
    print("ED25519 Raw Key:")
    print("Average time (ms): " + str(sum(list_times)/len(list_times)*1000))
    print("Max time (ms): " + str(max(list_times)*1000))
    print("Min time (ms): " + str(min(list_times)*1000))
    print("Number of messages that failed: " + str(counter_no_ok))
    list_times_hash = []
    counter_no_ok_hash = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_hash3_224_key(msg, pri, pub)
        start = time.process_time()
        _, ok = main.dissassemble_and_verify_msg_hash3_224_key(key_dict, big_msg)
        list_times_hash.append(time.process_time() - start)
        if not ok:
            counter_no_ok_hash += 1
    print("ED25519 Hash:")
    print("Average time (ms): " + str(sum(list_times_hash)/len(list_times_hash)*1000))
    print("Max time (ms): " + str(max(list_times_hash)*1000))
    print("Min time (ms): " + str(min(list_times_hash)*1000))
    print("Number of messages that failed: " + str(counter_no_ok_hash))
    list_times_hmac = []
    counter_no_ok_hmac = 0
    key = main.gen_secret()
    hmac_dict = {main.hash_sha1(key): key}
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_sha1_raw(msg, key)
        start = time.process_time()
        _, ok = main.disassemble_and_verify_msg_sha1_raw(big_msg)
        list_times_hmac.append(time.process_time() - start)
        if not ok:
            counter_no_ok_hmac += 1
    print("HMAC Raw Key:")
    print("Average time (ms): " + str(sum(list_times_hmac)/len(list_times_hmac)*1000))
    print("Max time (ms): " + str(max(list_times_hmac)*1000))
    print("Min time (ms): " + str(min(list_times_hmac)*1000))
    print("Number of messages that failed: " + str(counter_no_ok_hmac))

    print("HMAC Hash:")
    list_times_hmac_hash = []
    counter_no_ok_hmac_hash = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_sha1_hash(msg, key)
        start = time.process_time()
        _, ok = main.disassemble_and_verify_msg_sha1_hash(big_msg, hmac_dict)
        list_times_hmac_hash.append(time.process_time() - start)
        if not ok:
            counter_no_ok_hmac_hash += 1
    print("Average time (ms): " + str(sum(list_times_hmac_hash)/len(list_times_hmac_hash)*1000))
    print("Max time (ms): " + str(max(list_times_hmac_hash)*1000))
    print("Min time (ms): " + str(min(list_times_hmac_hash)*1000))
    print("Number of messages that failed: " + str(counter_no_ok_hmac_hash))

    graph_results(list_times, list_times_hash, list_times_hmac, list_times_hmac_hash)
