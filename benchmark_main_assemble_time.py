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
    print("Benchmark assembly time")
    pri, pub = main.keypair_generator()
    list_times = []
    for i in range(number):
        msg = random.randbytes(48)
        start = time.process_time()
        main.sign_and_assemble_message_key(msg, pri, pub)
        list_times.append(time.process_time() - start)
    print("ED25519 Raw Key:")
    print("Average time (ms): " + str(sum(list_times)/len(list_times)*1000))
    print("Max time (ms): " + str(max(list_times)*1000))
    print("Min time (ms): " + str(min(list_times)*1000))
    list_times_hash = []
    for i in range(number):
        msg = random.randbytes(48)
        start = time.process_time()
        main.sign_and_assemble_message_hash3_224_key(msg, pri, pub)
        list_times_hash.append(time.process_time() - start)
    print("ED25519 Hash:")
    print("Average time (ms): " + str(sum(list_times_hash)/len(list_times_hash)*1000))
    print("Max time (ms): " + str(max(list_times_hash)*1000))
    print("Min time (ms): " + str(min(list_times_hash)*1000))

    list_times_hmac = []
    key = main.gen_secret()
    hmac_dict = {main.hash_sha1(key): key}
    for i in range(number):
        msg = random.randbytes(48)
        start = time.process_time()
        main.sign_and_assemble_message_sha1_raw(msg, key)
        list_times_hmac.append(time.process_time() - start)
    print("ED25519 HMAC:")
    print("Average time (ms): " + str(sum(list_times_hmac)/len(list_times_hmac)*1000))
    print("Max time (ms): " + str(max(list_times_hmac)*1000))
    print("Min time (ms): " + str(min(list_times_hmac)*1000))
    list_times_hash_hmac = []
    for i in range(number):
        msg = random.randbytes(48)
        start = time.process_time()
        main.sign_and_assemble_message_sha1_hash(msg, key)
        list_times_hash_hmac.append(time.process_time() - start)
    print("ED25519 Hash and HMAC:")
    print("Average time (ms): " + str(sum(list_times_hash_hmac)/len(list_times_hash_hmac)*1000))
    print("Max time (ms): " + str(max(list_times_hash_hmac)*1000))
    print("Min time (ms): " + str(min(list_times_hash_hmac)*1000))

    graph_results(list_times, list_times_hash, list_times_hmac, list_times_hash_hmac)
