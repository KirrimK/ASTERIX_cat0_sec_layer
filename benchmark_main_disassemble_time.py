import main
import random
import time

def graph_results(list_times: list, list_hash_times: list):
    import matplotlib.pyplot as plt
    plt.plot(list_times, label='With raw_key')
    plt.plot(list_hash_times, label='With hash')
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
    print("Average time (ms): " + str(sum(list_times)/len(list_times)*1000))
    print("Max time (ms): " + str(max(list_times)*1000))
    print("Min time (ms): " + str(min(list_times)*1000))
    print("Number of messages that failed: " + str(counter_no_ok))
    print("Benchmark disassembly time with hash")
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
    print("Average time (ms): " + str(sum(list_times_hash)/len(list_times_hash)*1000))
    print("Max time (ms): " + str(max(list_times_hash)*1000))
    print("Min time (ms): " + str(min(list_times_hash)*1000))
    print("Number of messages that failed: " + str(counter_no_ok_hash))

    graph_results(list_times, list_times_hash)
