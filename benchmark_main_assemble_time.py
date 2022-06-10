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
    print("Benchmark assembly time")
    pri, pub = main.keypair_generator()
    list_times = []
    for i in range(number):
        msg = random.randbytes(48)
        start = time.process_time()
        main.sign_and_assemble_message_key(msg, pri, pub)
        list_times.append(time.process_time() - start)
    print("Average time (ms): " + str(sum(list_times)/len(list_times)*1000))
    print("Max time (ms): " + str(max(list_times)*1000))
    print("Min time (ms): " + str(min(list_times)*1000))
    print("Benchmark assembly time with hash")
    list_times_hash = []
    for i in range(number):
        msg = random.randbytes(48)
        start = time.process_time()
        main.sign_and_assemble_message_hash3_224_key(msg, pri, pub)
        list_times_hash.append(time.process_time() - start)
    print("Average time (ms): " + str(sum(list_times_hash)/len(list_times_hash)*1000))
    print("Max time (ms): " + str(max(list_times_hash)*1000))
    print("Min time (ms): " + str(min(list_times_hash)*1000))

    graph_results(list_times, list_times_hash)
