import random
import time
import operator


# generates a list of n random messages of length m bytes
# in: message_quantity: number of messages to generate
# in: message_length_bytes: length of the messages to generate
# out: list of n random messages of length m bytes
def radar(message_quantity: int, message_length_bytes: int):
    res = []
    for _ in range(message_quantity):
        res.append(random.randbytes(message_length_bytes))
    return res

# tests the signature and verification times of a library
# in: pri_pub_keys_generator: function that generates a pair of private and public keys
# in: sign_function: function that signs a message with a private key (order: message, private_key)
# in: verify_function: function that verifies a signature (order: signature, message, public_key)
# in: message_quantity: number of messages to sign and verify
# in: message_length_bytes: length of the messages to sign and verify
# out: lists of times it took to sign a message and verify a signature
def test_sign_verify_times(pri_pub_keys_generator, sign_function, verify_function, message_quantity: int, message_length_bytes: int):
    private_key, public_key = pri_pub_keys_generator()
    list_message = radar(message_quantity, message_length_bytes)
    list_signed = []
    list_sign_times = []
    list_verify_times = []
    for m in list_message:
        local_sign_start = time.process_time()
        signed = sign_function(m, private_key)
        list_sign_times.append(time.process_time() - local_sign_start)
        list_signed.append(signed)
    for i, s in enumerate(list_signed):
        try:
            local_verify_start = time.process_time()
            verify_function(s, list_message[i], public_key)
            list_verify_times.append(time.process_time() - local_verify_start)
        except Exception as e:
            print(e)
            print('Wrong signature')
    return list_sign_times, list_verify_times

# displays statistics about the times of a library
# in: list_sign_times: list of times it took to sign a message
# in: list_verify_times: list of times it took to verify a signature
def test_statistics(test_name: str, list_sign_times: list, list_verify_times: list):
    print("--- Signing and verifying times for " + test_name + " ---")
    def average(lst):
        return sum(lst) / len(lst)
    global_sign_time = sum(list_sign_times) * 1000
    global_verify_time = sum(list_verify_times) * 1000
    avg_sign = (average(list_sign_times))*1000
    avg_verify = (average(list_verify_times))*1000
    max_sgn = max(list_sign_times)*1000
    max_ver = max(list_verify_times)*1000
    both_times = list(map(operator.add, list_sign_times, list_verify_times))
    avg_both = (average(both_times))*1000
    print('Total Signing time: {} ms'.format(global_sign_time))
    print('Total Verify time: {} ms'.format(global_verify_time))
    print('Total time: {} ms\n'.format((global_sign_time + global_verify_time)))
    print('Signing average time: {} ms'.format(avg_sign))
    print('Verify average time: {} ms'.format(avg_verify))
    print('Both average time: {} ms\n'.format(avg_both))
    print('Max signing time: {} ms'.format(max_sgn))
    print('Max verify time: {} ms'.format(max_ver))
    return global_sign_time, global_verify_time, avg_sign, avg_verify, avg_both, max_sgn, max_ver

def graph_results(list_sign_times: list, list_verify_times: list):
    import matplotlib.pyplot as plt
    plt.plot(list_sign_times, label='Signing')
    plt.plot(list_verify_times, label='Verification')
    plt.legend()
    plt.show()
