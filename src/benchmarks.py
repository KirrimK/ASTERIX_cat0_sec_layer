"""
ASTERIX Cat0 Security Layer
Benchmarks

A test file for running benchmarks on the library's functions.
"""
import os, time
import matplotlib.pyplot as plt
import lib

def benchmark_hmac():
    print("Benchmarking HMAC...")
    key = lib.hmac_generate()
    times_sign = []
    times_verify = []
    for _ in range(0, 10000):
        message = os.urandom(48)
        start = time.time()
        sign = lib.hmac_sign(key, message)
        _ = message + sign
        end = time.time()
        _ = lib.hmac_verify(key, message, sign)
        end_verify = time.time()
        times_sign.append(end - start)
        times_verify.append(end_verify - end)
    print("Total time Signing: " + str(sum(times_sign)) + " seconds")
    print("Average time for HMAC signing: " + str(sum(times_sign) / len(times_sign)) + " seconds")
    print("Max time for HMAC signing: " + str(max(times_sign)) + " seconds")
    print("Min time for HMAC signing: " + str(min(times_sign)) + " seconds")
    print("Total time Verifying: " + str(sum(times_verify)) + " seconds")
    print("Average time for HMAC verifying: " + str(sum(times_verify) / len(times_verify)) + " seconds")
    print("Max time for HMAC verifying: " + str(max(times_verify)) + " seconds")
    print("Min time for HMAC verifying: " + str(min(times_verify)) + " seconds")
    plt.subplot(1, 2, 1)
    plt.plot(times_sign, label="Signing")
    plt.subplot(1, 2, 2)
    plt.plot(times_verify, label="Verifying")
    plt.show()

def benchmark_fernet():
    print("Benchmarking Fernet...")
    lib.fernet_generate_iek("iekt")
    iek = lib.load_IEK_from_file("iekt")
    times_cipher = []
    times_decipher = []
    for _ in range(0, 10000):
        _, payload = lib.eddsa_generate()
        start = time.time()
        ciphertext = lib.fernet_iek_cipher(iek, payload._key)
        end = time.time()
        _ = lib.fernet_iek_decipher(iek, ciphertext)
        end_decipher = time.time()
        times_cipher.append(end - start)
        times_decipher.append(end_decipher - end)
    print("Total time Ciphering: " + str(sum(times_cipher)) + " seconds")
    print("Average time for Fernet ciphering: " + str(sum(times_cipher) / len(times_cipher)) + " seconds")
    print("Max time for Fernet ciphering: " + str(max(times_cipher)) + " seconds")
    print("Min time for Fernet ciphering: " + str(min(times_cipher)) + " seconds")
    print("Total time Deciphering: " + str(sum(times_decipher)) + " seconds")
    print("Average time for Fernet deciphering: " + str(sum(times_decipher) / len(times_decipher)) + " seconds")
    print("Max time for Fernet deciphering: " + str(max(times_decipher)) + " seconds")
    print("Min time for Fernet deciphering: " + str(min(times_decipher)) + " seconds")
    plt.subplot(1, 2, 1)
    plt.plot(times_cipher, label="Ciphering")
    plt.subplot(1, 2, 2)
    plt.plot(times_decipher, label="Deciphering")
    plt.show()

if __name__ == "__main__":
    benchmark_hmac()
    benchmark_fernet()
