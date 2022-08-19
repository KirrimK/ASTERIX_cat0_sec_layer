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
        start = time.perf_counter()
        sign = lib.hmac_sign(key, message)
        _ = message + sign
        end = time.perf_counter()
        _ = lib.hmac_verify(key, message, sign)
        end_verify = time.perf_counter()
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
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.plot(times_sign, label="Signing")
    plt.plot([sum(times_sign)/len(times_sign) for _ in range(len(times_sign))], label="Average")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(times_verify, label="Verifying")
    plt.plot([sum(times_verify)/len(times_verify) for _ in range(len(times_verify))], label="Average")
    plt.legend()
    plt.savefig("hmac.png")
    plt.clf()

def benchmark_fernet():
    print("Benchmarking Fernet...")
    lib.fernet_generate_iek("iekt")
    iek = lib.load_IEK_from_file("iekt")
    times_cipher = []
    times_decipher = []
    for _ in range(0, 10000):
        _, payload = lib.eddsa_generate()
        start = time.perf_counter()
        ciphertext = lib.fernet_iek_cipher(iek, payload._key)
        end = time.perf_counter()
        _ = lib.fernet_iek_decipher(iek, ciphertext)
        end_decipher = time.perf_counter()
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
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.plot(times_cipher, label="Ciphering")
    plt.plot([sum(times_cipher)/len(times_cipher) for _ in range(len(times_cipher))], label="Average")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(times_decipher, label="Deciphering")
    plt.plot([sum(times_decipher)/len(times_decipher) for _ in range(len(times_decipher))], label="Average")
    plt.legend()
    plt.savefig("fernet.png")
    plt.clf()

def benchmark_eddsa_signatures():
    print("Benchmarking EdDSA Signatures...")
    signkey, verkey = lib.eddsa_generate()
    times_sign = []
    times_verify = []
    for _ in range(0, 10000):
        message = os.urandom(20) #replicate the secret that will be signed
        start = time.perf_counter()
        sign = lib.eddsa_sign(signkey, message)
        _ = message + sign
        end = time.perf_counter()
        _ = lib.eddsa_verify(verkey, sign, message)
        end_verify = time.perf_counter()
        times_sign.append(end - start)
        times_verify.append(end_verify - end)
    print("Total time Signing: " + str(sum(times_sign)) + " seconds")
    print("Average time for EdDSA signing: " + str(sum(times_sign) / len(times_sign)) + " seconds")
    print("Max time for EdDSA signing: " + str(max(times_sign)) + " seconds")
    print("Min time for EdDSA signing: " + str(min(times_sign)) + " seconds")
    print("Total time Verifying: " + str(sum(times_verify)) + " seconds")
    print("Average time for EdDSA verifying: " + str(sum(times_verify) / len(times_verify)) + " seconds")
    print("Max time for EdDSA verifying: " + str(max(times_verify)) + " seconds")
    print("Min time for EdDSA verifying: " + str(min(times_verify)) + " seconds")
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.plot(times_sign, label="Signing")
    plt.plot([sum(times_sign)/len(times_sign) for _ in range(len(times_sign))], label="Average")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(times_verify, label="Verifying")
    plt.plot([sum(times_verify)/len(times_verify) for _ in range(len(times_verify))], label="Average")
    plt.legend()
    plt.savefig("eddsa_sign.png")
    plt.clf()

def benchmark_eddsa_encryption():
    print("Benchmarking EdDSA Encryption...")
    signkey, verkey = lib.eddsa_generate()
    times_encrypt = []
    times_decrypt = []
    for _ in range(0, 10000):
        message = os.urandom(20+64) #replicate the secret that will be encrypted after being signed
        start = time.perf_counter()
        ciphertext = lib.eddsa_encr(verkey, message)
        end = time.perf_counter()
        _ = lib.eddsa_decr(signkey, ciphertext)
        end_decrypt = time.perf_counter()
        times_encrypt.append(end - start)
        times_decrypt.append(end_decrypt - end)
    print("Total time Encrypting: " + str(sum(times_encrypt)) + " seconds")
    print("Average time for EdDSA encryption: " + str(sum(times_encrypt) / len(times_encrypt)) + " seconds")
    print("Max time for EdDSA encryption: " + str(max(times_encrypt)) + " seconds")
    print("Min time for EdDSA encryption: " + str(min(times_encrypt)) + " seconds")
    print("Total time Decrypting: " + str(sum(times_decrypt)) + " seconds")
    print("Average time for EdDSA decryption: " + str(sum(times_decrypt) / len(times_decrypt)) + " seconds")
    print("Max time for EdDSA decryption: " + str(max(times_decrypt)) + " seconds")
    print("Min time for EdDSA decryption: " + str(min(times_decrypt)) + " seconds")
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.plot(times_encrypt, label="Encrypting")
    plt.plot([sum(times_encrypt)/len(times_encrypt) for _ in range(len(times_encrypt))], label="Average")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(times_decrypt, label="Decrypting")
    plt.plot([sum(times_decrypt)/len(times_decrypt) for _ in range(len(times_decrypt))], label="Average")
    plt.legend()
    plt.savefig("eddsa_encr.png")
    plt.clf()

if __name__ == "__main__":
    benchmark_hmac()
    benchmark_fernet()
    benchmark_eddsa_signatures()
    benchmark_eddsa_encryption()
