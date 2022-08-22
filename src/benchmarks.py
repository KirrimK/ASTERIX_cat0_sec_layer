"""
ASTERIX Cat0 Security Layer
Benchmarks

A test file for running benchmarks on the library's functions.
"""
import os, time
import matplotlib.pyplot as plt
import lib

def save_graphs(list_dt: list, label_: str, name_graph: str):
    plt.figure(figsize=(8, 5))
    plt.plot(list_dt, label=label_, linewidth=0.5)
    avg = sum(list_dt)/len(list_dt)
    plt.plot([avg for _ in list_dt], label="Average", linewidth=1)
    plt.legend()
    ax = plt.gca()
    ax.set_ylim([0, 2*avg])
    plt.savefig(name_graph)
    plt.clf()

def benchmark_hmac():
    print("Benchmarking HMAC...")
    key = lib.hmac_generate()
    times_sign = []
    times_verify = []
    for _ in range(0, 1000):
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
    save_graphs(times_sign, "Signing", "hmac_sign_benchmark.png")
    save_graphs(times_verify, "Verifying", "hmac_verify_benchmark.png")

def benchmark_fernet():
    print("Benchmarking Fernet...")
    lib.fernet_generate_iek("iekt")
    iek = lib.load_IEK_from_file("iekt")
    times_cipher = []
    times_decipher = []
    for _ in range(0, 1000):
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
    save_graphs(times_cipher, "Ciphering", "fernet_cipher_benchmark.png")
    save_graphs(times_decipher, "Deciphering", "fernet_decipher_benchmark.png")

def benchmark_eddsa_signatures():
    print("Benchmarking EdDSA Signatures...")
    signkey, verkey = lib.eddsa_generate()
    times_sign = []
    times_verify = []
    for _ in range(0, 1000):
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
    save_graphs(times_sign, "Signing", "eddsa_sign_benchmark.png")
    save_graphs(times_verify, "Verifying", "eddsa_verify_benchmark.png")

def benchmark_curve_encryption():
    print("Benchmarking Curve25519 Encryption...")
    signkey, verkey = lib.eddsa_generate()
    times_encrypt = []
    times_decrypt = []
    for _ in range(0, 1000):
        message = os.urandom(20+64) #replicate the secret that will be encrypted after being signed
        start = time.perf_counter()
        ciphertext = lib.curve_encr(verkey, message)
        end = time.perf_counter()
        _ = lib.curve_decr(signkey, ciphertext)
        end_decrypt = time.perf_counter()
        times_encrypt.append(end - start)
        times_decrypt.append(end_decrypt - end)
    print("Total time Encrypting: " + str(sum(times_encrypt)) + " seconds")
    print("Average time for Curve25519 encryption: " + str(sum(times_encrypt) / len(times_encrypt)) + " seconds")
    print("Max time for Curve25519 encryption: " + str(max(times_encrypt)) + " seconds")
    print("Min time for Curve25519 encryption: " + str(min(times_encrypt)) + " seconds")
    print("Total time Decrypting: " + str(sum(times_decrypt)) + " seconds")
    print("Average time for Curve25519 decryption: " + str(sum(times_decrypt) / len(times_decrypt)) + " seconds")
    print("Max time for Curve25519 decryption: " + str(max(times_decrypt)) + " seconds")
    print("Min time for Curve25519 decryption: " + str(min(times_decrypt)) + " seconds")
    save_graphs(times_encrypt, "Encryption", "curve_encrypt_benchmark.png")
    save_graphs(times_decrypt, "Decryption", "curve_decrypt_benchmark.png")

if __name__ == "__main__":
    benchmark_hmac()
    benchmark_fernet()
    benchmark_eddsa_signatures()
    benchmark_curve_encryption()
