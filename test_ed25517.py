import ed25519
import generic_test

def keypair_generator():
    return ed25519.create_keypair()

def sign_message(message: bytes, pkey: ed25519.SigningKey):
    return pkey.sign(message)

def verify_message(signature, message: bytes, pkey: ed25519.VerifyingKey):
    return pkey.verify(signature, message)

if __name__ == '__main__':
    sign_times, verify_times = generic_test.test_sign_verify_times(keypair_generator,
                                        sign_message,
                                        verify_message,
                                        10000,
                                        48)
    generic_test.test_statistics("ed25519", sign_times, verify_times)
    generic_test.graph_results(sign_times, verify_times)
