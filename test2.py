from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError
import generic_test

def keypair_generator():
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    return private_key, public_key

def sign_message(message, pkey):
    return pkey.sign(message).signature

def verify_message(signature, message, pkey):
    pkey.verify(message, signature)

if __name__ == '__main__':
    print("Signing and verifying times for nacl")
    sign_times, verify_times = generic_test.test_sign_verify_times(keypair_generator,
                                        sign_message,
                                        verify_message,
                                        10000,
                                        48)
    generic_test.display_results(sign_times, verify_times)
