from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import generic_test

def keypair_generator():
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    return private_key, public_key

def sign_message(message: bytes, pkey: SigningKey):
    return pkey.sign(message).signature

def verify_message(signature: bytes, message: bytes, pkey: VerifyKey):
    pkey.verify(message, signature)

if __name__ == '__main__':
    sign_times, verify_times = generic_test.test_sign_verify_times(keypair_generator,
                                        sign_message,
                                        verify_message,
                                        10000,
                                        48)
    generic_test.test_statistics("nacl", sign_times, verify_times)
    generic_test.graph_results(sign_times, verify_times)
