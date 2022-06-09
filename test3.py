
import base64
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError
import random



private_key = SigningKey.generate()
public_key = private_key.verify_key


if __name__ == '__main__':
        asterix_msg_size = 48
        original = random.randbytes(asterix_msg_size)
        print(original)
        print(private_key)

        print(public_key)
        signed = private_key.sign(original).signature
        print(signed)
        decoded = public_key.verify(original, signed)
        print(decoded)



