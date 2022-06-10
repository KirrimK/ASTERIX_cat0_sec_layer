import test_nacl
import random

if __name__ == '__main__':
    pri, pub = test_nacl.keypair_generator()
    msg = random.randbytes(48) #standard asterix message length
    print("Message (unmodified): "+str(msg))
    sgn = test_nacl.sign_message(msg, pri)
    print("Signature (unmodified): "+str(sgn))
    try:
        test_nacl.verify_message(sgn, msg, pub)
    except Exception as e:
        print(e)
    msg_mod = bytearray(msg)
    msg_mod[0] = 0x00
    msg_mod_bytes = bytes(msg_mod)
    print("\nMessage (modified): "+str(msg_mod_bytes))
    try:
        test_nacl.verify_message(sgn, msg_mod_bytes, pub)
    except Exception as e:
        print(e)
    sgn_mod = bytearray(sgn)
    sgn_mod[0] = 0x00
    sgn_mod_bytes = bytes(sgn_mod)
    print("\nSignature (modified): "+str(sgn_mod_bytes))
    try:
        test_nacl.verify_message(sgn_mod_bytes, msg, pub)
    except Exception as e:
        print(e)
