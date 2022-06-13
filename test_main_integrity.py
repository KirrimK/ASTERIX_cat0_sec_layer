import main
import random

def test_sign_verify_all_ok():
    number = 10000
    print("-- Test sign and verify all ok")
    pri, pub = main.keypair_generator()
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_key(msg, pri, pub)
        _, ok = main.disassemble_and_verify_msg_raw_key(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that failed: " + str(counter_no_ok))
    assert 0 == counter_no_ok

def test_hmac_sign_verify_all_ok():
    number = 10000
    print("-- Test hmac sign and verify all ok")
    secret = main.gen_secret()
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_sha1_raw(msg, secret)
        _, ok = main.disassemble_and_verify_msg_sha1_raw(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that failed: " + str(counter_no_ok))

def test_sign_verify_2modifs_random_message_zone():
    number = 10000
    print("-- Test sign and verify 2 modifications random big message")
    pri, pub = main.keypair_generator()
    counter_should_be_no = 0
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_key(msg, pri, pub)
        if random.random() < 0.5:
            big_msg = bytearray(big_msg)
            big_msg[0] = 0x00
            big_msg[3] = 0xFF
            big_msg = bytes(big_msg)
            counter_should_be_no += 1
        _, ok = main.disassemble_and_verify_msg_raw_key(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that should have failed: " + str(counter_should_be_no))
    print("Number of messages that failed: " + str(counter_no_ok))
    assert counter_should_be_no == counter_no_ok

def test_hmac_sign_verify_2modifs_random_message_zone():
    number = 10000
    print("-- Test hmac sign and verify 2 modifications random big message")
    secret = main.gen_secret()
    counter_should_be_no = 0
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_sha1_raw(msg, secret)
        if random.random() < 0.5:
            big_msg = bytearray(big_msg)
            big_msg[0] = 0x00
            big_msg[3] = 0xFF
            big_msg = bytes(big_msg)
            counter_should_be_no += 1
        _, ok = main.disassemble_and_verify_msg_sha1_raw(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that should have failed: " + str(counter_should_be_no))
    print("Number of messages that failed: " + str(counter_no_ok))
    assert counter_should_be_no == counter_no_ok

def test_sign_verify_2modifs_sign_zone():
    number = 10000
    print("-- Test sign and verify 2 modifications random signature")
    pri, pub = main.keypair_generator()
    counter_should_be_no = 0
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_key(msg, pri, pub)
        if random.random() < 0.5:
            big_msg = bytearray(big_msg)
            big_msg[48+0] = 0x00
            big_msg[48+3] = 0xFF
            big_msg = bytes(big_msg)
            counter_should_be_no += 1
        _, ok = main.disassemble_and_verify_msg_raw_key(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that should have failed: " + str(counter_should_be_no))
    print("Number of messages that failed: " + str(counter_no_ok))
    assert counter_should_be_no == counter_no_ok

def test_hmac_sign_verify_2modifs_sign_zone():
    number = 10000
    print("-- Test hmac sign and verify 2 modifications random signature")
    secret = main.gen_secret()
    counter_should_be_no = 0
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_sha1_raw(msg, secret)
        if random.random() < 0.5:
            big_msg = bytearray(big_msg)
            big_msg[48+0] = 0x00
            big_msg[48+3] = 0xFF
            big_msg = bytes(big_msg)
            counter_should_be_no += 1
        _, ok = main.disassemble_and_verify_msg_sha1_raw(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that should have failed: " + str(counter_should_be_no))
    print("Number of messages that failed: " + str(counter_no_ok))
    assert counter_should_be_no == counter_no_ok

def test_sign_verify_2modifs_key_zone():
    number = 10000
    print("-- Test sign and verify 2 modifications random key")
    pri, pub = main.keypair_generator()
    counter_should_be_no = 0
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_key(msg, pri, pub)
        if random.random() < 0.5:
            big_msg = bytearray(big_msg)
            big_msg[48+64+0] = 0x00
            big_msg[48+64+3] = 0xFF
            big_msg = bytes(big_msg)
            counter_should_be_no += 1
        _, ok = main.disassemble_and_verify_msg_raw_key(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that should have failed: " + str(counter_should_be_no))
    print("Number of messages that failed: " + str(counter_no_ok))
    assert counter_should_be_no == counter_no_ok

def test_hmac_sign_verify_2modifs_key_zone():
    number = 10000
    print("-- Test hmac sign and verify 2 modifications random key")
    secret = main.gen_secret()
    counter_should_be_no = 0
    counter_no_ok = 0
    for i in range(number):
        msg = random.randbytes(48)
        big_msg = main.sign_and_assemble_message_sha1_raw(msg, secret)
        if random.random() < 0.5:
            big_msg = bytearray(big_msg)
            big_msg[48+20+0] = 0x00
            big_msg[48+20+3] = 0xFF
            big_msg = bytes(big_msg)
            counter_should_be_no += 1
        _, ok = main.disassemble_and_verify_msg_sha1_raw(big_msg)
        if not ok:
            counter_no_ok += 1
    print("Number of messages that should have failed: " + str(counter_should_be_no))
    print("Number of messages that failed: " + str(counter_no_ok))
    assert counter_should_be_no == counter_no_ok

if __name__ == '__main__':
    test_sign_verify_all_ok()
    test_hmac_sign_verify_all_ok()
    
    test_sign_verify_2modifs_random_message_zone()
    test_hmac_sign_verify_2modifs_random_message_zone()

    test_sign_verify_2modifs_sign_zone()
    test_hmac_sign_verify_2modifs_sign_zone()
    
    test_sign_verify_2modifs_key_zone()
    test_hmac_sign_verify_2modifs_key_zone()
