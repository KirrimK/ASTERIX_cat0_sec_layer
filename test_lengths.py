import test_nacl
import hashlib
import random

if __name__ == '__main__':
    pri, pub = test_nacl.keypair_generator()
    print("Private key: "+str(pri))
    print("Private key length:"+ str(len(bytes(pri)))+"\n")
    print("Public key: "+str(pub))
    print("Public key length:"+ str(len(pub._key))+"\n")
    msg: bytes = random.randbytes(48) #standard asterix message length
    msg2: bytes = random.randbytes(30) #smaller message length
    print("Message: "+str(msg))
    print("Message length:"+ str(len(msg))+"\n")
    print("Message2: "+str(msg2))
    print("Message2 length:"+ str(len(msg2))+"\n")
    sig = test_nacl.sign_message(msg, pri)
    sig2 = test_nacl.sign_message(msg2, pri)
    print("Signature: "+str(sig))
    print("Signature length:"+ str(len(sig))+"\n")
    print("Signature2: "+str(sig2))
    print("Signature2 length:"+ str(len(sig2))+"\n")
    hash_pub_sha3_224 = hashlib.sha3_224(pub._key).digest()
    hash_pub_sha_256 = hashlib.sha256(pub._key).digest()
    hash_pub_sha_384 = hashlib.sha384(pub._key).digest()
    hash_pub_sha_512 = hashlib.sha512(pub._key).digest()
    print("Public key hash (sha3_224): "+str(hash_pub_sha3_224))
    print("Public key hash length:"+ str(len(hash_pub_sha3_224))+"\n")
    print("Public key hash (sha256): "+str(hash_pub_sha_256))
    print("Public key hash length:"+ str(len(hash_pub_sha_256))+"\n")
    print("Public key hash (sha384): "+str(hash_pub_sha_384))
    print("Public key hash length:"+ str(len(hash_pub_sha_384))+"\n")
    print("Public key hash (sha512): "+str(hash_pub_sha_512))
    print("Public key hash length:"+ str(len(hash_pub_sha_512))+"\n")
    