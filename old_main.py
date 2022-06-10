
import base64
import ed25519



private_key, public_key = ed25519.create_keypair()
public_key_hex = public_key.to_ascii(encoding="hex")
# Serialize the verify key to send it to a third party
public_key_b64 = public_key.to_ascii(encoding="base64")

# print the ed25519 private and public keys
print("the private key seed is", base64.b64encode(private_key.to_seed()).decode('ASCII'))
print("the private key byte is", base64.b64encode(private_key.to_bytes()).decode('ASCII'))
print("the public key byte is", base64.b64encode(public_key.to_bytes()).decode('ASCII'))

# print("the public key hex is", public_key_hex)
print("the public key hex is", public_key_hex)
print("the public key b64 is", public_key_b64)

if __name__ == '__main__':
    # read the file to sign
    ORIG_FILE_LCT = 'test/digital.txt'
    with open(ORIG_FILE_LCT, 'rb') as file2:
        original: bytes = file2.read()

    # write the private key in pem format
    PRIV_KEY_DST = 'test/private_key.pem'
    with open(PRIV_KEY_DST, 'w') as f:
        prvk = base64.b64encode(private_key.to_seed()).decode('ASCII')
        f.write(prvk)

    # write the public  key in pem format
    PUB_KEY_DST = 'test/public_key.pem'
    with open(PUB_KEY_DST, 'w+') as file1:
        pubk = base64.b64encode(public_key.to_bytes()).decode('ASCII')
        file1.write(pubk)

    # exporting the signature file
    SGN_FILE_DST = 'test/signature.sig'
    with open('SGN_FILE_DST', 'wb') as file4:
        signature = private_key.sign(original, encoding="base64")
        file4.write(signature)

    open("test/my-secret-key-byte", "wb").write(private_key.to_bytes())
    open("test/my-secret-key-seed", "wb").write(private_key.to_seed())
    open("test/my-public-key-byte", "wb").write(public_key.to_bytes())

    vkey_hex = public_key.to_ascii(encoding="hex")
    print("the public key is", vkey_hex)

    # Read secret key from file
    seed = open("test/my-secret-key-seed", "rb").read()
    # Rebuild secret key
    signing_key_s = ed25519.SigningKey(seed)

    keydata = open("test/my-secret-key-byte", "rb").read()
    signing_key_b = ed25519.SigningKey(keydata)

    open("test/my-signature-seed", "wb").write(signing_key_s.sign(original, encoding="base64"))
    open("test/my-signature-bytes", "wb").write(signing_key_b.sign(original, encoding="base64"))

    # Read public key from a file
    pub_key_byte = open("test/my-public-key-byte", "rb").read()

    # rebuild the public key
    public_key_rebuild = ed25519.VerifyingKey(pub_key_byte)

    #digest1 = SHA256.new()
    #digest2 = SHA256.new()

    # Validate digital signature
    #print("Verified:", public_key_rebuild.verify(signature, original))