from flask import Flask, request
import sys

app = Flask(__name__)

import lib, json

KNOWN_KEYS = {}
WHITELIST = set()

@app.route("/public", methods=["GET"])
def serve_public_key():
    return PAYLOAD.hex()

@app.route("/sign", methods=["GET"])
def sign_key():
    encr_key_hex = request.args.get("key", None)
    encr_key = bytes.fromhex(encr_key_hex)
    decr_key = lib.aes_iek_decipher(IEK, encr_key)
    if decr_key is None:
        return "", 400
    KNOWN_KEYS[request.remote_addr] = decr_key
    print("[CA] Updated key of "+request.remote_addr+" to: "+encr_key_hex)
    signature = lib.eddsa_sign(SIGNINGKEY, decr_key)
    return (decr_key + signature).hex()

if __name__ == "__main__":
    CONFIG: dict = json.load(open(sys.argv[1], "r"))
    print("[CA] Config loaded from "+sys.argv[1])
    IEK: bytes = lib.load_IEK_from_file(CONFIG["iek_path"])
    print("[CA] IEK loaded")
    # WHITELIST = set() #implement whitelist if needed
    SIGNINGKEY, VERIFYKEY = lib.eddsa_generate()
    print("[CA] Keypair generated")
    PAYLOAD = lib.aes_iek_cipher(IEK, VERIFYKEY._key)
    app.run(host=CONFIG["bound_ip"], port=CONFIG["bound_port"], debug=False)
