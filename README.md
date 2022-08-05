# ASTERIX_cat0_sec_layer

(cf https://github.com/fernet/spec/blob/master/Spec.md for Fernet cipher spec)

## TODO:

- NO CA (for now)
- Everyone has a assym priv-pub keypair (only one per agent)
- stronger IEKs
- how to share infos between user-groups? Put several IEKs on device? how? study practicality
- HMAC SECRET: sign w/own signingkey and send encrypted w/ recv's pubKey / one per sensor per UG
- IEK only for KeySharing
- (?Marketing: sell secure key exchange?)
