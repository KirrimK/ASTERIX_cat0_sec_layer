# Test for trying to reduce the signature size

import hashlib 
import random
from ecpy.curves     import Curve
from ecpy.keys       import ECPrivateKey
from ecpy.eddsa      import EDDSA

import time


h_functions = [hashlib.sha256, hashlib.sha1, hashlib.sha224, hashlib.md5, hashlib.sha384]
results=[]

if __name__ == "__main__":
   
    #Création du message à signer
    msg=random.randbytes(48)   
    #Algorithme cryptographique
    for h_function in h_functions :
        algo = EDDSA(h_function)
        edward_curve_1 = Curve.get_curve("Ed25519")
        #Création de la clé privée
        number = random.getrandbits(32)
        pv_key = ECPrivateKey(number,edward_curve_1)
        #Création de la clé publique
        pu_key = EDDSA.get_public_key(pv_key,hasher=h_function)
        

        #Signature du message
        a=algo.sign(msg,pv_key)
        results.append(len(a))
        print("signature : {} and length : {}".format(a,len(a)))
    
    print (results)