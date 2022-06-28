#Tester le temps pour les différents hashs
import hashlib 
import random
from ecpy.curves     import Curve
from ecpy.keys       import ECPrivateKey
from ecpy.eddsa      import EDDSA

import time

#To visualize the result 
import matplotlib.pyplot as plt

NB=1000
h_functions = [hashlib.sha256, hashlib.sha1, hashlib.sha224, hashlib.md5, hashlib.sha384]
results=[]
values=[]
names = ["sha256", "sha1", "sha224", "md5","sha384"]

if __name__ == "__main__":
   
     
    
    edward_curve_1 = Curve.get_curve("Ed25519")
    for h_function in h_functions :
        #Algorithme cryptographique
        algo = EDDSA(h_function)
        global_start = time.time()

        #Création de la clé privée
        number = random.getrandbits(32)
        pv_key = ECPrivateKey(number,edward_curve_1)
        #Création de la clé publique
        pu_key = EDDSA.get_public_key(pv_key,hasher=h_function)
        
        #Création de 1000 messages à signer
        for i in range(NB):
            msg=random.randbytes(48) 
            
            
            

            #Signature du message
            a=algo.sign(msg,pv_key)
        
            #Vérification de la signature
            algo.verify(msg,a,pu_key)
        values.append(time.time()-global_start)

    print(results)
    plt.bar(names,values)
    plt.show()