from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode,b64encode
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
import argparse
import sys

def generate_RSA(bits=1024):
    key = RSA.generate(bits)
    private_key,public_key = key, key.publickey()
    with open(private_key_file,'wb') as f1:
        f1.write(private_key.exportKey(format='PEM'))
        f1.close()
    with open(public_key_file,'wb') as f2:
        f2.write(public_key.exportKey(format='PEM'))
        f2.close()
    return private_key, public_key

def encrypt_RSA(public_key_file,message):
    pubkey = RSA.importKey(open(public_key_file,'rb').read())
    oaep =  PKCS1_OAEP.new(pubkey)
    cipher = oaep.encrypt(message)
    return b64encode(cipher) # return in base64

def decrypt_RSA(private_key_file,cipher):
    privkey = RSA.importKey(open(private_key_file,'rb').read())
    oaep =  PKCS1_OAEP.new(privkey)
    message = oaep.decrypt(b64decode(cipher))
    return message

def sign_RSA(private_key_loc,data):
    privkey = RSA.importKey(open(private_key_loc,'rb').read())
    mhash = SHA256.new(data)
    signer = PKCS1_PSS.new(privkey)
    signature = signer.sign(mhash)
    return b64encode(signature) #return in base64

def verify_sign(public_key_loc,signature,data):
    pubkey = RSA.importKey(open(public_key_file,'rb').read())
    mhash = SHA256.new(data)
    verifier = PKCS1_PSS.new(pubkey)
    if verifier.verify(mhash,b64decode(signature)): return True
    else:return False




if __name__=="__main__":
    private_key_file = 'newkey.pem.priv'
    public_key_file = 'newkey.pem.pub'
    message = ''

    with open('message.txt','rb') as mf:
        message = mf.read()
        mf.close()

    generate_RSA()
    cipher = encrypt_RSA(public_key_file,message)
    print('encrypted = ',cipher)
    message = decrypt_RSA(private_key_file,cipher)
    print('decrypted = ',message)

    signature = sign_RSA(private_key_file,message)
    print('signature = ',signature)
    print('verified = ',verify_sign(public_key_file,signature, message))
