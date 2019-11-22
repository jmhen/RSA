from Crypto.PublicKey import RSA
from base64 import b64encode,b64decode
from Crypto.Hash import SHA256
import random

def square_multiply(a,x,n):
    res=1
    for i in bin(x)[2:]:# step bitwise through key
        res=res*res %n
        if (i=='1'):
            res=res*a % n
    return res

# function to convert long int to byte string
def pack_bigint(i):
    b=bytearray()
    while i:
        b.append(i&0xFF)
        i>>=8
    return b

# function to convert byte string to long int
def unpack_bigint(b):
    b=bytearray(b)
    return sum((1<<(bi*8))* bb for (bi,bb) in enumerate(b))

def encrypt_RSA(k,m):
    cipher = square_multiply(m,k.e,k.n)
    return cipher

def decrypt_RSA(k,c):
    message = square_multiply(c,k.d,k.n)
    return message

def sign_RSA(k,m):
    digest = SHA256.new(m).digest()
    sign = square_multiply(unpack_bigint(digest),k.d,k.n)
    return sign

def verify_sign(k,s,m):
    digest = SHA256.new(m).digest()
    x = square_multiply(s,k.e,k.n)
    xdigest = pack_bigint(x)
    if xdigest == digest:
        return True
    return False



def generate_int(n = 1024):
    return random.getrandbits(n)

if __name__=="__main__":
    private_key_file = 'mykey.pem.priv'
    public_key_file = 'mykey.pem.pub'

    key1 = open(private_key_file,'rb')
    privkey = RSA.importKey(key1.read())

    key2 = open(public_key_file,'rb')
    pubkey = RSA.importKey(key2.read())

    mf = open('message.txt','rb')
    message = mf.read()
    mf.close()


    print('Part I --------')
    # Demo encryption and decryption
    cipher = encrypt_RSA(pubkey, unpack_bigint(message))
    print('encrptyed = ',b64encode(pack_bigint(cipher)))
    decrypted_m = decrypt_RSA(privkey,cipher)
    print('decrypted = ',pack_bigint(decrypted_m).decode())

    # Demo signing and verification
    signature = sign_RSA(privkey,message)
    print('signature = ',b64encode(pack_bigint(signature)))
    verified = verify_sign(pubkey,signature,message)
    print('verified = ',verified)

    print('\n\n')

    print('Part II --------')
    # Demo encryption protocol attack
    mint = 100
    print('Encrypting: ', mint)
    y = encrypt_RSA(pubkey, mint)
    print('Result:')
    print(b64encode(pack_bigint(y)))
    ys = encrypt_RSA(pubkey,2)
    mresult = y*ys
    print('Modified Result: ')
    print(b64encode(pack_bigint(mresult)))
    decrypted = decrypt_RSA(privkey,mresult)
    print('Decrypted: ',decrypted)

    # Demo digital signature protoccol attack
    s = generate_int(1024)
