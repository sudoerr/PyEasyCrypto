# 786
# code by Tony
"""
<< PyEasyCrypto >>

A python library to easily and safely transfer information over
unsafe channels and sign and verify data using ECDSA. Everything
is working with safe-curve 25519 and AES.

PyEasyCrypto Provides simple wrappers around Python cryptography module.

Created By Tony Kulaei - December 27, 2023
Github : https://github.com/sudoerr
Update : December 29, 2023
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding





class ECDSA:
    def __init__(self, root="./data/keys"):
        self.__root = root
        self.__private_key : Ed25519PrivateKey = None
        self.__public_key : Ed25519PublicKey = None
        self.__private_key_file = os.path.join(self.__root, "private.pem")
        self.__public_key_file = os.path.join(self.__root, "public.pem")

        os.makedirs(root, exist_ok=True)
    
    def load_keys(self, password:bytes=None):
        if os.path.isfile(self.__private_key_file):
            with open(self.__private_key_file, "rb") as f:
                self.__private_key = serialization.load_pem_private_key(f.read(), password)
                self.__public_key = self.__private_key.public_key()
            return True
        return False
    
    def load_keys_from(self, private_key:str="path/to/private_key.pem", password:bytes=None):
        if os.path.isfile(private_key):
            with open(private_key, "rb") as f:
                self.__private_key = serialization.load_pem_private_key(f.read(), password)
                self.__public_key = self.__private_key.public_key()
            return True
        return False

    def generate_new_keypair(self, password:bytes=None):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        # Checking password
        if password == None:
            encryption_algorithm = serialization.NoEncryption()
        else:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        # Writing private key to file
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        with open(self.__private_key_file, "wb") as f:
            f.write(private_bytes)
        # Writing public key to file
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.__public_key_file, "wb") as f:
            f.write(public_bytes)
        return True
    
    def sign(self, data:bytes):
        data = self.__private_key.sign(data)
        return data

    def verify(self, public_key_pem:bytes, signature:bytes, data:bytes):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            public_key.verify(signature, data)
            return True
        except:
            return False

    def get_public_key_pem(self):
        public_bytes = self.__public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes



class ECDH:
    def __init__(self):
        self.__private_key : X25519PrivateKey = None
        self.__public_key : X25519PublicKey = None
        self.__peer_public_key = None
        self.__shared_key = None
        self.__derived_key = None

    def generate_keypair(self):
        self.__private_key = X25519PrivateKey.generate()
        self.__public_key = self.__private_key.public_key()
        return True
    
    def generate_shared_key_and_derive(self, peer_public_key_pem:bytes):
        self.__peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        self.__shared_key = self.__private_key.exchange(self.__peer_public_key)
        self.__derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data"
        ).derive(self.__shared_key)
        return True
    
    def get_public_key_pem(self):
        pem = self.__public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def get_derived_key(self):
        return self.__derived_key
    



class AES256CBC:
    def __init__(self, key32:bytes, iv:int):
        self.__key32 = key32
        self.__iv = iv
        self.__cipher = Cipher(
            algorithm=algorithms.AES256(self.__key32),
            mode=modes.CBC(iv)
        )
    
    def encrypt(self, data:bytes):
        padder = padding.PKCS7(256).padder()
        data = padder.update(data) + padder.finalize()
        encryptor = self.__cipher.encryptor()
        enc = encryptor.update(data) + encryptor.finalize()
        return enc
    
    def decrpyt(self, data:bytes):
        unpadder = padding.PKCS7(256).unpadder()
        decryptor = self.__cipher.decryptor()
        dec = decryptor.update(data) + decryptor.finalize()
        dec = unpadder.update(dec) + unpadder.finalize()
        return dec


        


if __name__ == "__main__":
    # c = ECDSA()
    # # c.generate_new_keypair(b"mahdi")
    # c.load_keys(b"mahdi")
    # signature = c.sign(b"Hello World")
    # with open("./data/keys/public.pem", "rb") as f:
    #     p_key_pem = f.read()
    #     print(c.verify(p_key_pem, signature, b"Hello World"))

#   ========================================================

    e = ECDH()
    e.generate_keypair()
    e2 = ECDH()
    e2.generate_keypair()
    e.generate_shared_key_and_derive(e2.get_public_key_pem())
    e2.generate_shared_key_and_derive(e.get_public_key_pem())
    print(e.get_derived_key() == e2.get_derived_key())

#   ========================================================

    message = b"hello world hois"
    iv = os.urandom(16)
    a = AES256CBC(e.get_derived_key(), iv)
    enc = a.encrypt(message)
    print("Encrypted : ", enc)

    # iv = os.urandom(16)
    a2 = AES256CBC(e2.get_derived_key(), iv)
    dec = a2.decrpyt(enc)
    print("Decrypted : ", dec)
        




            