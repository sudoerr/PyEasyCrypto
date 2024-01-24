 # PyEasyCrypto
 
#### A python library to easily and safely transfer information over unsafe channels and sign and verify data using ECDSA. Everything is working with safe-curve 25519 and AES.
**PyEasyCrypto** Provides simple wrappers around Python [cryptography](https://cryptography.io/en/latest/) module.

<br>

## First Install Required Libraries :
```shell
pip install cryptography
```
### Download PyEasyCrypto In Your Project Folder
```shell
git clone https://github.com/sudoerr/PyEasyCrypto.git
```

## Sign And Verify
ed25519 curve is used to sign and verify and everytime we save it in root directory given to root parameter which by default is ```./data/keys```.

 ```python
 from PyEasyCrypto import ECDSA

 # Sign And Verify
 e = ECDSA()
 e.generate_new_keypair(password=None)
 e.load_keys(password=None)

 message = b"A message to sign"
 signature = e.sign(message)
 # using public key to verify
 with open("./data/keys/public.pem", "rb") as f:
    e.verify(f.read(), signature, message)
 ```

### Load Keys From Anywhere
In case you don't want to change root path for ECDSA object.
```python
e.load_keys_from(
   private_key="path/to/private_key.pem",
   password:bytes=None
)
```
> Warning : Saving keys without password is not secure enough. Also remember to not hard-code password!

> NOTE : ```load_keys``` and ```load_keys_from``` will return a bool value. Please check before doing anything.

## Encrypt And Decrypt
x25519 curve is used to generate shared keys between 2 peers and then AES-256 mode CBC is used to encrypt data with shared key.
```python
import os
from PyEasyCrypto import ECDH, AES256CBC

# Generate Shared Key Between 2 Peers
p1 = ECDH()
p1.generate_keypair()
p2 = ECDH()
p2.generate_keypair()
p1.generate_shared_key_and_derive(p2.get_public_key_pem())
p2.generate_shared_key_and_derive(p1.get_public_key_pem())
# testing
print(p1.get_derived_key() == p2.get_derived_key())


# Encrypt And Decrypt Data Using Shared Key
data = b"Some Data"
iv = os.urandom(16)
aes = AES256CBC(p1.get_derived_key(), iv)
encrypted = aes.encrypt(data)
decrypted = aes.decrypt(encrypted)

# NOTE : You can use base64 built-in 
#        library to convert bytes to
#        base64 if you want.
```
### Save And Load x25519 Keys
```python
p1.save_keys(
   private_key="path/to/private.pem",
   public_key="path/to/public.pem",
   password=None
)

p1.load_keys(
   priavte_key="path/to/private.pem",
   public_key=None,
   password=None
)
# There will not be any problem 
# if you set public_key as None.
# Public key will be derived from
# private key.
```

## What's Happening Here?
The library is only a thin wrapper of python's own [cryptography](https://cryptography.io/en/latest/) module. It uses well known and battle tested encryption techniques. It provides a convenient wrapper around these functions, taking away the details of using encryption correctly. Feel free to explore the source!

