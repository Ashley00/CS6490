import socket
import json
import secrets
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# default mode is CBC
def encrypt_3des(key, plaintext, mode='CBC'):
    # for CBC vs ECB diff:
    #if mode == 'ECB':
    #    mode = 'CBC'

    if isinstance(plaintext, str):  # Convert to bytes if it's a string
        plaintext = plaintext.encode()
    
    if mode == 'CBC':
        iv = secrets.token_bytes(8)  # generate a random IV (8 bytes)
        cipher = DES3.new(key, DES3.MODE_CBC, iv) # create a 3DES cipher object
        ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size)) # pad the plaintext to make it a multiple of the block size
        return (iv + ciphertext).hex()  # convert IV + ciphertext to hex
    elif mode == 'ECB':
        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
        return ciphertext.hex()  # convert ciphertext to hex (no IV)
    else:
        raise ValueError("Unsupported mode")

# default mode is CBC
def decrypt_3des(key, hex_ciphertext, mode='CBC'):
    # for CBC vs ECB diff:
    #if mode == 'ECB':
    #    mode = 'CBC'

    data = bytes.fromhex(hex_ciphertext)  # convert hex string back to bytes

    if mode == 'CBC':
        iv, ciphertext = data[:8], data[8:]  # extract IV (first 8 bytes) and ciphertext
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif mode == 'ECB':
        ciphertext = data  # no IV in ECB mode
        cipher = DES3.new(key, DES3.MODE_ECB)
    else:
        raise ValueError("Unsupported mode")

    decrypted = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return decrypted