import hashlib
import base58
import binascii
import struct

def toLittleEndian(val):
    # big endian to little endian
    # return bytearray.fromhex(val).reverse()
    return hexify(struct.pack('<L', val))

def hexify(val):
    return binascii.hexlify(val).decode()

def sha256(val):
    return hashlib.sha256(val).digest()

def ripemd160(val):
    ripemd = hashlib.new('ripemd160')
    ripemd.update(val)
    return ripemd.digest()

def hash160(val):
    return ripemd160(sha256(val))

def b58wchecksum(val):
    checksum = sha256(sha256(val))[:4]
    return base58.b58encode(val + checksum).decode()
