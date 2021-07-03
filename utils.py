import hashlib
import base58
import binascii
import struct

def btcToSatoshi(val):
    # 1 BTC = 1e8 satoshi
    return int(val * 1e8)

def toLittleEndian(val):
    # big endian to little endian
    if isinstance(val, bytes) or isinstance(val, int):
        out = struct.pack('<L', val)
    else:
        out = bytearray.fromhex(val)
        out.reverse()
    return hexify(out)

def hexify(val):
    if isinstance(val, bytes) or isinstance(val, bytearray):
        return binascii.hexlify(val).decode()
    else:
        return hex(val)[2:]

def getLen(val):
    # gets the length of the hex value given
    return hexify(len(binascii.unhexlify(val)))


def netaddr(ipaddr, port):
    # https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    services = 1
    return struct.pack('<Q12s', services, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') + struct.pack('>4sH', ipaddr, port)

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
