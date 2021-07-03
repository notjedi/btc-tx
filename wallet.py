import random
import base58
import binascii
import ecdsa
import hashlib

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

def generate_key_pair():
    priv_key = bytes([random.randint(0, 255) for _ in range(32)])

    # https://learnmeabitcoin.com/technical/wif
    # https://en.bitcoin.it/wiki/Wallet_import_format
    # wif = base58.b58encode_check(b'\xef' + priv_key)
    # add 0x80 if it's a mainnet addrress
    wif = b58wchecksum(b'\xef' + priv_key)


    # https://learnmeabitcoin.com/technical/address
    # http://static.righto.com/images/bitcoin/bitcoinkeys.png
    # https://developer.bitcoin.org/reference/transactions.html#address-conversion
    # https://www.royalfork.org/2014/08/11/graphical-address-generator
    # https://learnmeabitcoin.com/technical/public-key
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key().to_string()
    # remove 0x04 if the pub_key is compressed
    pub_key = b'\x04' + vk

    pub_key_hash = hash160(pub_key)
    # addr = base58.b58encode_check(b'\x6f' + pub_key_hash)
    # add 0x00 if it's a mainnet addrress
    pub_addr = b58wchecksum(b'\x6f' + pub_key_hash)
    return priv_key, wif, pub_key, pub_key_hash, pub_addr

if __name__ == '__main__':
    random.seed(3301)
    priv_key, wif, pub_key, _, pub_addr = generate_key_pair()
    print('pub_addr:', pub_addr)
