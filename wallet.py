import random
import ecdsa
from utils import b58wchecksum, ripemd160, sha256

class Wallet:
    def __init__(self, seed):
        random.seed(seed)
        self.generate_key_pair()

    @staticmethod
    def hash160(val):
        return ripemd160(sha256(val))

    @staticmethod
    def gen_priv_key():
        return bytes([random.randint(0, 255) for _ in range(32)])

    @staticmethod
    def privKeyToWif(priv_key):
        # wif = base58.b58encode_check(b'\xef' + priv_key)
        # https://en.bitcoin.it/wiki/Wallet_import_format
        # https://learnmeabitcoin.com/technical/wif
        # add 0x80 if it's a mainnet addrress
        return b58wchecksum(b'\xef' + priv_key)

    @staticmethod
    def privKeyToPubKey(priv_key):
        # https://www.royalfork.org/2014/08/11/graphical-address-generator
        # http://static.righto.com/images/bitcoin/bitcoinkeys.png
        # https://learnmeabitcoin.com/technical/public-key
        # https://learnmeabitcoin.com/technical/address
        sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key().to_string()
        # remove 0x04 if the pub_key is compressed
        return b'\x04' + vk
    
    @staticmethod
    def compressPubKey(pub_key):
        pass

    @staticmethod
    def pubKeyToPubKeyHash(pub_key):
        return Wallet.hash160(pub_key)

    @staticmethod
    def pubKeyHashToPubAddr(pub_key_hash):
        # https://developer.bitcoin.org/reference/transactions.html#address-conversion
        # addr = base58.b58encode_check(b'\x6f' + pub_key_hash)
        # add 0x00 if it's a mainnet addrress
        return b58wchecksum(b'\x6f' + pub_key_hash)

    def generate_key_pair(self):
        # TODO: generate mainnet and compressed addresses
        self.priv_key = self.gen_priv_key()
        self.wif = self.privKeyToWif(self.priv_key)
        self.pub_key = self.privKeyToPubKey(self.priv_key)
        self.pub_key_hash = self.pubKeyToPubKeyHash(self.pub_key)
        self.pub_addr = self.pubKeyHashToPubAddr(self.pub_key_hash)

if __name__ == '__main__':
    org = Wallet(3301)
    dest = Wallet(1337)
    print(org.pub_addr)
    print(dest.pub_addr)
