import random
import ecdsa
from utils import b58wchecksum, hash160

class Wallet:
    def __init__(self, seed):
        random.seed(seed)
        self.generate_key_pair()

    def generate_key_pair(self):
        # TODO: generate mainnet and compressed addresses
        self.priv_key = bytes([random.randint(0, 255) for _ in range(32)])

        # https://learnmeabitcoin.com/technical/wif
        # https://en.bitcoin.it/wiki/Wallet_import_format
        # wif = base58.b58encode_check(b'\xef' + priv_key)
        # add 0x80 if it's a mainnet addrress
        self.wif = b58wchecksum(b'\xef' + self.priv_key)

        # https://learnmeabitcoin.com/technical/address
        # http://static.righto.com/images/bitcoin/bitcoinkeys.png
        # https://developer.bitcoin.org/reference/transactions.html#address-conversion
        # https://www.royalfork.org/2014/08/11/graphical-address-generator
        # https://learnmeabitcoin.com/technical/public-key
        sk = ecdsa.SigningKey.from_string(self.priv_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key().to_string()
        # remove 0x04 if the pub_key is compressed
        self.pub_key = b'\x04' + vk

        self.pub_key_hash = hash160(self.pub_key)
        # addr = base58.b58encode_check(b'\x6f' + pub_key_hash)
        # add 0x00 if it's a mainnet addrress
        self.pub_addr = b58wchecksum(b'\x6f' + self.pub_key_hash)

if __name__ == '__main__':
    wallet = Wallet(3301)
    print('pub_addr:', wallet.pub_addr)
