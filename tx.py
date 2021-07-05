import struct
import socket
import random
import ecdsa
import time

from utils import hexify, unhexify, toLittleEndian, sha256, getLen, btcToSatoshi, netaddr, varstr
from hexdump import hexdump
from wallet import Wallet
from ecdsa import util


class Transaction:
    def __init__(self, org: Wallet, dest: Wallet):
        self.org = org
        self.dest = dest
        self.VERSION = 1
        # https://github.com/bitcoin/bitcoin/blob/v0.8.5/src/version.h#L28
        self.PROTOCOL_VERSION = 70001
        self.OP_DUP = '76'
        self.OP_HASH160 = 'a9'
        self.OP_EQUALVERIFY = '88'
        self.OP_CHECKSIG = 'ac'
        self.HASH_CODE_TYPE = b'\x01'
        self.MAGIC_BYTES = '0b110907' # testnet magic bytes


    def makeScriptPubKey(self, addr):
        # locking script
        # https://developer.bitcoin.org/devguide/transactions.html#p2pkh-script-validation
        # https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
        # https://learnmeabitcoin.com/technical/scriptPubKey
        return (self.OP_DUP +
                self.OP_HASH160 +
                getLen(addr) +  # push the next 20(0x14) bytes onto the stack
                addr +          # PK_HASH
                self.OP_EQUALVERIFY +
                self.OP_CHECKSIG)


    def makeOutput(self, data):
        value, addr = data
        scriptPubKey = self.makeScriptPubKey(addr)
        scriptPubKeySize = getLen(scriptPubKey)
        return hexify(struct.pack('<Q', value)) + scriptPubKeySize + scriptPubKey


    def makeRawTx(self, txid, vout, scriptSig):
        # https://www.blockchain.com/btc-testnet/tx/dc2a7fa88c93327fe70893df86d1ed9df4904c8a586d661895756a7b528fbe01
        # https://bitcoin.stackexchange.com/questions/35878/is-there-a-maximum-size-of-a-scriptsig-scriptpubkey
        # https://learnmeabitcoin.com/technical/transaction-data
        # https://en.bitcoin.it/wiki/Protocol_documentation#tx
        # https://www.royalfork.org/2014/11/20/txn-demo/
        version = toLittleEndian(self.VERSION) # version: 1
        lockTime = '00000000'

        # inputs
        input_count = '01' # total input count
        txid = toLittleEndian(txid) # txid (hash of the last tx)
        vout = toLittleEndian(vout) # index of the output from the last tx
        inputs = input_count + txid + vout + getLen(scriptSig) + scriptSig + 'ffffffff'

        # outputs
        output_count = '02'
        outputs = ''.join(map(self.makeOutput, self.outputs))
        outputs = output_count + outputs
        return version + inputs + outputs + lockTime


    def createOutputs(self, balance, value, fee):
        self.outputs = [[value, hexify(self.dest.pub_key_hash)], [balance-value-fee, hexify(self.org.pub_key_hash)]]


    def makeMessage(self, command, payload):
        payloadHash = self.dbl256(payload)[:4]
        # magic, command, payload length, payload checksum, payload
        return unhexify(self.MAGIC_BYTES) + struct.pack('12s', command.encode('utf-8')) +  len(payload).to_bytes(4, 'little') + struct.pack('4s', unhexify(toLittleEndian(payloadHash))) + payload


    def getVersionMsg(self):
        # http://sebastianappelt.com/understanding-blockchain-peer-discovery-and-establishing-a-connection-with-python/
        services = 1
        timestamp = int(time.time())
        addr_recv = netaddr(socket.inet_aton('127.0.0.1'), 8333)
        addr_from = netaddr(socket.inet_aton('127.0.0.1'), 8333)
        nonce = random.getrandbits(64)
        user_agent = varstr(b'')
        start_height = 0

        payload = struct.pack('<LQQ26s26sQsL', self.PROTOCOL_VERSION, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height)
        return self.makeMessage('version', payload)


    def send(self):
        # https://tbtc.bitaps.com/broadcast
        site = 'seed.tbtc.petertodd.org'
        peers = socket.gethostbyname_ex(site)[2]
        random.seed(time.time())
        random.shuffle(peers)

        for peer in peers:
            try:
                print('Connecting with: ', peer)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((peer, 8333))
                print('Connection successful')

                self.sock.send(self.getVersionMsg())
                self.sock.send(self.makeMessage('verack', b''))
                # self.sock.recv(1000)

                self.broadcast = self.makeMessage('tx', unhexify(self.txPayload))
                self.sock.send(self.broadcast)
                hexdump(self.broadcast)
                return
            except (ConnectionRefusedError, ConnectionResetError) as e:
                print(e)
                continue

    @staticmethod
    def dbl256(val):
        return sha256(sha256(val))


    def signTx(self, tx):
        # https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required
        sk = ecdsa.SigningKey.from_string(self.org.priv_key, curve=ecdsa.SECP256k1)
        N = ecdsa.SECP256k1.order
        Nby2 = N / 2
        txSig = None

        while 1:
            # https://bitcoin.stackexchange.com/questions/68254/how-can-i-fix-this-non-canonical-signature-s-value-is-unnecessarily-high
            # https://bitcointalk.org/index.php?topic=1356430.msg13810572#msg13810572
            txSig = sk.sign_digest(tx, sigencode=util.sigencode_der)
            r, s = util.sigdecode_der(txSig, ecdsa.SECP256k1.order)
            if s < Nby2:
                vk = ecdsa.VerifyingKey.from_string(self.org.pub_key, curve=ecdsa.SECP256k1)
                decodedSig = unhexify('%064x%064x' % (r, s))
                assert vk.verify_digest(decodedSig, tx)
                break

        return txSig + self.HASH_CODE_TYPE


    def makeSignedTx(self, txid, vout):
        # tx without scriptSig
        scriptPubKey = self.makeScriptPubKey(hexify(self.org.pub_key_hash))
        fakeTx = unhexify(self.makeRawTx(txid, vout, scriptPubKey) + hexify(struct.pack('<L', int.from_bytes(self.HASH_CODE_TYPE, 'big'))))

        # sign rawTx | unlocking script
        txDigest = self.dbl256(fakeTx)
        signedTx = self.signTx(txDigest)

        # tx with scriptSig
        scriptSig = hexify(varstr(signedTx)) + hexify(varstr(self.org.pub_key))
        self.txPayload = self.makeRawTx(txid, vout, scriptSig)
        return self.txPayload


if __name__ == '__main__':
    # https://blockstream.info/testnet/address/n1DBaALdsbC46K6UAwJDiUBMH8kYPia4Hq
    org = Wallet(3301)
    dest = Wallet(1337)

    # https://bitcoin.stackexchange.com/questions/68390/bitcoin-core-bad-txns-in-belowout
    # https://bitcoin.stackexchange.com/questions/48235/what-is-the-minrelaytxfee
    # REPLACE ALL OF THESE WITH YOUR DATA
    txid = '2b89646ada2f01b7c587469e463bec0e7eea02457988534b1b2192607eca2f5b'
    vout = 0
    balance = btcToSatoshi(0.001)
    val = btcToSatoshi(0.00001)
    fee = btcToSatoshi(0.00001)

    tx = Transaction(org, dest)
    tx.createOutputs(balance, val, fee)
    data = tx.makeSignedTx(txid, vout)
    print('data:', data, end='\n\n')
    print('txid:', toLittleEndian(hexify(Transaction.dbl256(unhexify(data)))), end='\n\n')
    tx.send()
