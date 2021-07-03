import random
import struct
import ecdsa

from ecdsa import util
from wallet import generate_key_pair
from utils import hexify, toLittleEndian, sha256


def makeScriptPubKey(addr):
    # locking script
    # https://learnmeabitcoin.com/technical/scriptPubKey
    # https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
    # https://developer.bitcoin.org/devguide/transactions.html#p2pkh-script-validation
    return ('76' + # OP_DUP
            'a9' + # OP_HASH160
            addr + # PK_HASH
            '88' + # OP_EQUALVERIFY
            'ac') # OP_CHECKSIG


def getLenOfHex(val):
    return hexify(len(val) // 2)


def makeOutput(data):
    value, addr = data
    scriptPubKey = makeScriptPubKey(addr)
    scriptPubKeySize = getLenOfHex(scriptPubKey)
    return hexify(struct.pack('<Q', value)) + scriptPubKeySize + scriptPubKey


def makeRawTx(txid, vout, scriptSig, outputs):
    # https://en.bitcoin.it/wiki/Protocol_documentation#tx
    # https://learnmeabitcoin.com/technical/transaction-data
    # https://bitcoin.stackexchange.com/questions/35878/is-there-a-maximum-size-of-a-scriptsig-scriptpubkey
    # https://www.blockchain.com/btc-testnet/tx/dc2a7fa88c93327fe70893df86d1ed9df4904c8a586d661895756a7b528fbe01
    version = toLittleEndian('00000001') # version: 1
    lockTime = '00000000'

    # inputs
    input_count = '01' # total input count
    txid = toLittleEndian(txid) # txid (hash of the last tx)
    vout = toLittleEndian(vout) # index of the output from the last tx
    inputs = input_count + txid + vout + hexify(len(scriptSig)) + scriptSig + 'ffffffff'
    # outputs
    output_count = hexify(len(outputs))
    outputs = ''.join(map(makeOutput, outputs))
    outputs = output_count + outputs

    return version + inputs + outputs + lockTime


def signTx(tx):
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    print(sk.sign_digest(tx, sigencode=util.sigencode_der))
    print(sk.sign(tx))
    return sk.sign_digest(tx, sigencode=util.sigencode_der)


def makeSignedTx(output_hash, index, outputs):
    # output_hash = 'dc2a7fa88c93327fe70893df86d1ed9df4904c8a586d661895756a7b528fbe01'
    # index = '00000001'

    # tx without scriptSig
    scriptPubKey = makeScriptPubKey(pub_key_hash)
    scriptPubKeySize = getLenOfHex(scriptPubKey)
    rawTx = makeRawTx(output_hash, index, scriptPubKeySize + scriptPubKey, outputs)
    # sign rawTx
    txDigest = sha256(sha256(rawTx))
    signedTx = signTx(txDigest)
    # tx with scriptSig
    scriptSig = getLenOfHex(signedTx) + hexify(signedTx) + getLenOfHex(pub_key) + pub_key
    return makeRawTx(output_hash, index, scriptSig, outputs)


if __name__ == '__main__':
    random.seed(3301)
    priv_key, wif, pub_key, pub_key_hash, pub_addr = generate_key_pair()
    
    print('pub_addr:', pub_addr)
