import requests
import json
import copy

from hashlib import sha256, pbkdf2_hmac

import base58

import ecdsa

import unicodedata
import string

from typing import Sequence, Dict, Tuple
from types import MappingProxyType

from btchip.btchipUtils import *

from bip32 import BIP32, ripemd160

''' Helpers '''

class CountList(list):

    def __iter__(self):
        total = len(self)
        for i in range(total):
            print(f'Output {i + 1} of {total}', end='\r')
            yield self[i]
        print('')

def sha256d(b: bytes):
    return sha256(sha256(b).digest()).digest()

def h160h(b: bytes):
    return h160b(b).hex()

def h160b(b: bytes):
    return ripemd160.ripemd160(sha256(b).digest())

def hash160_to_b58_address(h160: bytes, addrtype: int) -> str:
    s = bytes([addrtype]) + h160
    s = s + sha256d(s)[0:4]
    return base58.b58encode(s)

BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1

def convert_bip32_path_to_list_of_uint32(n: str):
    """Convert bip32 path to list of uint32 integers with prime flags
    m/0/-1/1' -> [0, 0x80000001, 0x80000001]

    based on code in trezorlib
    """
    if not n:
        return []
    if n.endswith("/"):
        n = n[:-1]
    n = n.split('/')
    # cut leading "m" if present, but do not require it
    if n[0] == "m":
        n = n[1:]
    path = []
    for x in n:
        if x == '':
            # gracefully allow repeating "/" chars in path.
            # makes concatenating paths easier
            continue
        prime = 0
        if x.endswith("'") or x.endswith("h"):
            x = x[:-1]
            prime = BIP32_PRIME
        if x.startswith('-'):
            if prime:
                raise ValueError(f"bip32 path child index is signalling hardened level in multiple ways")
            prime = BIP32_PRIME
        child_index = abs(int(x)) | prime
        if child_index > UINT32_MAX:
            raise ValueError(f"bip32 path child index too large: {child_index} > {UINT32_MAX}")
        path.append(child_index)
    return path


def convert_bip32_intpath_to_strpath(path) -> str:
    s = "m/"
    for child_index in path:
        if not isinstance(child_index, int):
            raise TypeError(f"bip32 path child index must be int: {child_index}")
        if not (0 <= child_index <= UINT32_MAX):
            raise ValueError(f"bip32 path child index out of range: {child_index}")
        prime = ""
        if child_index & BIP32_PRIME:
            prime = "'"
            child_index = child_index ^ BIP32_PRIME
        s += str(child_index) + prime + '/'
    # cut trailing "/"
    s = s[:-1]
    return s

def op_push(i: int) -> bytes:
    if i < 0x4c:
        return i.to_bytes(1, 'little', signed=False)
    elif i <= 0x4d:
        return b'\x4c' + i.to_bytes(1, 'little', signed=False)
    elif i <= 0xffff:
        return b'\x4d' + i.to_bytes(2, 'little', signed=False)
    else:
        return b'\x4e' + i.to_bytes(4, 'little', signed=False)

def var_int(i: int) -> str:
    assert i >= 0, i
    if i<0xfd:
        return i.to_bytes(1, 'little', signed=False)
    elif i<=0xffff:
        return b'\xfd'+i.to_bytes(2, 'little', signed=False)
    elif i<=0xffffffff:
        return b'\xfe'+i.to_bytes(4, 'little', signed=False)
    else:
        return b'\xff'+i.to_bytes(8, 'little', signed=False)

# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F, 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]

def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False


def normalize_text(seed: str) -> str:
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed


_WORDLIST_CACHE = {}  # type: Dict[str, Wordlist]


class Wordlist(tuple):

    def __init__(self, words: Sequence[str]):
        super().__init__()
        index_from_word = {w: i for i, w in enumerate(words)}
        self._index_from_word = MappingProxyType(index_from_word)  # no mutation
        self.space = ' '

    def index(self, word, start=None, stop=None) -> int:
        try:
            return self._index_from_word[word]
        except KeyError as e:
            raise ValueError from e

    def __contains__(self, word) -> bool:
        try:
            self.index(word)
        except ValueError:
            return False
        else:
            return True

    @classmethod
    def from_file(cls, filename) -> 'Wordlist':
        path = f'./wordlist/{filename}'
        if path not in _WORDLIST_CACHE:
            with open(path, 'r', encoding='utf-8') as f:
                s = f.read().strip()
            s = unicodedata.normalize('NFKD', s)
            lines = s.split('\n')
            words = []
            for line in lines:
                line = line.split('#')[0]
                line = line.strip(' \r')
                assert ' ' not in line
                if line:
                    words.append(line)

            _WORDLIST_CACHE[path] = Wordlist(words)
        return _WORDLIST_CACHE[path]


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'ja':'japanese.txt',
    #'pt':'portuguese.txt',
    'zh_s':'chinese_simplified.txt',
    'zh_t':'chinese_traditional.txt',
    'fr':'french.txt',
    'it':'italian.txt',
    'ko':'korean.txt'
}


def bip39_is_checksum_valid(
        mnemonic: str,
        wordlist: Wordlist
) -> Tuple[bool, bool]:
    """Test checksum of bip39 mnemonic assuming English wordlist.
    Returns tuple (is_checksum_valid, is_wordlist_valid)
    """
    words = [unicodedata.normalize('NFKD', word) for word in mnemonic.split()]
    words_len = len(words)
    n = len(wordlist)
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist.index(w)
        except ValueError:
            return False, False, f'{w} not in wordlist'
        i = i*n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True, 'invalid number of words'
    checksum_length = 11 * words_len // 33  # num bits
    entropy_length = 32 * checksum_length  # num bits
    entropy = i >> checksum_length
    checksum = i % 2**checksum_length
    entropy_bytes = int.to_bytes(entropy, length=entropy_length//8, byteorder="big")
    hashed = int.from_bytes(sha256(entropy_bytes).digest(), byteorder="big")
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True, ''


def bip39_normalize_passphrase(passphrase):
    return unicodedata.normalize('NFKD', passphrase or '')


def bip39_to_seed(mnemonic, passphrase):
    PBKDF2_ROUNDS = 2048
    mnemonic = unicodedata.normalize('NFKD', ' '.join(mnemonic.split()))
    passphrase = bip39_normalize_passphrase(passphrase)
    return pbkdf2_hmac('sha512', mnemonic.encode('utf-8'),
        b'mnemonic' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)


def serialize_input(txin, script: bytes) -> bytes:
        # Prev hash and index
        s = txin.prevOut
        # Script length, script, sequence
        s += var_int(len(script))
        s += script
        s += txin.sequence
        return s


def tx_to_preimage(tx: bitcoinTransaction, signing_txin, locking_script):
    txins = var_int(len(tx.inputs))
    for i, txin in enumerate(tx.inputs):
        txin = serialize_input(txin, locking_script if signing_txin == i else b'')
        txins += txin
    txouts = var_int(len(tx.outputs)) + b''.join(bytes(o.serialize()) for o in tx.outputs)
    return tx.version + txins + txouts + tx.lockTime + (1).to_bytes(4, 'little', signed=False)

''' Script '''

EVRMORE_NODE_IP = '127.0.0.1'
EVRMORE_NODE_PORT = 8819
EVRMORE_NODE_USER = 'username'
EVRMORE_NODE_PASSWORD = 'password'

ADDRESS_TO_SEND_TO = 'CHANGE ME'

MNEMONIC = 'CHANGE ME'
MNEMONIC_PASSPHRASE = ''  # Only change if you know what this is

for name, file in filenames.items():
    checksum_ok, filename_ok, error = bip39_is_checksum_valid(MNEMONIC, Wordlist.from_file(file))
    if checksum_ok:
        break
if not checksum_ok:
    print(f'invalid mnemonic: {error}')
    exit()

print(f'valid mnemonic (lang: {name})')

seed = bip39_to_seed(normalize_text(MNEMONIC), MNEMONIC_PASSPHRASE)
root_node = BIP32.from_seed(seed)

print('Getting blockhash 0')
data = {
    'jsonrpc':'2.0',
    'id':'0',
    'method':'getblockhash',
    'params':[0]
}
res = requests.post(f'http://{EVRMORE_NODE_USER}:{EVRMORE_NODE_PASSWORD}@{EVRMORE_NODE_IP}:{EVRMORE_NODE_PORT}', json=data)
#print(res.text)
block_hash_hex = json.loads(res.text)['result']

print('Getting block 0')
data = {
    'jsonrpc':'2.0',
    'id':'0',
    'method':'getblock',
    'params':[block_hash_hex]
}
res = requests.post(f'http://{EVRMORE_NODE_USER}:{EVRMORE_NODE_PASSWORD}@{EVRMORE_NODE_IP}:{EVRMORE_NODE_PORT}', json=data)
#print(res.text)
chain_base_txid = json.loads(res.text)['result']['tx'][0]

print('Getting chainbase tx')
data = {
    'jsonrpc':'2.0',
    'id':'0',
    'method':'getrawtransaction',
    'params':[chain_base_txid, True]
}
res = requests.post(f'http://{EVRMORE_NODE_USER}:{EVRMORE_NODE_PASSWORD}@{EVRMORE_NODE_IP}:{EVRMORE_NODE_PORT}', json=data)
#print(res.text)
chain_base_tx_vouts = json.loads(res.text)['result']['vout']
chain_base_tx_raw = json.loads(res.text)['result']['hex']

print('mapping public keys h160 to idxs')
pubkeys = dict()
for i, vout_dict in enumerate(chain_base_tx_vouts):
    vout_hex = vout_dict['scriptPubKey']['hex']
    if vout_hex[:2] == '41' and vout_hex[-2:] == 'ac':
        pubkey_h160 = h160h(compress_public_key(bytes.fromhex(vout_hex[2:-2])))
        pubkeys[pubkey_h160] = i
    elif vout_hex[:6] == '76a914' and vout_hex[-4:] == '88ac':
        pubkeys[vout_hex[6:-4]] = i
    elif vout_hex[:4] == 'a914' and vout_hex[-2:] == '87':
        pubkeys[vout_hex[4:-2]] = i
    else:
        raise Exception('Not valid vout')

# if you have over 500 addresses (or transactions), change this number
ADDRESSES_TO_CHECK = 500

# derive the xpub of this account, if you used a different bip44 path, change this
ACCOUNT_PATH = "44'/175'/0'"

index_to_path = dict()
index_to_public_key = dict()

for i in range(ADDRESSES_TO_CHECK):
    external_pubkey = root_node.get_pubkey_from_path(f'm/{ACCOUNT_PATH}/0/{i}')
    external_compressed_pubkey = compress_public_key(external_pubkey)
    external_h160_bytes = h160b(external_compressed_pubkey)
    external_h160_hex = external_h160_bytes.hex()
    
    idx = pubkeys.get(external_h160_hex, None)

    if idx is not None:
        print(f'Found matching ravencoin address: {hash160_to_b58_address(external_h160_bytes, 60)}')
        index_to_public_key[idx] = external_compressed_pubkey
        index_to_path[idx] = f'm/{ACCOUNT_PATH}/0/{i}'

    internal_pubkey = root_node.get_pubkey_from_path(f'm/{ACCOUNT_PATH}/1/{i}')
    internal_compressed_pubkey = compress_public_key(internal_pubkey)
    internal_h160_bytes = h160b(internal_compressed_pubkey)
    internal_h160_hex = internal_h160_bytes.hex()

    idx = pubkeys.get(internal_h160_hex, None)

    if idx is not None:
        print(f'Found matching ravencoin address: {hash160_to_b58_address(internal_h160_bytes, 60)}')
        index_to_public_key[idx] = internal_compressed_pubkey
        index_to_path[idx] = f'm/{ACCOUNT_PATH}/1/{i}'


transaction = bitcoinTransaction(bytes.fromhex(chain_base_tx_raw))
transaction.outputs = CountList(transaction.outputs)

print('Grabbing locking scripts')
idxs = [k for k in index_to_path.keys()]
idxs.sort()
locking_scripts = [transaction.outputs[k].script for k in idxs]
amount = sum(int.from_bytes(transaction.outputs[k].amount, 'little', signed=False) for k in idxs)

print(f'Total EVR amount: {amount/100_000_000}')

print('Creating new unsigned tx')
output = bitcoinOutput()

# Static 0.01 EVR fee. Change this if you want
output.amount = (amount - 1_000_000).to_bytes(8, 'little', signed=False)
raw_addr = base58.b58decode_check(ADDRESS_TO_SEND_TO)
if raw_addr[0] != 33:
    raise Exception('Not sending to a p2pkh address')
output.script = b'\x76\xa9\x14' + raw_addr[1:] + b'\x88\xac'

new_tx = bitcoinTransaction()
new_tx.version = (1).to_bytes(4, 'little', signed=False)
new_tx.lockTime = (0).to_bytes(4, 'little', signed=False)
new_tx.outputs = [output]
inputs = []
for idx in idxs:
    input = bitcoinInput()
    input.prevOut = bytes.fromhex(chain_base_txid)[::-1] + idx.to_bytes(4, 'little', signed=False)
    input.sequence = b'\xff\xff\xff\xff'
    # Just the public key for now...
    input.script = b'' #get_regular_input_script(b'', index_to_public_key[idx])
    inputs.append(input)
new_tx.inputs = inputs

print('Signing Tx')

sigs = []
for i, idx in enumerate(idxs):
    pk = root_node.get_privkey_from_path(index_to_path[idx])

    external_pubkey = root_node.get_pubkey_from_path(index_to_path[idx])
    external_compressed_pubkey = compress_public_key(external_pubkey)
    external_h160_bytes = h160b(external_compressed_pubkey)
    address = hash160_to_b58_address(external_h160_bytes, 33)
    print(f'signing vin {i} for {address}')
    
    preimage = tx_to_preimage(new_tx, i, locking_scripts[i])
    to_sign = sha256d(preimage)
    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(to_sign, sigencode=ecdsa.util.sigencode_der) + b'\x01' # 01 is hashtype
    sigs.append(sig)

for i, sig in enumerate(sigs):    
    new_tx.inputs[i].script = get_regular_input_script(sig, index_to_public_key[idxs[i]])

signed_tx_h = bytes(new_tx.serialize()).hex()
print(signed_tx_h)
print('broadcasting tx')
data = {
    'jsonrpc':'2.0',
    'id':'0',
    'method':'sendrawtransaction',
    'params':[signed_tx_h]
}
res = requests.post(f'http://{EVRMORE_NODE_USER}:{EVRMORE_NODE_PASSWORD}@{EVRMORE_NODE_IP}:{EVRMORE_NODE_PORT}', json=data)
print(res.text)
