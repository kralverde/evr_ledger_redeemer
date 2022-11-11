import requests
import json
import copy

from hashlib import sha256

import base58

from btchip.btchip import *
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


''' Script '''


EVRMORE_NODE_IP = '127.0.0.1'
EVRMORE_NODE_PORT = 8819
EVRMORE_NODE_USER = 'username'
EVRMORE_NODE_PASSWORD = 'password'

ADDRESS_TO_SEND_TO = 'CHANGE ME'

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

dongle = getDongle(False)
app = btchip(dongle)

# if you have over 500 addresses (or transactions), change this number
ADDRESSES_TO_CHECK = 500

# derive the xpub of this account, if you used a different bip44 path, change this
ACCOUNT_PATH = "44'/175'/0'"

bip32_intpath = convert_bip32_path_to_list_of_uint32(ACCOUNT_PATH)

prev_path = convert_bip32_intpath_to_strpath(bip32_intpath[:-1])[2:]
prev_account_pubkey = compress_public_key(app.getWalletPublicKey(prev_path)['publicKey'])
fingerprint_bytes = h160b(prev_account_pubkey)[0:4]
childnum_bytes = bip32_intpath[-1].to_bytes(length=4, byteorder="big")
account_data = app.getWalletPublicKey(ACCOUNT_PATH)
account_pubkey = compress_public_key(account_data['publicKey'])
account_chaincode = account_data['chainCode']
account_depth = len(bip32_intpath)

account_node = BIP32(bytes(account_chaincode), None, bytes(account_pubkey), fingerprint_bytes, account_depth)

index_to_path = dict()
index_to_public_key = dict()

for i in range(ADDRESSES_TO_CHECK):
    external_pubkey = account_node.get_pubkey_from_path(f'm/0/{i}')
    external_compressed_pubkey = compress_public_key(external_pubkey)
    external_h160_bytes = h160b(external_compressed_pubkey)
    external_h160_hex = external_h160_bytes.hex()
    
    idx = pubkeys.get(external_h160_hex, None)

    if idx is not None:
        print(f'Found matching ravencoin address: {hash160_to_b58_address(external_h160_bytes, 60)}')
        index_to_public_key[idx] = external_compressed_pubkey
        index_to_path[idx] = f"{ACCOUNT_PATH}/0/{i}"

    internal_pubkey = account_node.get_pubkey_from_path(f'm/1/{i}')
    internal_compressed_pubkey = compress_public_key(internal_pubkey)
    internal_h160_bytes = h160b(internal_compressed_pubkey)
    internal_h160_hex = internal_h160_bytes.hex()

    idx = pubkeys.get(internal_h160_hex, None)

    if idx is not None:
        print(f'Found matching ravencoin address: {hash160_to_b58_address(internal_h160_bytes, 60)}')
        index_to_public_key[idx] = internal_compressed_pubkey
        index_to_path[idx] = f"{ACCOUNT_PATH}/1/{i}"


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
    input.script = get_regular_input_script(b'', index_to_public_key[idx])
    inputs.append(input)
new_tx.inputs = inputs

new_tx_b = new_tx.serialize()

trusted_inputs = []
if os.path.exists('./trusted'):
    print('Trusted inputs found: loading...')
    for i in range(len(os.listdir('./trusted'))):
        with open(f'./trusted/{i}.dat', 'r') as f:
            serialized = json.loads(f.read())
            serialized['value'] = bytearray(bytes.fromhex(serialized['value']))
            trusted_inputs.append(serialized)

else:
    print('No trusted input dat files found, parsing from ledger')
    import time
    sec_start = time.time()
    print('Grabbing trusted inputs (this will take a while since the tx is so big)')
    for i, idx in enumerate(idxs):
        trusted_inputs.append(app.getTrustedInput(transaction, idx))
        print(f'Got input {i + 1} of {len(idxs)}')
    print(f'took {time.time() - sec_start} seconds')

    print('Storing inputs just in case')
    os.mkdir('./trusted')
    for i, input in enumerate(trusted_inputs):
        modified_input = copy.copy(input)
        modified_input['value'] = modified_input['value'].hex()
        serialized = json.dumps(modified_input)
        with open(f'./trusted/{i}.dat', 'w') as f:
            f.write(serialized)

print('Signing Tx')
app.startUntrustedTransaction(True, 0, trusted_inputs, locking_scripts[0])
app.finalizeInput(b'', 0, 0, '', bytes(new_tx_b))
inputSignature = app.untrustedHashSign(index_to_path[idxs[0]], '')
inputSignature[0] = 0x30
new_tx.inputs[0].script = get_regular_input_script(inputSignature, index_to_public_key[idxs[0]])

if len(idxs) > 1:
    for i in range(1, len(idxs)):
        app.startUntrustedTransaction(False, i, trusted_inputs, locking_scripts[i])
        app.finalizeInput(b'', 0, 0, '', bytes(new_tx_b))
        inputSignature = app.untrustedHashSign(index_to_path[idxs[i]], '')
        inputSignature[0] = 0x30
        new_tx.inputs[i].script = get_regular_input_script(inputSignature, index_to_public_key[idxs[i]])

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
