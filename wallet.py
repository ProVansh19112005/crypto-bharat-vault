import os
import hashlib
import base58
import ecdsa
import secrets
from bitcoinlib.wallets import Wallet

def generate_private_key():
    return secrets.token_bytes(32)

def private_key_to_wif(private_key, compressed=True, network='litecoin'):
    if network == 'litecoin':
        version = b'\xb0'
    else:
        version = b'\x80'
    payload = version + private_key
    if compressed:
        payload += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    wif = base58.b58encode(payload + checksum).decode()
    return wif

def private_key_to_public_key(private_key, compressed=True):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if compressed:
        public_key_bytes = vk.to_string()
        x = public_key_bytes[:32]
        y = public_key_bytes[32:]
        prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
        return prefix + x
    else:
        return b'\x04' + vk.to_string()

def public_key_to_litecoin_address(public_key):
    version = b'\x30'
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pk).digest()
    payload = version + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()
    return address

def create_wallet(wallet_name="new_ltc_wallet"):
    private_key = generate_private_key()
    wif = private_key_to_wif(private_key, network='litecoin')
    public_key = private_key_to_public_key(private_key)
    computed_address = public_key_to_litecoin_address(public_key)
    try:
        from bitcoinlib.wallets import wallet_delete
        wallet_delete(wallet_name, force=True)
    except Exception:
        pass
    wallet = Wallet.create(wallet_name, keys=[wif], network='litecoin', witness_type='legacy')
    key = wallet.get_key()
    if key.address != computed_address:
        print("Warning: The computed address does not match bitcoinlib’s address. Using bitcoinlib’s version.")
        computed_address = key.address
        wif = key.wif
    return computed_address, wif

def get_balance(address):
    from bitcoinlib.services.services import Service
    service = Service(network='litecoin')
    balance = service.getbalance(address)
    return balance

if __name__ == '__main__':
    wallet_name = "test_wallet"
    address, wif = create_wallet(wallet_name)
    print("New Litecoin Wallet Generated:")
    print("Address:", address)
    print("Private Key (WIF):", wif)
    balance = get_balance(address)
    print("Balance (in satoshis):", balance)
