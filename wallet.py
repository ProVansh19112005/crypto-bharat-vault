#!/usr/bin/env python3
import os
import hashlib
import base58
import ecdsa
import secrets
from bitcoinlib.wallets import Wallet

def generate_private_key():
    """Generate a 32-byte cryptographically secure private key."""
    return secrets.token_bytes(32)

def private_key_to_wif(private_key, compressed=True, network='litecoin'):
    """
    Convert a private key (32 bytes) to Wallet Import Format (WIF).
    For Litecoin mainnet, the private key version byte is 0xB0.
    (For Bitcoin it is 0x80.)
    """
    # Set the version byte depending on the network
    if network == 'litecoin':
        version = b'\xb0'
    else:
        version = b'\x80'
    payload = version + private_key
    if compressed:
        payload += b'\x01'
    # Compute the checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    wif = base58.b58encode(payload + checksum).decode()
    return wif

def private_key_to_public_key(private_key, compressed=True):
    """
    Derive the public key from the private key.
    If compressed, use the compressed format.
    """
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
    """
    Convert a public key into a Litecoin legacy (P2PKH) address.
    Litecoin P2PKH addresses use version byte 0x30.
    """
    version = b'\x30'  # Litecoin P2PKH version byte (48 decimal)
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pk).digest()
    payload = version + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()
    return address

def create_wallet(wallet_name="new_ltc_wallet"):
    """
    Create (or load) a new Litecoin mainnet wallet using a manually generated key.
    
    This function does the following:
      1. Generates a new private key.
      2. Converts it to WIF (using Litecoin’s private key version byte 0xB0).
      3. Derives the public key and computes the corresponding Litecoin address
         (using version byte 0x30 for P2PKH addresses).
      4. Imports the key into a bitcoinlib wallet so that later operations (like sending)
         use this key.
    
    Returns:
        tuple: (litecoin_address, private_key_wif)
    """
    # Generate a new key pair
    private_key = generate_private_key()
    wif = private_key_to_wif(private_key, network='litecoin')
    public_key = private_key_to_public_key(private_key)
    computed_address = public_key_to_litecoin_address(public_key)
    
    # For bitcoinlib to use this key, import it into a new wallet.
    # Optionally, delete any existing wallet with the same name so you always start fresh.
    try:
        from bitcoinlib.wallets import wallet_delete
        wallet_delete(wallet_name, force=True)
    except Exception:
        pass  # If the wallet does not exist, that's fine.
    
    wallet = Wallet.create(wallet_name, keys=[wif], network='litecoin', witness_type='legacy')
    
    # Retrieve the key as stored by bitcoinlib; if the computed address differs, log a warning.
    key = wallet.get_key()
    if key.address != computed_address:
        print("Warning: The computed address does not match bitcoinlib’s address. Using bitcoinlib’s version.")
        computed_address = key.address
        wif = key.wif
    return computed_address, wif

def get_balance(address):
    """
    Retrieve the balance for a given Litecoin mainnet address using bitcoinlib's Service.
    
    Returns:
        int: Balance in satoshis (1 LTC = 100,000,000 satoshis)
    """
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
