#!/usr/bin/env python3
from bitcoinlib.wallets import Wallet
from bitcoinlib.services.services import Service

def create_wallet(wallet_name="new_ltc_wallet"):
    """
    Create (or load) a new Litecoin mainnet wallet using bitcoinlib.
    Returns a tuple: (litecoin_address, private_key_wif)
    """
    try:
        # Try to load an existing wallet
        wallet = Wallet(wallet_name)
    except Exception:
        # Create a new wallet; keys are generated automatically
        wallet = Wallet.create(wallet_name, network='litecoin', witness_type='legacy')
    key = wallet.get_key()
    address = key.address
    private_key_wif = key.wif
    return address, private_key_wif

def get_balance(address):
    """
    Retrieve the balance for a Litecoin address using bitcoinlib's Service.
    Returns the balance in satoshis.
    """
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
