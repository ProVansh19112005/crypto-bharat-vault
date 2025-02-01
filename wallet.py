import json
import ecdsa
import hashlib
import base58

def create_wallet():
    try:
        # Generate private key
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string().hex()

        # Compute public key
        public_key = '04' + private_key[:64] + private_key[64:]

        # Hash public key for address
        sha256 = hashlib.sha256(bytes.fromhex(public_key)).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        prefix = b'\x30'  # Litecoin prefix
        hashed_public_key = prefix + ripemd160

        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()[:4]
        address = base58.b58encode(hashed_public_key + checksum).decode()

        return address, private_key
    except Exception as e:
        print("Error creating wallet:", e)
        return None, None

def send_litecoin(private_key, recipient, amount):
    try:
        wallet = Wallet("LitecoinWallet")
        tx = wallet.send_to(recipient, amount, network='litecoin')
        return tx
    except Exception as e:
        print(f"Error sending Litecoin: {e}")
        return None

# Show Balance
import requests
def get_balance(address):
    url = f'https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance'
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        balance = data.get('final_balance', 0) / 100000000  # Convert to LTC
        return balance
    else:
        return "Error: Unable to retrieve balance"








