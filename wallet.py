import json
import ecdsa
import hashlib
import base58
import requests

# Create a Litecoin wallet
def create_wallet():
    try:
        # Generate private key
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        private_key = sk.to_string().hex()

        # Compute public key
        vk = sk.verifying_key
        public_key = b'\x04' + vk.to_string()

        # Hash public key for address
        sha256 = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()

        # Litecoin Mainnet Prefix (P2PKH - addresses start with 'L')
        prefix = b'\x30'  
        hashed_public_key = prefix + ripemd160

        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()[:4]
        address = base58.b58encode(hashed_public_key + checksum).decode()

        return address, private_key
    except Exception as e:
        print("Error creating wallet:", e)
        return None, None

# Get Litecoin balance using SoChain API
def get_balance(litecoin_address):
    url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{litecoin_address}/balance"
    response = requests.get(url)

    # Log the response
    print(f"API Response: {response.status_code} - {response.text}")

    if response.status_code == 200:
        balance_data = response.json()
        return balance_data.get('final_balance', 0)
    else:
        print(f"Error fetching balance: {response.status_code}")
        return 0


# Placeholder for send_litecoin (transaction signing not implemented yet)
def send_litecoin(private_key, recipient, amount):
    print("Error: send_litecoin is not yet implemented")
    return None

# Example usage
if __name__ == "__main__":
    addr, priv = create_wallet()
    if addr:
        print(f"New Litecoin Address: {addr}")
        print(f"Private Key: {priv}")
        print(f"Balance: {get_balance(addr)} LTC")









