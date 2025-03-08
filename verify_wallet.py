import hashlib
import base58
import ecdsa
from bitcoinlib.keys import HDKey

hd_private_key_str = "Ltpv7CM6xSY7X1WxejbstLhUga5uW3txJSvSA3PsxfDk3Ef1y3q1eqNPz1S4qtBtC9VpAV5Uh8wnAMsoDykWnafMg5G8zAWoFWEmKWSp4mq3pS9"
expected_address = "LdULDueQzRbr97qjLHMNFzrsRqQrwB9FpL"

try:
    hd_key = HDKey(hd_private_key_str, network='litecoin')
except Exception as e:
    print("Error creating HDKey:", e)
    exit(1)

print("HD Key depth:", hd_key.depth)

raw_private_key = hd_key.private_byte
print("Raw private key (hex):", raw_private_key.hex())

def private_key_to_public_key(private_key, compressed=True):
    """
    Derive the public key from the raw private key bytes.
    If compressed, return the compressed public key.
    """
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if compressed:
        pub_key_bytes = vk.to_string()
        x = pub_key_bytes[:32]
        y = pub_key_bytes[32:]
        prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
        return prefix + x
    else:
        return b'\x04' + vk.to_string()

public_key = private_key_to_public_key(raw_private_key, compressed=True)
print("Public key (hex):", public_key.hex())

def public_key_to_litecoin_address(public_key):
    """
    Compute a Litecoin legacy (P2PKH) address from a public key.
    Uses Litecoin's version byte 0x30.
    """
    version = b'\x30' 
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pk).digest()
    payload = version + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()
    return address

computed_address = public_key_to_litecoin_address(public_key)
print("Computed Address:", computed_address)
print("Expected Address:", expected_address)

if computed_address == expected_address:
    print("✅ SUCCESS: The private key and Litecoin address match!")
else:
    print("❌ ERROR: The private key does NOT match the Litecoin address!")
