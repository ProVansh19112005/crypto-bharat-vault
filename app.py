#!/usr/bin/env python3
import os
import json
import requests
import base58
import ecdsa
from ecdsa import SigningKey, SECP256k1
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from wallet import create_wallet, get_balance  # Your wallet functions
from bitcoinlib.wallets import Wallet, wallet_delete  # (May be used for wallet creation)
import hashlib

# --- Monkey-patch bitcoinlib's DbTransactionOutput if needed ---
try:
    from bitcoinlib.transactions import DbTransactionOutput
    if not hasattr(DbTransactionOutput, '_sa_instance_state'):
        # Provide a dummy _sa_instance_state property so that attribute checks pass.
        DbTransactionOutput._sa_instance_state = property(lambda self: None)
except Exception:
    pass
# --- End monkey-patch ---

app = Flask(__name__)

# Configure Database for Flask models
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret-key")

# Initialize Session and Database
Session(app)
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    litecoin_address = db.Column(db.String(100), unique=True, nullable=False)
    private_key = db.Column(db.String(200), nullable=True)  # Stored WIF

# --------------------------
# Helper: Validate Litecoin Address
# --------------------------
def is_valid_ltc_address(address):
    """
    Basic validation for a Litecoin mainnet address.
    Accepts:
      - Legacy addresses starting with "L" or "M" (34 characters)
      - Bech32 addresses starting with "ltc1" (26 to 90 characters)
    """
    if (address.startswith("L") or address.startswith("M")) and len(address) == 34:
        return True
    if address.startswith("ltc1") and 26 <= len(address) <= 90:
        return True
    return False

# --------------------------
# Helper: Convert WIF to SigningKey
# --------------------------
def wif_to_signing_key(wif):
    """
    Convert a Litecoin WIF private key to an ECDSA SigningKey.
    This function supports both standard WIF (expected length 34 bytes after base58
    decoding) and extended private keys (BIP32) that are longer.
    
    For a standard compressed WIF:
      - The decoded bytes are: [version (1)] + [32-byte key] + [compression flag (1)]
        Total length = 34 bytes, plus 4 checksum bytes (handled by base58.b58decode_check).
      - The function strips the version and compression flag to yield 32 bytes.
    
    For an extended private key (if decoded length >= 78 bytes):
      - The extended key format is:
            4 bytes version | 1 byte depth | 4 bytes fingerprint | 4 bytes child number |
            32 bytes chain code | 33 bytes key data (first byte is 0x00, then 32 bytes key)
      - In that case, this function extracts the 32-byte private key.
    
    Raises:
      ValueError: if the extracted key is not 32 bytes.
    """
    decoded = base58.b58decode_check(wif)
    # Standard compressed WIF should have 34 bytes (version + 32-byte key + compression flag)
    if len(decoded) == 34:
        priv_key_bytes = decoded[1:]
        if len(priv_key_bytes) == 33 and priv_key_bytes[-1] == 0x01:
            priv_key_bytes = priv_key_bytes[:-1]
    elif len(decoded) >= 78:
        # Assume it's an extended private key (BIP32 format)
        if decoded[45] == 0:
            priv_key_bytes = decoded[46:78]
        else:
            priv_key_bytes = decoded[-32:]
    else:
        priv_key_bytes = decoded

    if len(priv_key_bytes) != 32:
        raise ValueError(f"Invalid private key length: {len(priv_key_bytes)}; expected 32")
    return SigningKey.from_string(priv_key_bytes, curve=SECP256k1)

# --------------------------------------------------------------------
# Helper functions for manual transaction construction & signing
# --------------------------------------------------------------------
def int_to_little_endian(n, length):
    """Convert an integer to little-endian bytes of specified length."""
    return n.to_bytes(length, byteorder='little')

def varint(n):
    """Encode an integer as a Bitcoin-style varint."""
    if n < 0xfd:
        return n.to_bytes(1, byteorder='little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, byteorder='little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, byteorder='little')
    else:
        return b'\xff' + n.to_bytes(8, byteorder='little')

def address_to_pubkey_hash(address):
    """
    Convert a Base58Check Litecoin address (legacy P2PKH) to its 20-byte hash160.
    Assumes the address is valid.
    """
    decoded = base58.b58decode_check(address)
    # For Litecoin P2PKH addresses, the first byte is the version (0x30)
    return decoded[1:]

def p2pkh_script(pubkey_hash):
    """
    Build a standard P2PKH scriptPubKey:
      OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    return b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

def create_signed_transaction(utxo, recipient_address, amount, fee, change_address, priv_key_wif):
    """
    Build and sign a raw Litecoin transaction using one UTXO.
    
    Parameters:
      utxo: a dictionary (from BlockCypher) with keys:
            "tx_hash" (hex string), "tx_output_n" (int), "value" (satoshis),
            and "script" (hex string of the UTXO's scriptPubKey)
      recipient_address: destination address (string)
      amount: satoshis to send to recipient
      fee: fee in satoshis
      change_address: address for change output (string)
      priv_key_wif: the private key in WIF format
      
    Returns:
      raw_tx_hex: the fully signed transaction as a hex string.
    """
    total_in = utxo["value"]
    change = total_in - amount - fee
    if change < 0:
        return None  # insufficient funds

    # Transaction header
    version = int_to_little_endian(1, 4)  # version 1
    locktime = int_to_little_endian(0, 4)
    
    # ---- Build the input ----
    # txid (in raw tx, txid is little-endian)
    txid = bytes.fromhex(utxo["tx_hash"])[::-1]
    vout = int_to_little_endian(utxo["tx_output_n"], 4)
    sequence = bytes.fromhex("ffffffff")
    
    # For signing, set the scriptSig to the UTXO's scriptPubKey
    script_pubkey = bytes.fromhex(utxo["script"])
    script_length = varint(len(script_pubkey))
    txin_for_sign = txid + vout + script_length + script_pubkey + sequence

    # ---- Build the outputs ----
    # Recipient output:
    recipient_pubkey_hash = address_to_pubkey_hash(recipient_address)
    recipient_script = p2pkh_script(recipient_pubkey_hash)
    recipient_value = int_to_little_endian(amount, 8)
    recipient_script_length = varint(len(recipient_script))
    txout_recipient = recipient_value + recipient_script_length + recipient_script

    # Change output (if change > 0)
    txout_change = b""
    if change > 0:
        change_pubkey_hash = address_to_pubkey_hash(change_address)
        change_script = p2pkh_script(change_pubkey_hash)
        change_value = int_to_little_endian(change, 8)
        change_script_length = varint(len(change_script))
        txout_change = change_value + change_script_length + change_script

    output_count = 2 if change > 0 else 1
    txout = txout_recipient + txout_change

    txin_count = varint(1)
    txout_count = varint(output_count)

    # Build the transaction for signing
    pre_tx = version + txin_count + txin_for_sign + txout_count + txout + locktime
    # Append hash type (SIGHASH_ALL = 0x01) as 4-byte little-endian
    hash_type = int_to_little_endian(1, 4)
    pre_tx_for_sign = pre_tx + hash_type

    # Calculate the sighash (double SHA256)
    sighash = hashlib.sha256(hashlib.sha256(pre_tx_for_sign).digest()).digest()

    # ---- Sign the transaction ----
    signing_key = wif_to_signing_key(priv_key_wif)
    signature = signing_key.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der) + b'\x01'

    # Build the scriptSig: push signature and public key (compressed)
    verifying_key = signing_key.get_verifying_key()
    pubkey = verifying_key.to_string("compressed")
    script_sig = (len(signature).to_bytes(1, byteorder='little') + signature +
                  len(pubkey).to_bytes(1, byteorder='little') + pubkey)
    script_sig_length = varint(len(script_sig))

    # Rebuild the input with the final scriptSig
    txin_final = txid + vout + script_sig_length + script_sig + sequence

    # Final raw transaction
    final_tx = version + txin_count + txin_final + txout_count + txout + locktime
    return final_tx.hex()

# --------------------------
# Routes
# --------------------------
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('intro'))
    return redirect(url_for('index'))

@app.route('/intro')
def intro():
    return render_template('intro.html')

import re

def is_valid_email(address):
    # A simple regex that checks for "something@something.something"
    pattern = r"^[^@]+@[^@]+\.[^@]+$"
    return re.match(pattern, address) is not None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 1) Check if username is a valid email
        if not is_valid_email(username):
            flash('Username must be a valid email address!', 'error')
            return redirect(url_for('register'))

        # 2) Proceed if valid
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        print(f"DEBUG: Generating Litecoin wallet for new user {username}...")
        litecoin_address, private_key_wif = create_wallet(wallet_name="wallet_" + username)
        new_user = User(username=username, password=password,
                        litecoin_address=litecoin_address, private_key=private_key_wif)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        print(f"DEBUG: Wallet generated for user {username} - Address = {litecoin_address}, Private Key = {private_key_wif}")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/check_balance', methods=['GET', 'POST'], endpoint="wallet_balance")
def check_balance():
    address_to_check = request.form.get('address')
    if not address_to_check and 'user_id' in session:
        user = User.query.get(session['user_id'])
        address_to_check = user.litecoin_address
    if not address_to_check:
        return render_template('check_balance.html', error="Please enter a Litecoin address.")
    if not is_valid_ltc_address(address_to_check):
        # Immediately return error for invalid address.
        return render_template('check_balance.html', error="Litecoin address is incorrect!", address=address_to_check)
    
    url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address_to_check}/balance"
    try:
        response = requests.get(url)
        print(f"API Status Code: {response.status_code}")
        print(f"API Response: {response.text}")
        if response.status_code == 200:
            data = response.json()
            balance_ltc = data.get('final_balance', 0) / 1e8
            unconfirmed_ltc = data.get('unconfirmed_balance', 0) / 1e8

            # Fetch LTC → INR rate from CoinGecko
            rate_url = "https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=inr"
            rate_response = requests.get(rate_url)
            if rate_response.status_code == 200:
                rates = rate_response.json().get('litecoin', {})
                inr_rate = rates.get('inr', 0)
            else:
                inr_rate = 0

            balance_inr = balance_ltc * inr_rate
            unconfirmed_inr = unconfirmed_ltc * inr_rate

            return render_template('check_balance.html', 
                                   balance=balance_ltc,
                                   unconfirmed_balance=unconfirmed_ltc,
                                   balance_inr=balance_inr,
                                   unconfirmed_inr=unconfirmed_inr,
                                   address=address_to_check)
        else:
            return render_template('check_balance.html', error="Error fetching balance", address=address_to_check)
    except Exception as e:
        return render_template('check_balance.html', error=str(e), address=address_to_check)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials, please try again.", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return render_template('logout.html')

@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/create_wallet')
def create_wallet_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.litecoin_address:
        # Removed the flash message "Wallet already exists."
        return render_template('wallet_created.html', user=user, private_key=user.private_key)
    litecoin_address, private_key_wif = create_wallet(wallet_name="wallet_" + user.username)
    user.litecoin_address = litecoin_address
    user.private_key = private_key_wif
    try:
        db.session.commit()
    except Exception as e:
        flash("Error saving wallet: " + str(e), "error")
    return render_template('wallet_created.html', user=user, private_key=user.private_key)

@app.route('/send', methods=['GET', 'POST'])
def send_litecoin():
    """
    Manually build, sign, and broadcast a Litecoin transaction.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    
    # Ensure the user has a wallet
    if not user.litecoin_address:
        flash("No wallet found. Please create one.", "error")
        return redirect(url_for("create_wallet_route"))
    
    if request.method == 'POST':
        recipient_address = request.form.get('recipient_address')
        amount_ltc = request.form.get('amount')
        
        print("Received POST request")
        print(f"Recipient: {recipient_address}, Amount: {amount_ltc}")
        
        if not recipient_address or not amount_ltc:
            flash("Enter recipient address and amount.", "error")
            return redirect(url_for("send_litecoin"))
        
        try:
            # Convert LTC amount to satoshis
            amount_satoshis = int(Decimal(amount_ltc) * 100_000_000)
        except Exception as e:
            flash("Invalid amount.", "error")
            return redirect(url_for("send_litecoin"))
        
        fee_satoshis = 5000  # Example fee (adjust as needed)
        
        # Fetch UTXOs for the sender's address from BlockCypher (include script info)
        utxo_url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{user.litecoin_address}?unspentOnly=true&includeScript=true"
        utxo_resp = requests.get(utxo_url)
        if utxo_resp.status_code != 200:
            error_msg = "Error fetching UTXOs: " + utxo_resp.text
            return render_template("transaction_failure.html", error=error_msg)
        utxo_data = utxo_resp.json()
        if "txrefs" not in utxo_data or len(utxo_data["txrefs"]) == 0:
            error_msg = "No UTXOs available."
            return render_template("transaction_failure.html", error=error_msg)
        
        # For simplicity, select the first UTXO with sufficient funds
        selected_utxo = None
        for utxo in utxo_data["txrefs"]:
            if utxo["value"] >= amount_satoshis + fee_satoshis:
                selected_utxo = utxo
                break
        if selected_utxo is None:
            error_msg = "No UTXO with sufficient funds."
            return render_template("transaction_failure.html", error=error_msg)
        
        # Create the raw transaction manually
        raw_tx = create_signed_transaction(
            selected_utxo,
            recipient_address,
            amount_satoshis,
            fee_satoshis,
            user.litecoin_address,  # Send change back to sender
            user.private_key
        )
        if raw_tx is None:
            error_msg = "Failed to create raw transaction."
            return render_template("transaction_failure.html", error=error_msg)
        
        # Broadcast the raw transaction via BlockCypher's push API
        push_url = "https://api.blockcypher.com/v1/ltc/main/txs/push"
        push_data = {"tx": raw_tx}
        push_resp = requests.post(push_url, json=push_data)
        if push_resp.status_code not in (200, 201):
            error_msg = "Broadcast failed: " + push_resp.text
            return render_template("transaction_failure.html", error=error_msg)
        
        tx_info = push_resp.json()
        txid = tx_info.get("tx", {}).get("hash", "unknown")
        return redirect(url_for("transaction_successful", txid=txid))
    
    return render_template('send_litecoin.html', user=user)

@app.route('/transaction_successful')
def transaction_successful():
    txid = request.args.get('txid')  # Get TXID from the URL parameters
    return render_template('transaction_successful.html', txid=txid)

# --------------------------
# New Route: Transaction History
# --------------------------
@app.route('/history')
def history():
    """
    Display the transaction history for the logged-in user's Litecoin address.
    Uses the BlockCypher API to fetch confirmed and unconfirmed transactions.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    address = user.litecoin_address
    history_url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}?limit=50"
    try:
        response = requests.get(history_url)
        if response.status_code == 200:
            data = response.json()
            # BlockCypher returns "txrefs" for confirmed transactions and "unconfirmed_txrefs" for unconfirmed ones.
            txrefs = data.get("txrefs", [])
            unconfirmed_txrefs = data.get("unconfirmed_txrefs", [])
            transactions = txrefs + unconfirmed_txrefs
            # Optionally, sort transactions by confirmation time (if available)
            transactions.sort(key=lambda x: x.get("confirmed", ""), reverse=True)
            return render_template("history.html", transactions=transactions, address=address)
        else:
            flash("Error fetching transaction history", "error")
            return redirect(url_for("index"))
    except Exception as e:
        flash("Error: " + str(e), "error")
        return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True)