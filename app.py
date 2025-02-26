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
import secrets
import string

# Import libraries for 2FA
import pyotp
import qrcode
from io import BytesIO
import base64

# --- Monkey-patch bitcoinlib's DbTransactionOutput if needed ---
try:
    from bitcoinlib.transactions import DbTransactionOutput
    if not hasattr(DbTransactionOutput, '_sa_instance_state'):
        DbTransactionOutput._sa_instance_state = property(lambda self: None)
except Exception:
    pass
# --- End monkey-patch ---

app = Flask(__name__)

# Configure Database for Flask models using an absolute path
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'database.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret-key")

# Initialize Session and Database
Session(app)
db = SQLAlchemy(app)

# Define User model (updated with secret_code and totp_secret fields)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    litecoin_address = db.Column(db.String(100), unique=True, nullable=False)
    private_key = db.Column(db.String(200), nullable=True)  # Stored WIF
    secret_code = db.Column(db.String(12), nullable=False)   # 12-letter secret code
    totp_secret = db.Column(db.String(32), nullable=True)      # TOTP secret for 2FA

# --------------------------
# Helper: Generate 12-letter Secret Code
# --------------------------
def generate_secret_code(length=12):
    return ''.join(secrets.choice(string.ascii_letters) for _ in range(length))

# --------------------------
# Helper: Validate Litecoin Address
# --------------------------
def is_valid_ltc_address(address):
    if (address.startswith("L") or address.startswith("M")) and len(address) == 34:
        return True
    if address.startswith("ltc1") and 26 <= len(address) <= 90:
        return True
    return False

# --------------------------
# Helper: Convert WIF to SigningKey
# --------------------------
def wif_to_signing_key(wif):
    decoded = base58.b58decode_check(wif)
    if len(decoded) == 34:
        priv_key_bytes = decoded[1:]
        if len(priv_key_bytes) == 33 and priv_key_bytes[-1] == 0x01:
            priv_key_bytes = priv_key_bytes[:-1]
    elif len(decoded) >= 78:
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
    return n.to_bytes(length, byteorder='little')

def varint(n):
    if n < 0xfd:
        return n.to_bytes(1, byteorder='little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, byteorder='little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, byteorder='little')
    else:
        return b'\xff' + n.to_bytes(8, byteorder='little')

def address_to_pubkey_hash(address):
    decoded = base58.b58decode_check(address)
    return decoded[1:]

def p2pkh_script(pubkey_hash):
    return b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

def create_signed_transaction(utxo, recipient_address, amount, fee, change_address, priv_key_wif):
    total_in = utxo["value"]
    change = total_in - amount - fee
    if change < 0:
        return None

    version = int_to_little_endian(1, 4)
    locktime = int_to_little_endian(0, 4)
    
    txid = bytes.fromhex(utxo["tx_hash"])[::-1]
    vout = int_to_little_endian(utxo["tx_output_n"], 4)
    sequence = bytes.fromhex("ffffffff")
    
    script_pubkey = bytes.fromhex(utxo["script"])
    script_length = varint(len(script_pubkey))
    txin_for_sign = txid + vout + script_length + script_pubkey + sequence

    recipient_pubkey_hash = address_to_pubkey_hash(recipient_address)
    recipient_script = p2pkh_script(recipient_pubkey_hash)
    recipient_value = int_to_little_endian(amount, 8)
    recipient_script_length = varint(len(recipient_script))
    txout_recipient = recipient_value + recipient_script_length + recipient_script

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

    pre_tx = version + txin_count + txin_for_sign + txout_count + txout + locktime
    hash_type = int_to_little_endian(1, 4)
    pre_tx_for_sign = pre_tx + hash_type

    sighash = hashlib.sha256(hashlib.sha256(pre_tx_for_sign).digest()).digest()

    signing_key = wif_to_signing_key(priv_key_wif)
    signature = signing_key.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der) + b'\x01'

    verifying_key = signing_key.get_verifying_key()
    pubkey = verifying_key.to_string("compressed")
    script_sig = (len(signature).to_bytes(1, byteorder='little') + signature +
                  len(pubkey).to_bytes(1, byteorder='little') + pubkey)
    script_sig_length = varint(len(script_sig))

    txin_final = txid + vout + script_sig_length + script_sig + sequence
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
    pattern = r"^[^@]+@[^@]+\.[^@]+$"
    return re.match(pattern, address) is not None

# Registration Route: Generates wallet, secret code, and renders a success page.
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not is_valid_email(username):
            flash('Username must be a valid email address!', 'error')
            return redirect(url_for('register'))
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        litecoin_address, private_key_wif = create_wallet(wallet_name="wallet_" + username)
        secret_code = generate_secret_code(12)
        new_user = User(
            username=username,
            password=password,
            litecoin_address=litecoin_address,
            private_key=private_key_wif,
            secret_code=secret_code
        )
        db.session.add(new_user)
        db.session.commit()
        return render_template('register_success.html', secret_code=secret_code)
    return render_template('register.html')

# Check Balance Route – now explicitly given the endpoint "wallet_balance"
@app.route('/check_balance', methods=['GET', 'POST'], endpoint="wallet_balance")
def check_balance():
    address_to_check = request.form.get('address')
    if not address_to_check and 'user_id' in session:
        user = User.query.get(session['user_id'])
        address_to_check = user.litecoin_address
    if not address_to_check:
        return render_template('check_balance.html', error="Please enter a Litecoin address.")
    if not is_valid_ltc_address(address_to_check):
        return render_template('check_balance.html', error="Litecoin address is incorrect!", address=address_to_check)
    url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address_to_check}/balance"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            balance_ltc = data.get('final_balance', 0) / 1e8
            unconfirmed_ltc = data.get('unconfirmed_balance', 0) / 1e8
            rate_url = "https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=inr"
            rate_response = requests.get(rate_url)
            inr_rate = rate_response.json().get('litecoin', {}).get('inr', 0) if rate_response.status_code == 200 else 0
            return render_template('check_balance.html', 
                                   balance=balance_ltc,
                                   unconfirmed_balance=unconfirmed_ltc,
                                   balance_inr=balance_ltc * inr_rate,
                                   unconfirmed_inr=unconfirmed_ltc * inr_rate,
                                   address=address_to_check)
        else:
            return render_template('check_balance.html', error="Error fetching balance", address=address_to_check)
    except Exception as e:
        return render_template('check_balance.html', error=str(e), address=address_to_check)

# Login Route with secret code and 2FA check
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        secret_code_input = request.form['secret_code']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password and user.secret_code == secret_code_input:
            if user.totp_secret:
                session['pending_2fa_user_id'] = user.id
                return redirect(url_for('two_factor_auth'))
            else:
                session['user_id'] = user.id
                return redirect(url_for('index'))
        else:
            flash("Invalid credentials or secret code, please try again.", "error")
    return render_template('login.html')

# Two-Factor Authentication Verification Route
@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    pending_user_id = session.get('pending_2fa_user_id')
    if not pending_user_id:
        return redirect(url_for('login'))
    user = User.query.get(pending_user_id)
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_code):
            session.pop('pending_2fa_user_id', None)
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash("Invalid 2FA code, please try again.", "error")
            # Instead of redirecting, re-render the two_factor_auth page so the flash message appears here.
            return render_template('two_factor_auth.html')
    return render_template('two_factor_auth.html')

# Enable 2FA Route
@app.route('/enable_2fa', methods=['GET', 'POST'])
def enable_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
        return redirect(url_for('show_qr_code'))
    return render_template('enable_2fa.html')

# Show QR Code Route for 2FA
@app.route('/show_qr_code')
def show_qr_code():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.totp_secret:
        flash('2FA is not enabled for your account.', 'error')
        return redirect(url_for('enable_2fa'))
    issuer_name = "BharatVault"
    totp_uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.username, issuer_name=issuer_name)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return render_template('show_qr_code.html', qr_code=img_str)

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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.litecoin_address:
        flash("No wallet found. Please create one.", "error")
        return redirect(url_for("create_wallet_route"))
    if request.method == 'POST':
        recipient_address = request.form.get('recipient_address')
        amount_ltc = request.form.get('amount')
        if not recipient_address or not amount_ltc:
            flash("Enter recipient address and amount.", "error")
            return redirect(url_for("send_litecoin"))
        try:
            amount_satoshis = int(Decimal(amount_ltc) * 100_000_000)
        except Exception as e:
            flash("Invalid amount.", "error")
            return redirect(url_for("send_litecoin"))
        fee_satoshis = 5000
        utxo_url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{user.litecoin_address}?unspentOnly=true&includeScript=true"
        utxo_resp = requests.get(utxo_url)
        if utxo_resp.status_code != 200:
            error_msg = "Error fetching UTXOs: " + utxo_resp.text
            return render_template("transaction_failure.html", error=error_msg)
        utxo_data = utxo_resp.json()
        if "txrefs" not in utxo_data or len(utxo_data["txrefs"]) == 0:
            error_msg = "No UTXOs available."
            return render_template("transaction_failure.html", error=error_msg)
        selected_utxo = None
        for utxo in utxo_data["txrefs"]:
            if utxo["value"] >= amount_satoshis + fee_satoshis:
                selected_utxo = utxo
                break
        if selected_utxo is None:
            error_msg = "No UTXO with sufficient funds."
            return render_template("transaction_failure.html", error=error_msg)
        raw_tx = create_signed_transaction(
            selected_utxo,
            recipient_address,
            amount_satoshis,
            fee_satoshis,
            user.litecoin_address,
            user.private_key
        )
        if raw_tx is None:
            error_msg = "Failed to create raw transaction."
            return render_template("transaction_failure.html", error=error_msg)
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
    txid = request.args.get('txid')
    return render_template('transaction_successful.html', txid=txid)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    address = user.litecoin_address
    history_url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}?limit=50"
    try:
        response = requests.get(history_url)
        if response.status_code == 200:
            data = response.json()
            txrefs = data.get("txrefs", [])
            unconfirmed_txrefs = data.get("unconfirmed_txrefs", [])
            transactions = txrefs + unconfirmed_txrefs
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
