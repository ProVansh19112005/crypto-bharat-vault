#!/usr/bin/env python3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
import requests
from bitcoinlib.wallets import Wallet
from wallet import create_wallet, get_balance  # our wallet.py functions

app = Flask(__name__)

# Configure Database
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
    private_key = db.Column(db.String(200), nullable=True)  # storing the wallet's private key (WIF)

# --------------------------
# Helper: Validate Litecoin Address
# --------------------------
def is_valid_ltc_address(address):
    """
    Basic validation for a Litecoin mainnet address.
    Accepts:
      - Legacy P2PKH/P2SH addresses that start with "L" or "M" and are 34 characters long.
      - Bech32 addresses that start with "ltc1" and have a reasonable length (typically 26 to 90 characters).
    """
    if (address.startswith("L") or address.startswith("M")) and len(address) == 34:
        return True
    if address.startswith("ltc1") and 26 <= len(address) <= 90:
        return True
    return False

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        # Create a new Litecoin wallet using our wallet module
        litecoin_address, private_key_wif = create_wallet(wallet_name="wallet_" + username)
        new_user = User(username=username, password=password,
                        litecoin_address=litecoin_address, private_key=private_key_wif)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful', 'success')
        print(f"DEBUG: Wallet generated for user {username} - Address = {litecoin_address}, Private Key = {private_key_wif}")
        return redirect(url_for('login'))
    return render_template('register.html')

# Check Balance Route (allows checking any address)
@app.route('/check_balance', methods=['GET', 'POST'], endpoint="wallet_balance")
def check_balance():
    # You can check any Litecoin address
    address_to_check = request.form.get('address')
    # If no address is provided, and the user is logged in, default to their wallet
    if not address_to_check and 'user_id' in session:
        user = User.query.get(session['user_id'])
        address_to_check = user.litecoin_address
    if not address_to_check:
        return render_template('check_balance.html', error="Please enter a Litecoin address.")
    # Validate the address
    if not is_valid_ltc_address(address_to_check):
        return render_template('check_balance.html', error="Invalid Litecoin address!", address=address_to_check)
    url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address_to_check}/balance"
    try:
        response = requests.get(url)
        print(f"API Status Code: {response.status_code}")
        print(f"API Response: {response.text}")
        if response.status_code == 200:
            data = response.json()
            balance_ltc = data.get('final_balance', 0) / 1e8
            unconfirmed_ltc = data.get('unconfirmed_balance', 0) / 1e8
            return render_template('check_balance.html', balance=balance_ltc,
                                   unconfirmed_balance=unconfirmed_ltc, address=address_to_check)
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
        flash("Wallet already exists.", "info")
        return render_template('wallet_created.html', user=user, private_key=user.private_key)
    litecoin_address, private_key_wif = create_wallet(wallet_name="wallet_" + user.username)
    user.litecoin_address = litecoin_address
    user.private_key = private_key_wif
    try:
        db.session.commit()
    except Exception as e:
        flash("Error saving wallet: " + str(e), "error")
    return render_template('wallet_created.html', user=user, private_key=user.private_key)

# /send Route using bitcoinlib for sending transactions on Litecoin mainnet
@app.route('/send', methods=['GET', 'POST'])
def send_litecoin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        recipient_address = request.form.get('recipient_address')
        amount_input = request.form.get('amount')
        try:
            amount_ltc = float(amount_input)
        except ValueError:
            flash("Invalid amount entered.", "error")
            return render_template('send_litecoin.html', user=user)
        fee = 0.0001  # Fee in LTC, adjust as needed
        wallet_name = "wallet_" + user.username
        try:
            from bitcoinlib.wallets import Wallet
            try:
                wallet = Wallet(wallet_name)
            except Exception:
                # Create the wallet if not exists (this imports the stored private key)
                wallet = Wallet.create(wallet_name, keys=user.private_key, network='litecoin', witness_type='legacy')
            tx = wallet.send_to(recipient_address, amount_ltc, fee=fee)
            flash(f"Transaction successful! TXID: {tx.txid}", "success")
            return redirect(url_for('transaction_successful'))
        except Exception as e:
            flash("Transaction failed: " + str(e), "error")
            return render_template('send_litecoin.html', user=user)
    return render_template('send_litecoin.html', user=user)

@app.route('/transaction_successful')
def transaction_successful():
    return render_template('transaction_successful.html')

if __name__ == '__main__':
    app.run(debug=True)
