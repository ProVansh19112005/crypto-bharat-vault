import os
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session  # FIXED: Import Session
import bitcoin
import re

app = Flask(__name__)

# **Fix 1: Configure Database**
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# **Fix 2: Configure Session**
app.config['SESSION_TYPE'] = 'filesystem'  # Stores session data locally
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret-key")

# **Fix 3: Initialize Session**
Session(app)  # FIXED: Session is now imported and initialized correctly

# **Fix 4: Initialize Database**
db = SQLAlchemy(app)



# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    litecoin_address = db.Column(db.String(100), unique=True, nullable=False)

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('intro'))  # Redirect to login if not logged in
    return redirect(url_for('index'))  # Redirect to the index page if logged in

@app.route('/intro')
def intro():
    return render_template('intro.html')


from bitcoinlib.wallets import Wallet

import uuid
from bitcoinlib.wallets import Wallet

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Generate a unique wallet name using UUID
        wallet_name = f"LitecoinWallet_{uuid.uuid4().hex}"

        try:
            # Create a new wallet with the unique name
            wallet = Wallet.create(wallet_name, network='litecoin')
            
            # Generate the Litecoin address
            litecoin_address = wallet.get_key().address
            
            # Save user details and the generated Litecoin address
            new_user = User(username=username, password=password, litecoin_address=litecoin_address)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))  # Redirect to login after successful registration

        except WalletError as e:
            # Handle wallet creation error
            print(f"Error creating wallet: {e}")
            return render_template('register.html', error="Error creating wallet")

    return render_template('register.html')



@app.route('/check_balance', methods=['GET', 'POST'])
def check_balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user = User.query.get(session['user_id'])  # Get the current logged-in user
    litecoin_address = user.litecoin_address  # Get the user's Litecoin address

    # If the address is not present, show an error
    if not litecoin_address:
        return render_template('error.html', message="No Litecoin address found.")

    # If the user submitted a different address via the form
    address_to_check = request.form.get('address', litecoin_address)  # Default to user's address

    # Simple validation: Check if it starts with "ltc" and has exactly 43 characters
    if not address_to_check.startswith("ltc") or len(address_to_check) != 43:
        return render_template('check_balance.html', error="Invalid Litecoin address!", address=address_to_check)

    # Fetch the balance for the Litecoin address
    url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address_to_check}/balance"

    try:
        response = requests.get(url)
        print(f"API Status Code: {response.status_code}")  # Log status code
        print(f"API Response: {response.text}")  # Log response text for debugging

        if response.status_code == 200:
            data = response.json()
            balance = data.get('final_balance', 0) / 1e8  # Convert to LTC
            unconfirmed_balance = data.get('unconfirmed_balance', 0) / 1e8  # Unconfirmed balance

            return render_template('check_balance.html', balance=balance, 
                                   unconfirmed_balance=unconfirmed_balance, address=address_to_check)
        else:
            error_message = "Error fetching balance. Please try again."
            return render_template('check_balance.html', error=error_message, address=address_to_check)
    except Exception as e:
        print(f"Error: {str(e)}")  # Log the exception
        return render_template('check_balance.html', error=f"An error occurred: {str(e)}", address=address_to_check)

    return render_template('check_balance.html')


    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['user_id'] = user.id  # Store user id in session
            return redirect(url_for('index'))  # Redirect to index after successful login
        else:
            return "Invalid credentials, please try again."

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user from the session
    return render_template('logout.html')  # Render the logout success page


@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/create_wallet')
def create_wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    # Check if the user already has a Litecoin address
    if user.litecoin_address:
        return render_template('wallet_created.html', user=user)  # Wallet already created

    # Logic to create wallet if none exists
    litecoin_address = generate_litecoin_address()  # Use your function to generate a valid address

    # Update the user's Litecoin address
    user.litecoin_address = litecoin_address
    db.session.commit()

    print(f"DEBUG: Created wallet for {user.username} with address {litecoin_address}")

    return render_template('wallet_created.html', user=user)


@app.route('/send', methods=['GET', 'POST'])
def send_litecoin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        recipient_address = request.form.get('recipient_address')
        amount = request.form.get('amount')

        # Your logic for sending Litecoin

        # Assuming successful transaction
        print(f"Sent {amount} Litecoin to {recipient_address}")
        
        return redirect(url_for('transaction_successful'))  # Or any route you prefer
    
    return render_template('send_litecoin.html', user=user)


from bitcoinlib.wallets import Wallet

def generate_litecoin_address():
    # Create a new wallet for Litecoin (can specify network as 'litecoin')
    wallet = Wallet.create('LitecoinWallet')  
    
    # Get the Litecoin address from the generated wallet
    litecoin_address = wallet.get_key().address
    return litecoin_address


@app.route('/check_balance', methods=['GET'])
def wallet_balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    litecoin_address = user.litecoin_address

    print(f"DEBUG: Checking balance for address {litecoin_address}")  # Debugging line

    try:
        balance = get_litecoin_balance(litecoin_address)  # Call the new API
        print(f"DEBUG: Balance for {litecoin_address} is {balance}")  # Debugging line
        return render_template('wallet_balance.html', balance=balance, litecoin_address=litecoin_address)
    except Exception as e:
        print(f"DEBUG: Error fetching balance: {str(e)}")  # Debugging line
        return render_template('error.html', message="Error fetching balance.")


import requests

import requests

def is_valid_litecoin_address(address):
    """Check if the Litecoin address is valid based on length and prefix."""
    return isinstance(address, str) and len(address) == 43 and address.startswith("ltc")

def get_litecoin_balance(address):
    if not is_valid_litecoin_address(address):
        raise ValueError("Invalid Litecoin address. It must be 43 characters long and start with 'ltc'.")

    url = f'https://sochain.com/api/v2/get_address_balance/LTC/{address}'

    try:
        response = requests.get(url)
        print(f"DEBUG: API Response: {response.text}")  # Log the raw response text

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'confirmed_balance' in data["data"]:
                return data["data"]["confirmed_balance"]  # The confirmed balance in LTC
            else:
                raise Exception("Address not found or invalid.")
        else:
            raise Exception(f"Error fetching balance. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error fetching balance: {e}")
        raise


if __name__ == '__main__':
    app.run(debug=True)

