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
        return redirect(url_for('login'))  # Redirect to login if not logged in
    return redirect(url_for('index'))  # Redirect to the index page if logged in

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # You can add hashing here for security
        
        # Generate a new Litecoin address
        private_key = bitcoin.random_key()
        public_key = bitcoin.privtopub(private_key)
        litecoin_address = bitcoin.pubtoaddr(public_key)

        # Save the new user in the database
        new_user = User(username=username, password=password, litecoin_address=litecoin_address)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))  # Redirect to login after successful registration
    return render_template('register.html')

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


def generate_litecoin_address():
    private_key = bitcoin.random_key()
    public_key = bitcoin.privtopub(private_key)
    litecoin_address = bitcoin.pubtoaddr(public_key, network='litecoin')

    # Validate Litecoin address format using regex
    litecoin_regex = re.compile(r'^[LM][A-Za-z0-9]{26,35}$')
    
    if not litecoin_regex.match(litecoin_address):
        raise ValueError(f"Invalid Litecoin address generated: {litecoin_address}")
    
    # Check the length of the address
    if len(litecoin_address) < 26 or len(litecoin_address) > 35:
        raise ValueError(f"Invalid Litecoin address length: {litecoin_address}")

    # Check if the address starts with L or M
    if not (litecoin_address.startswith('L') or litecoin_address.startswith('M')):
        raise ValueError(f"Invalid Litecoin address prefix: {litecoin_address}")
    
    # Optionally check if the address already exists in the database (ensure uniqueness)
    existing_address = User.query.filter_by(litecoin_address=litecoin_address).first()
    if existing_address:
        raise ValueError(f"Litecoin address already exists in the database: {litecoin_address}")

    return litecoin_address






@app.route('/check_balance', methods=['GET'])
def wallet_balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    litecoin_address = user.litecoin_address

    print(f"DEBUG: Checking balance for address {litecoin_address}")  # Add this line

    try:
        balance = get_litecoin_balance(litecoin_address)  # Call the new API
        print(f"DEBUG: Balance for {litecoin_address} is {balance}")  # Add this line
        return render_template('wallet_balance.html', balance=balance, litecoin_address=litecoin_address)
    except Exception as e:
        print(f"DEBUG: Error fetching balance: {str(e)}")  # Add this line for more insight
        return render_template('error.html', message="Error fetching balance.")





import requests

def get_litecoin_balance(address):
    url = f"https://api.blockchair.com/ltc/testnet/dashboards/address/{address}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        return data['data'][address]['address']['balance'] / 1e8  # Convert from satoshis to LTC
    else:
        print(f"Error fetching balance: {response.text}")
        raise Exception(f"Error fetching balance: {response.text}")





if __name__ == '__main__':
    app.run(debug=True)

