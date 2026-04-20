# Bharat Vault

A non-custodial Litecoin wallet — built from scratch and deployed on the web.

[Live Demo](https://bharat-vault.fly.dev)

---

## Overview

Bharat Vault is a self-custodial Litecoin wallet that lets users generate wallets, send and receive LTC, and track balances without handing over private keys to a third party. Every critical operation — from key generation to transaction signing — happens on the server you control.

Registered under the Copyright Act, 1957, Government of India (Certificate No. SW-2025021335).

---

## Features

- Cryptographically secure wallet generation
- Real-time balance tracking via the Litecoin network
- Transaction building, signing, and broadcasting with UTXO handling
- Private key management end-to-end
- REST API backend
- Live deployment on Fly.io

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Deployment | Fly.io |
| Frontend | HTML, CSS, JavaScript |

---

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
git clone https://github.com/swayamrthakur/bharat-vault.git
cd bharat-vault

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Run

```bash
flask run
```

App runs at `http://localhost:5000`.

---

## Project Structure

```
bharat-vault/
├── app.py
├── wallet/
│   ├── keygen.py
│   ├── transactions.py
│   └── balance.py
├── templates/
├── static/
├── database.db
└── requirements.txt
```

---

## How It Works

1. **Wallet creation** — Generates a private/public key pair and derives a valid Litecoin address.
2. **Balance tracking** — Fetches UTXOs associated with an address from the Litecoin network.
3. **Transactions** — Constructs, signs, and broadcasts transactions with proper input/output validation.

---

## Copyright

Registered under the Copyright Act, 1957, Government of India.
Certificate No. SW-2025021335 (2025).

---

## Disclaimer

Bharat Vault is built for learning and demonstration purposes. Never store significant amounts of cryptocurrency in any wallet you do not fully understand or control.
