# 🪙 Bharat Vault

> A live, self-custodial Litecoin wallet — built from scratch, deployed on the web, and officially copyrighted under the Government of India.

**[🌐 Live Demo](https://bharat-vault.fly.dev)** &nbsp;·&nbsp; **[📂 GitHub](https://github.com/swayamrthakur)** &nbsp;·&nbsp; ![License](https://img.shields.io/badge/Copyright-GOI%20SW--2025021335-blue)

---

## What is Bharat Vault?

Bharat Vault is a non-custodial Litecoin wallet that lets users generate wallets, send and receive LTC, and track balances — all without handing over private keys to a third party. Every critical operation, from key generation to transaction signing, happens on the server you control.

Built entirely in Python and Flask, deployed on Fly.io, and registered under the **Copyright Act, 1957, Government of India** (Certificate No. SW-2025021335) — making it one of the few student-built projects in India with official IP protection.

---

## Features

- **Wallet Generation** — Cryptographically secure key pair generation for Litecoin addresses
- **Balance Tracking** — Real-time balance lookup via the Litecoin network
- **Transaction Validation** — Send and receive LTC with proper UTXO handling
- **Cryptographic Key Management** — Private keys handled securely end-to-end
- **REST API Backend** — Clean Flask API powering all wallet operations
- **Live Deployment** — Publicly accessible at `bharat-vault.fly.dev`

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Deployment | Fly.io |
| Frontend | HTML, CSS, JavaScript |
| Crypto | Litecoin protocol, cryptographic key primitives |

---

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/swayamrthakur/bharat-vault.git
cd bharat-vault

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run Locally

```bash
flask run
```

The app will be available at `http://localhost:5000`.

---

## Project Structure

```
bharat-vault/
├── app.py               # Flask app entry point
├── wallet/
│   ├── keygen.py        # Key pair generation
│   ├── transactions.py  # Transaction building & validation
│   └── balance.py       # Balance lookup
├── templates/           # HTML frontend
├── static/              # CSS & JS assets
├── database.db          # SQLite database
└── requirements.txt
```

---

## How It Works

1. **Wallet creation** — Generates a private/public key pair using cryptographic primitives specific to the Litecoin protocol, derives a valid LTC address.
2. **Balance tracking** — Queries the Litecoin network to fetch UTXOs associated with an address.
3. **Transactions** — Constructs, signs, and broadcasts transactions to the Litecoin network with proper input/output validation.

---

## Copyright

This project is officially registered under the **Copyright Act, 1957, Government of India**.
**Certificate No.:** SW-2025021335 | **Year:** 2025

Co-authored and co-owned by 5 contributors.

---

## Authors

- **Swayam Thakur** — [LinkedIn](https://linkedin.com/in/swayam-thakur) · [GitHub](https://github.com/swayamrthakur)
- 4 other co-authors

---

## Disclaimer

Bharat Vault is a project built for learning and demonstration purposes. Use it responsibly. Never store large amounts of cryptocurrency in any wallet you do not fully understand or control.
