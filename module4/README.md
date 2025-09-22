A python script for encrypting and decrypting files using a password.  
It demonstrates the **CIA Triad** and basic cryptographic hygiene (salted key derivation, nonces, hashing).

---

## Install

Open a terminal in the folder containing `module4.py`, then run:

```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install cryptography
```

---
---

## How to Run

Ecrypt a file:

```bash
python module4.py --infile plain.txt --out secret.json
```

Decrypt a file:

```bash
python module4.py --infile secret.json --out recovered.txt --decrypt
```

---
---

## Examples

# Encrypt
python module4.py --infile plain.txt --out secret.json
# Password: ********

# Decrypt
python module4.py --infile secret.json --out recovered.txt --decrypt
# Password: ********
# Integrity check: OK
