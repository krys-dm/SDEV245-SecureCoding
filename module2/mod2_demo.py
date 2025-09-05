#!/usr/bin/env python3
"""
Mod 2 login + RBAC + crypto demo.

What this script does:
- In-memory "login" with two users (admin, kate) and their roles.
- Role-based access control (only 'admin' can do admin-only actions).
- Symmetric encryption demo using Fernet.
- Asymmetric encryption demo using RSA-OAEP.
- Writes keys used, inputs, and outputs to 'report.txt'.

Requires:
    pip install cryptography
"""


# -------- Standard library imports --------
import base64  
import json    
from pathlib import Path 


# -------- Third-party cryptography --------
from cryptography.fernet import Fernet  # symmetric encryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding  
from cryptography.hazmat.primitives import serialization, hashes    


# -------- Database --------
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "kate":  {"password": "kate123",  "role": "user"},
}


# -------- Authentication: verifies username/password --------
def login(username, password):
    u = USERS.get(username)
    if not u:
        return None
    return {"username": username, "role": u["role"]} if u["password"] == password else None


# -------- Authorization (RBAC): check if user has a required role --------
def require_role(user, role):
    return bool(user and user.get("role") == role)


# -------- Generates a random key, Encrypts and decrypts a short message, Returns printable report --------
def symmetric_demo(message: str):
    key = Fernet.generate_key()   
    f = Fernet(key)             
    ct = f.encrypt(message.encode())  
    pt = f.decrypt(ct).decode()     
    return {
        "algorithm": "Fernet (symmetric)",
        "key_b64": key.decode(),                  
        "plaintext": message,                     
        "ciphertext_b64": ct.decode(),          
        "decrypted": pt                          
    }


# -------- Generates a demo --------
def asymmetric_demo(message: str):
    # Generate RSA private key (has the public key inside it)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize keys to PEM for report
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,           
        encryption_algorithm=serialization.NoEncryption()     
    ).decode()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  
    ).decode()

    # Encrypt using RSA-OAEP (secure padding) with SHA-256
    ct = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt with the private key
    pt = private_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

    return {
        "algorithm": "RSA-OAEP (asymmetric)",
        "public_key_pem": pub_pem,
        "private_key_pem": priv_pem,
        "plaintext": message,    
        "ciphertext_b64": base64.b64encode(ct).decode(),
        "decrypted": pt 
    }


# -------- Performs logins, Checks admin-only access, Writes everything to report.txt --------
def main():
    out_file = Path(__file__).with_name("report.txt")  # CHANGED HERE

    # Logins
    admin = login("admin", "admin123")
    kate  = login("kate",  "kate123")
    wrong = login("kate",  "wrong") 

    # RBAC checks
    admin_can = require_role(admin, "admin")
    kate_can  = require_role(kate,  "admin")

    # Crypto demos
    message = "Hello! This is the message!!"
    sym = symmetric_demo(message)
    asym = asymmetric_demo(message)

    # Write results to report.txt
    with out_file.open("w", encoding="utf-8") as f:
        f.write("=== REPORT OUTPUT ===\n\n")

        f.write("== Users (demo-only; plaintext in code) ==\n")
        f.write(json.dumps({"admin": {"role": "admin"}, "kate": {"role": "user"}}, indent=2))

        f.write("\n\n== Login Attempts ==\n")
        f.write(f"admin/admin123 -> {admin}\n")
        f.write(f"kate/kate123  -> {kate}\n")
        f.write(f"kate/nope     -> {wrong}\n\n")

        f.write("== RBAC Checks ==\n")
        f.write(f"admin can view admin panel: {admin_can}\n")
        f.write(f"kate  can view admin panel: {kate_can}\n\n")

        f.write("== Symmetric Encryption ==\n")
        f.write(json.dumps(sym, indent=2) + "\n\n")

        f.write("== Asymmetric Encryption ==\n")
        f.write(json.dumps(asym, indent=2) + "\n")

    print(f"[ok] wrote {out_file}")


if __name__ == "__main__":
    main()
