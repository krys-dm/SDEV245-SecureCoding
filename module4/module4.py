#!/usr/bin/env python3
"""
this app demonstrates:
- SHA-256 hashing 
- Password based AES-256-GCM symmetric encryption/decryption
- Checks integrity by comparing pre-encryption SHA-256 after decryption

requires:
  pip install cryptography
"""

import argparse, json, getpass, hashlib, base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(plaintext: bytes, password: str) -> dict:
    salt = secrets.token_bytes(16)   
    key  = derive_key(password, salt)
    nonce = secrets.token_bytes(12)  
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "v": 1,
        "scheme": "AES-256-GCM",
        "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": 200_000},
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
        "sha256": sha256_hex(plaintext),
    }

def decrypt_bundle(bundle: dict, password: str) -> tuple[bytes, bool]:
    salt = b64d(bundle["salt"])
    nonce = b64d(bundle["nonce"])
    ct = b64d(bundle["ciphertext"])
    iters = int(bundle.get("kdf", {}).get("iterations", 200_000))
    key = derive_key(password, salt, iterations=iters)
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt, (sha256_hex(pt) == bundle["sha256"])

def main():
    ap = argparse.ArgumentParser(description="Minimal AES-GCM + SHA-256 demo")
    ap.add_argument("--infile", required=True, help="Input file (plaintext or JSON bundle)")
    ap.add_argument("--out", required=True, help="Output file (JSON when encrypting; plaintext when decrypting)")
    ap.add_argument("--decrypt", action="store_true", help="Decrypt instead of encrypt")
    args = ap.parse_args()

    password = getpass.getpass("Password: ")

    if not args.decrypt:
        # Encrypt path
        data = Path(args.infile).read_bytes()
        bundle = encrypt_file(data, password)
        Path(args.out).write_text(json.dumps(bundle, indent=2))
        print(f"Encrypted → {args.out}")
        print(f"SHA-256(plaintext): {bundle['sha256']}")
    else:
        # Decrypt path
        bundle = json.loads(Path(args.infile).read_text())
        pt, ok = decrypt_bundle(bundle, password)
        Path(args.out).write_bytes(pt)
        print(f"Decrypted → {args.out}")
        print(f"Integrity check: {'OK' if ok else 'FAILED'}")

if __name__ == "__main__":
    main()
