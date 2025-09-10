# SHA-256 Hasher (`hash_generator.py`)

This script computes **SHA-256 hashes** for strings, files, or stdin input.

## Usage

### Hash a string
```bash
python hash_generator.py --string "hello world"
```

### Hash a file
```bash
python hash_generator.py --file path/to/file.txt
```

### Hash from stdin
```bash
echo "hello world" | python hash_generator.py
```

The script prints the **64-character SHA-256 digest** in hexadecimal format.

---
---
---

# Caesar Cipher Tool (`caesar.py`)

This script encrypts or decrypts text using **Caesar cipher** with a key (shift value).

## Usage

### Encrypt text
```bash
python caesar.py encrypt --key 3 --text "Caesar cipher tool works."
# Output: Fdhvdu flskhu wrrl zrunv.
```

---
---
---

# Digital Signature Demo (`sign_verify.sh`)

This script uses **OpenSSL** to generate keys, sign messages, and verify signatures.


## Usage

### Initialize keys (ECDSA P-256 by default)
```bash
./sign_verify.sh init
```

### Sign a message file
```bash
echo "important message" > message.txt
./sign_verify.sh sign message.txt
```

### Verify the signature
```bash
./sign_verify.sh verify message.txt signature.bin
```

### Optional: Use RSA instead of ECDSA
```bash
ALG=rsa ./sign_verify.sh init
./sign_verify.sh sign message.txt
./sign_verify.sh verify message.txt signature.bin
```

### Clean up files
```bash
./sign_verify.sh clean
```

---
