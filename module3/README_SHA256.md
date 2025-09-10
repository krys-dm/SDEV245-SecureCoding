# SHA-256 Hasher (`hash.py`)

This script computes **SHA-256 hashes** for strings, files, or stdin input.

## Usage

### Hash a string
```bash
python hash.py --string "hello world"
```

### Hash a file
```bash
python hash.py --file path/to/file.py
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
python caesar.py 
```

---
---
---

# Digital Signature Demo (`sign.sh`)

This script uses **OpenSSL** to generate keys, sign messages, and verify signatures.


## Usage

### Initialize keys (ECDSA P-256 by default)
```bash
chmod +x sign.sh
```
```bash
./sign.sh
```

### Clean up files
```bash
./sign.sh clean
```

---
