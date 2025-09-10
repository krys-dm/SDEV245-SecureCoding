# SHA-256 Hasher (`hash_generator.py`)

This script computes **SHA-256 hashes** for strings, files, or stdin input.

---

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
