"""
hash_generator.py computes SHA-256 hashes for strings or files.

see README file
"""

import argparse
import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB

def sha256_hex_from_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Compute SHA-256 for strings or files.")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--string", "-s", help="Literal string to hash.")
    g.add_argument("--file", "-f", type=Path, help="Path to file to hash.")
    args = parser.parse_args()

    if args.string:
        digest = hashlib.sha256(args.string.encode('utf-8')).hexdigest()
        print(digest)
    elif args.file:
        if not args.file.exists() or not args.file.is_file():
            print(f"Error: file not found: {args.file}")
            return
        digest = sha256_hex_from_file(args.file)
        print(digest)

if __name__ == "__main__":
    main()

