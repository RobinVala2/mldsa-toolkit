"""
Generates ML-DSA keys and random messages for signing.
"""

import argparse
import os
import subprocess
from pathlib import Path

BASE = Path(".")
DATA_BIN = BASE / "data.bin"

SCHEMES = {
    "mldsa-44": "ML-DSA-44",
    "mldsa-65": "ML-DSA-65",
    "mldsa-87": "ML-DSA-87"
}

MSG_SIZE = 32
CHUNK_SIZE = 1024 * 16

def generate_keys(name: str):
    print(f"Generating keys for {name}")
    outdir = Path(name) / "keys"
    outdir.mkdir(parents=True, exist_ok=True)
    
    pk_path = outdir / "pk.pem"
    sk_path = outdir / "sk.pem"
    
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", SCHEMES[name], "-out", sk_path, "-outform", "PEM"],
        check=True
    )

    subprocess.run(
        ["openssl", "pkey", "-in", sk_path, "-pubout", "-out", pk_path, "-outform", "PEM"],
        check=True
    )

    print("Done.")

def generate_messages(count: int):
    total_bytes = count * MSG_SIZE
    print(f"Generating {count} messages")

    with open(DATA_BIN, "wb") as f:
        left = total_bytes
        while left > 0:
            n = min(CHUNK_SIZE, left)
            f.write(os.urandom(n))
            left -= n 
    
    print(f"Created {DATA_BIN} with size {DATA_BIN.stat().st_size} bytes")

def parse_args():
    parser = argparse.ArgumentParser(description="Generate ML-DSA keys and random messages for signing")
    parser.add_argument(
        "--keys", action="store_true", help="Generate ML-DSA keys"
    )
    parser.add_argument(
        "--messages", action="store_true", help="Generate random messages"
    )
    parser.add_argument(
        "--scheme", type=str, default="all", 
        choices=["all", "mldsa-44", "mldsa-65", "mldsa-87"], 
        help="Scheme to generate keys for"
    )
    parser.add_argument(
        "--count", type=int, default=10000,
        help="Number of messages to generate"
    )

    args = parser.parse_args()

    if not args.keys and not args.messages:
        args.keys = True
        args.messages = True
    
    return args

def main():
    args = parse_args()

    if args.keys:
        if args.scheme == "all":
            print("Starting key generation for all schemes")
            for name in SCHEMES:
                generate_keys(name)
        else:
            print(f"Starting key generation for {args.scheme}")
            generate_keys(args.scheme)
    
    if args.messages:
        print(f"Starting message generation")
        generate_messages(args.count)
        print("Message generation done")

if __name__ == "__main__":
    main()