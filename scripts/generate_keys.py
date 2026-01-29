"""
Usage:
    python generate_keys.py [44|65|87] --count N [--output-dir DIR]
"""

import argparse
import subprocess
from pathlib import Path

SCHEMES = {
    "44": "ML-DSA-44",
    "65": "ML-DSA-65",
    "87": "ML-DSA-87",
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate multiple ML-DSA keys for timing analysis"
    )
    parser.add_argument(
        "param", 
        choices=["44", "65", "87"],
        help="ML-DSA parameter set (44, 65, or 87)"
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=25,
        help="Number of keys to generate (default: 25)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output directory (default: mldsa-{param}-keys/)"
    )
    
    return parser.parse_args()

def generate_keys(scheme_name, count, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    legend_lines = ["key_id,key_dir"]
    
    for i in range(count):
        key_dir = output_dir / f"key_{i:02d}"
        key_dir.mkdir(parents=True, exist_ok=True)
        
        sk_pem = key_dir / "sk.pem"
        pk_pem = key_dir / "pk.pem"
        
        print(f"Generating key {i+1}/{count}.", end=" ", flush=True)
        
        # private key
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", scheme_name, "-out", str(sk_pem)],
            check=True,
            capture_output=True
        )
        
        # public key
        subprocess.run(
            ["openssl", "pkey", "-in", str(sk_pem), "-pubout", "-out", str(pk_pem)],
            check=True,
            capture_output=True
        )
        
        print(f"done")
        
        legend_lines.append(f"{i},key_{i:02d}")
    
    (output_dir / "legend.csv").write_text("\n".join(legend_lines) + "\n")
    
    print()
    print(f"Generated {count} keys in {output_dir}/")


def main():

    args = parse_args()
    
    if args.output is None:
        args.output = f"mldsa-{args.param}-keys"
    
    scheme_name = SCHEMES[args.param]
    
    print(f"ML-DSA-{args.param} Key Generation")
    print(f"Number of keys: {args.count}")
    print(f"Output directory: {args.output}")
    print()
    
    generate_keys(scheme_name, args.count, args.output)
    
    print()
    print("Key generation complete!")


if __name__ == "__main__":
    main()
