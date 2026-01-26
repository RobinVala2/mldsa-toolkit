import argparse
from pathlib import Path
import shutil
import sys

def main():
    parser = argparse.ArgumentParser(description="Create folder setup for timing analysis")
    parser.add_argument("-o", "--output-dir", type=str, help="Output directory")
    args = parser.parse_args()

    if args.output_dir is None:
        print("Error: Output directory is required")
        sys.exit(1)

    output_dir = args.output_dir
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Creating folders for CSV files")

    properties = (
            'hw-rho-prime',
            'bit-size-rho-prime',

            'hw-y',
            'bit-size-y',
            'ntt-hw-y',
            'ntt-bit-size-y',

            'hw-w',
            'bit-size-w',
            'ntt-hw-w',
            'ntt-bit-size-w',

            'hw-c-s1',
            'bit-size-c-s1',
            'ntt-hw-c-s1',
            'ntt-bit-size-c-s1',

            'hw-c-s2',
            'bit-size-c-s2',
            'ntt-hw-c-s2',
            'ntt-bit-size-c-s2',

            'hw-w-cs2-low-bits',
            'bit-size-w-cs2-low-bits',

            'inf-norm-z',
            'inf-norm-y',
            'inf-norm-w0',
        )

    for property in properties:
        folder_name = f"{property}"
        folder_path = output_dir / folder_name
        folder_path.mkdir(parents=True, exist_ok=True)
        print(f"Created folder: {folder_path}")

    for property in properties:
        csv_file = f"measurements-{property}.csv"
        csv_file_path = output_dir / csv_file
        new_csv_file_path = output_dir / property / "measurements.csv"
        shutil.copy(csv_file_path, new_csv_file_path)
        print(f"Copied CSV file: {csv_file_path} to {new_csv_file_path}")

if __name__ == "__main__":
    main()