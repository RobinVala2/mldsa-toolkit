# ML-DSA Side-Channel Analysis Toolkit

A toolkit for performing side-channel timing analysis on ML-DSA (Dilithium) signature implementations. This toolkit extracts intermediate values from ML-DSA signatures and correlates them with timing measurements to identify potential side-channel vulnerabilities.

## Features

The toolkit extracts the following features from ML-DSA signatures:

- **rho-prime**: Private random seed (Hamming weight, bit size)
- **y**: Secret polynomial vector in coefficient and NTT domains (Hamming weight, bit size)
- **w**: Commitment polynomial vector (Hamming weight, bit size)
- **c·s1**: Product used in signer's response computation (Hamming weight, bit size, NTT domain)
- **c·s2**: Product used in r0 computation (Hamming weight, bit size, NTT domain)
- **w-cs2-low-bits**: Low bits of (w - c·s2) (Hamming weight, bit size)


## Setup

Run the setup script to automatically download dependencies and configure the environment:

```bash
./setup.sh
```

This script will:
1. Download `tlsfuzzer` from GitHub (if not already present)
2. Copy `extract.py` to `tlsfuzzer/tlsfuzzer/extract.py`
3. Create a Python virtual environment (`venv`)
4. Install all required dependencies:
   - Base tlsfuzzer dependencies
   - Timing analysis dependencies
   - ML-DSA specific dependencies (`dilithium-py`)

After setup, activate the virtual environment:
```bash
source venv/bin/activate
```

## Usage

### Step 1: Generate Test Data

Generate random messages to sign:
```bash
python generate_data.py
```
This creates `data.bin` with random 32-byte messages.

### Step 2: Collect Timing Data

Measure ML-DSA signing times and collect signatures:
```bash
python dilithium-py/timing.py --scheme mldsa-44 -i data.bin -o output-mldsa-44
```

This will:
- Generate a key pair (if not present)
- Sign all messages in `data.bin`
- Save signatures to `output-mldsa-44/results/signatures.bin`
- Save timing measurements to `output-mldsa-44/results/timings.bin`
- Save the private key to `output-mldsa-44/keys/sk.pem`

Supported schemes: `mldsa-44`, `mldsa-65`, `mldsa-87`

### Step 3: Extract Features

Extract intermediate values and correlate with timing data:
```bash
PYTHONPATH=./tlsfuzzer python extract.py \
  --ml-dsa-keys output-mldsa-44/keys/sk.pem \
  --ml-dsa-sigs output-mldsa-44/results/signatures.bin \
  --ml-dsa-messages data.bin \
  --raw-times output-mldsa-44/results/timings.bin \
  --binary 8 \
  -o output-mldsa-44 \
  --verbose
```

**Parameters:**
- `--ml-dsa-keys`: Path to ML-DSA private key (PEM format)
- `--ml-dsa-sigs`: Binary file containing signatures
- `--ml-dsa-messages`: Binary file containing messages (32 bytes each)
- `--raw-times`: Binary file containing timing measurements (8 bytes each, little-endian)
- `--binary 8`: Timing file format (8 bytes per measurement)
- `-o`: Output directory for extracted measurements
- `--verbose`: Enable verbose output

### Step 4: Analyze Results

The extraction process creates CSV files for each extracted feature:
- `measurements-hw-rho-prime.csv`
- `measurements-bit-size-rho-prime.csv`
- `measurements-hw-y.csv`
- `measurements-bit-size-y.csv`
- `measurements-ntt-hw-y.csv`
- `measurements-ntt-bit-size-y.csv`
- ... and more

Each CSV file contains:
- Row number (tuple identifier)
- Feature value
- Timing measurement (in seconds)

You can then use statistical analysis tools (`tlsfuzzer/tlsfuzzer/analysis.py`) to analyze correlations.

## Example Workflow

Complete example for ML-DSA-44:

```bash
# 1. Generate test data
python generate_data.py

# 2. Collect timing data
python dilithium-py/timing.py --scheme mldsa-44 -i data.bin 

# 3. Extract features
PYTHONPATH=./tlsfuzzer python extract.py \
  --ml-dsa-keys mldsa-44/keys/sk.pem \
  --ml-dsa-sigs mldsa-44/results/signatures.bin \
  --ml-dsa-messages data.bin \
  --raw-times mldsa-44/results/timings.bin \
  --binary 8 \
  -o output-mldsa-44 \
  --verbose

# 4. Analyze a specific feature (example: bit-size-y)
# Copy measurement file to analysis directory
cp output-mldsa-44/measurements-bit-size-y.csv output-mldsa-44/bit-size-y/measurements.csv

# Run statistical analysis
PYTHONPATH=./tlsfuzzer python tlsfuzzer/tlsfuzzer/analysis.py \
    -o output-mldsa-44/bit-size-y/ \
    --verbose \
    --summary-only \
    --Hamming-weight \
    --minimal-analysis \
    --no-sign-test 

```

