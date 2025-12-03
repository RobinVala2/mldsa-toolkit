# ML-DSA Side-Channel Analysis Toolkit

A toolkit for performing side-channel timing analysis on ML-DSA ignature implementations. This toolkit extracts intermediate values from ML-DSA signatures and correlates them with timing measurements to identify potential side-channel vulnerabilities.

## Example Usage

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
  --raw-times mldsa-44/results/timings.csv \
  --clock-frequency 1000 \
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

