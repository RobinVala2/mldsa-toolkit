#!/bin/bash
set -e  
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "tlsfuzzer" ]; then
    echo "Downloading tlsfuzzer..."
    git clone https://github.com/tlsfuzzer/tlsfuzzer.git
else
    echo "tlsfuzzer directory already exists, skipping download"
fi

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists"
fi

source venv/bin/activate
echo "Installing tlsfuzzer base dependencies..."
pip install -r tlsfuzzer/requirements.txt
echo "Installing tlsfuzzer timing dependencies..."
pip install -r tlsfuzzer/requirements-timing.txt

echo "Installing ML-DSA specific dependencies..."
pip install dilithium-py

