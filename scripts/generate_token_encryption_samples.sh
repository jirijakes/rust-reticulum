#!/bin/sh

# Use Python reference implementation to generate testing data for token encryption.
#
# Usage:
#
# PYTHONPATH='/path/to/Reticulum' sh generate_token_encryption_samples.sh
#
# Store the output in crates/reticulum/tests/data/token_encryption_samples.txt

if python -c 'import RNS' 2> /dev/null; then
    python generate_token_encryption_samples.py
else
    echo "Run this script with PYTHONPATH='DIR' where DIR points to Reticulum reference implementation."
    exit 1
fi


