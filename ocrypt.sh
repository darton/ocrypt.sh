#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

progname=$(basename "$0")

usage() {
    cat <<EOF
Usage:
  $progname encrypt <input_file> <output_file>
  $progname decrypt <input_file> <output_file>

Description:
  Simple AES-256-CBC encryption/decryption with PBKDF2 (SHA-512, 1M iterations).

Examples:
  $progname encrypt secret.txt secret.enc
  $progname decrypt secret.enc secret.txt

EOF
    exit 1
}

# Check args count
if [ $# -ne 3 ]; then
    usage
fi

mode=$1
infile=$2
outfile=$3

# Validate input file
if [ ! -f "$infile" ]; then
    echo "Error: input file '$infile' does not exist."
    exit 2
fi

# Prevent overwriting existing files
if [ -e "$outfile" ]; then
    echo "Error: output file '$outfile' already exists."
    exit 3
fi

# OpenSSL command (common opts)
openssl_bin=$(command -v openssl)
if [ -z "$openssl_bin" ]; then
    echo "Error: openssl not found in PATH."
    exit 4
fi

common="-aes-256-cbc -md sha512 -pbkdf2 -iter 1000000 -salt"

case "$mode" in
    encrypt)
        echo "Encrypting '$infile' → '$outfile'..."
        "$openssl_bin" enc $common -in "$infile" -out "$outfile"
        echo "Done."
        ;;

    decrypt)
        echo "Decrypting '$infile' → '$outfile'..."
        "$openssl_bin" enc $common -d -in "$infile" -out "$outfile"
        echo "Done."
        ;;

    *)
        usage
        ;;
esac
