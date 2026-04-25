#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

progname=$(basename "$0")

usage() {
  cat <<EOF
Usage:
  $progname encrypt <input_file> <output_file>
  $progname decrypt <input_file> <output_file>

Format:
  [salt(16)][iv(16)][ciphertext...][hmac(32)]

EOF
  exit 1
}

die() {
  echo "Error: $*" >&2
  exit 1
}

[ $# -eq 3 ] || usage

mode="$1"
infile="$2"
outfile="$3"

[ -f "$infile" ] || die "Input file '$infile' does not exist."
[ ! -e "$outfile" ] || die "Output file '$outfile' already exists."

openssl_bin=$(command -v openssl || true)
[ -n "$openssl_bin" ] || die "openssl not found."

get_password_encrypt() {
  local p1 p2
  read -s -p "Password: " p1; echo
  read -s -p "Confirm: " p2; echo
  [ "$p1" = "$p2" ] || die "Password mismatch."
  printf '%s' "$p1"
}

get_password_decrypt() {
  local p
  read -s -p "Password: " p; echo
  printf '%s' "$p"
}

# Derive keys: 64 bytes total
# first 32 bytes = AES key
# next 32 bytes  = HMAC key
derive_keys_hex() {
  local pass="$1"
  local salt_hex="$2"

  # 64 bytes = 512 bits => 128 hex chars
  printf '%s' "$pass" | "$openssl_bin" kdf \
    -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt iter:1000000 \
    -kdfopt salt:"$salt_hex" \
    PBKDF2 | tr -d '\n'
}

case "$mode" in
  encrypt)
    pass="$(get_password_encrypt)"

    salt_hex=$("$openssl_bin" rand -hex 16)
    iv_hex=$("$openssl_bin" rand -hex 16)

    keymat_hex="$(derive_keys_hex "$pass" "$salt_hex")"
    aes_key_hex="${keymat_hex:0:64}"
    hmac_key_hex="${keymat_hex:64:64}"

    tmp_cipher="$(mktemp)"
    tmp_data="$(mktemp)"
    trap 'rm -f "$tmp_cipher" "$tmp_data"' EXIT

    # Encrypt
    "$openssl_bin" enc -aes-256-cbc \
      -K "$aes_key_hex" -iv "$iv_hex" \
      -in "$infile" -out "$tmp_cipher"

    # Build output = salt + iv + ciphertext
    {
      echo -n "$salt_hex" | xxd -r -p
      echo -n "$iv_hex"   | xxd -r -p
      cat "$tmp_cipher"
    } > "$tmp_data"

    # HMAC over (salt+iv+ciphertext)
    hmac_hex=$("$openssl_bin" dgst -sha256 -mac HMAC -macopt hexkey:"$hmac_key_hex" "$tmp_data" | awk '{print $2}')

    # Write final output = data + hmac
    cat "$tmp_data" > "$outfile"
    echo -n "$hmac_hex" | xxd -r -p >> "$outfile"

    echo "Encrypted: $outfile"
    ;;

  decrypt)
    pass="$(get_password_decrypt)"

    # Need at least 16+16+32 bytes
    minsize=$((16 + 16 + 32))
    filesize=$(stat -c%s "$infile" 2>/dev/null || stat -f%z "$infile")

    [ "$filesize" -ge "$minsize" ] || die "File too small or corrupted."

    tmp_data="$(mktemp)"
    tmp_cipher="$(mktemp)"
    trap 'rm -f "$tmp_data" "$tmp_cipher"' EXIT

    # Split:
    # data_part = file without last 32 bytes
    # hmac_part = last 32 bytes
    data_size=$((filesize - 32))

    head -c "$data_size" "$infile" > "$tmp_data"
    tail -c 32 "$infile" | xxd -p -c 256 > /tmp/ocrypt_hmac_hex.$$
    stored_hmac_hex=$(cat /tmp/ocrypt_hmac_hex.$$ | tr -d '\n')
    rm -f /tmp/ocrypt_hmac_hex.$$

    # Extract salt + iv
    salt_hex=$(head -c 16 "$tmp_data" | xxd -p -c 256 | tr -d '\n')
    iv_hex=$(tail -c +17 "$tmp_data" | head -c 16 | xxd -p -c 256 | tr -d '\n')

    keymat_hex="$(derive_keys_hex "$pass" "$salt_hex")"
    aes_key_hex="${keymat_hex:0:64}"
    hmac_key_hex="${keymat_hex:64:64}"

    # Verify HMAC
    calc_hmac_hex=$("$openssl_bin" dgst -sha256 -mac HMAC -macopt hexkey:"$hmac_key_hex" "$tmp_data" | awk '{print $2}')

    [ "$calc_hmac_hex" = "$stored_hmac_hex" ] || die "HMAC verification failed (wrong password or file modified)."

    # Extract ciphertext (skip salt+iv)
    tail -c +33 "$tmp_data" > "$tmp_cipher"

    # Decrypt
    "$openssl_bin" enc -aes-256-cbc -d \
      -K "$aes_key_hex" -iv "$iv_hex" \
      -in "$tmp_cipher" -out "$outfile"

    echo "Decrypted: $outfile"
    ;;

  *)
    usage
    ;;
esac
