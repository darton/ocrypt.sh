#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

progname="$(basename "$0")"

FORCE=0
QUIET=0

log() {
  [ "$QUIET" -eq 1 ] && return 0
  echo "$@"
}

die() {
  echo "Error: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
$progname - AES-256-CBC + PBKDF2 + HMAC (Encrypt-then-MAC)

Usage:
  $progname encrypt [--force] [--quiet] <input> <output>
  $progname decrypt [--force] [--quiet] <input> <output>

  input/output can be '-' for stdin/stdout.

Options:
  -f, --force     overwrite output file
  -q, --quiet     suppress messages
  -h, --help      show help

Format output file:
  [salt(16)][iv(16)][ciphertext...][hmac(32)]

Examples:
  $progname encrypt secret.txt secret.enc
  $progname decrypt secret.enc secret.txt

  cat secret.txt | $progname encrypt - - > secret.enc
  $progname decrypt secret.enc - > secret.txt
EOF
  exit 0
}

openssl_bin="$(command -v openssl || true)"
[ -n "$openssl_bin" ] || die "openssl not found"

stat_size() {
  # Linux: stat -c%s
  # macOS: stat -f%z
  if stat -c%s "$1" >/dev/null 2>&1; then
    stat -c%s "$1"
  else
    stat -f%z "$1"
  fi
}

read_password_encrypt() {
  local p1 p2
  read -s -p "Password: " p1; echo >&2
  read -s -p "Confirm: " p2; echo >&2
  [ "$p1" = "$p2" ] || die "password mismatch"
  printf '%s' "$p1"
}

read_password_decrypt() {
  local p
  read -s -p "Password: " p; echo >&2
  printf '%s' "$p"
}

derive_keys_hex() {
  # 64 bytes output: 32 AES key + 32 HMAC key
  local pass="$1"
  local salt_hex="$2"

  printf '%s' "$pass" | "$openssl_bin" kdf \
    -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt iter:1000000 \
    -kdfopt salt:"$salt_hex" \
    PBKDF2 | tr -d '\n'
}

parse_args() {
  local args=()

  while [ $# -gt 0 ]; do
    case "$1" in
      -f|--force) FORCE=1 ;;
      -q|--quiet) QUIET=1 ;;
      -h|--help) usage ;;
      --) shift; break ;;
      -*)
        die "unknown option: $1"
        ;;
      *)
        args+=("$1")
        ;;
    esac
    shift
  done

  # append leftovers
  while [ $# -gt 0 ]; do
    args+=("$1")
    shift
  done

  echo "${args[@]}"
}

main_args=($(parse_args "$@"))

[ "${#main_args[@]}" -eq 3 ] || usage

mode="${main_args[0]}"
infile="${main_args[1]}"
outfile="${main_args[2]}"

# Validate output
if [ "$outfile" != "-" ]; then
  if [ -e "$outfile" ] && [ "$FORCE" -ne 1 ]; then
    die "output file exists (use --force): $outfile"
  fi
fi

# Encrypt/decrypt implementation
encrypt_file() {
  local in="$1"
  local out="$2"

  local pass salt_hex iv_hex keymat_hex aes_key_hex hmac_key_hex
  pass="$(read_password_encrypt)"

  salt_hex=$("$openssl_bin" rand -hex 16)
  iv_hex=$("$openssl_bin" rand -hex 16)

  keymat_hex="$(derive_keys_hex "$pass" "$salt_hex")"
  aes_key_hex="${keymat_hex:0:64}"
  hmac_key_hex="${keymat_hex:64:64}"

  local tmp_cipher tmp_data
  tmp_cipher="$(mktemp)"
  tmp_data="$(mktemp)"
  trap 'rm -f "$tmp_cipher" "$tmp_data"' RETURN

  # Read input (file or stdin) into temp file (because we need HMAC)
  local tmp_plain
  tmp_plain="$(mktemp)"
  trap 'rm -f "$tmp_plain" "$tmp_cipher" "$tmp_data"' RETURN

  if [ "$in" = "-" ]; then
    cat > "$tmp_plain"
  else
    [ -f "$in" ] || die "input file not found: $in"
    cat "$in" > "$tmp_plain"
  fi

  "$openssl_bin" enc -aes-256-cbc \
    -K "$aes_key_hex" -iv "$iv_hex" \
    -in "$tmp_plain" -out "$tmp_cipher"

  {
    echo -n "$salt_hex" | xxd -r -p
    echo -n "$iv_hex"   | xxd -r -p
    cat "$tmp_cipher"
  } > "$tmp_data"

  local hmac_hex
  hmac_hex=$("$openssl_bin" dgst -sha256 -mac HMAC -macopt hexkey:"$hmac_key_hex" "$tmp_data" | awk '{print $2}')

  if [ "$out" = "-" ]; then
    cat "$tmp_data"
    echo -n "$hmac_hex" | xxd -r -p
  else
    cat "$tmp_data" > "$out"
    echo -n "$hmac_hex" | xxd -r -p >> "$out"
  fi

  log "Encrypted OK."
}

decrypt_file() {
  local in="$1"
  local out="$2"

  local pass
  pass="$(read_password_decrypt)"

  local tmp_in
  tmp_in="$(mktemp)"
  trap 'rm -f "$tmp_in"' RETURN

  # read input (file or stdin) into temp file
  if [ "$in" = "-" ]; then
    cat > "$tmp_in"
  else
    [ -f "$in" ] || die "input file not found: $in"
    cat "$in" > "$tmp_in"
  fi

  local filesize
  filesize="$(stat_size "$tmp_in")"

  local minsize=$((16 + 16 + 32))
  [ "$filesize" -ge "$minsize" ] || die "file too small/corrupted"

  local data_size=$((filesize - 32))

  local tmp_data tmp_cipher
  tmp_data="$(mktemp)"
  tmp_cipher="$(mktemp)"
  trap 'rm -f "$tmp_in" "$tmp_data" "$tmp_cipher"' RETURN

  head -c "$data_size" "$tmp_in" > "$tmp_data"
  local stored_hmac_hex
  stored_hmac_hex="$(tail -c 32 "$tmp_in" | xxd -p -c 256 | tr -d '\n')"

  local salt_hex iv_hex
  salt_hex="$(head -c 16 "$tmp_data" | xxd -p -c 256 | tr -d '\n')"
  iv_hex="$(tail -c +17 "$tmp_data" | head -c 16 | xxd -p -c 256 | tr -d '\n')"

  local keymat_hex aes_key_hex hmac_key_hex
  keymat_hex="$(derive_keys_hex "$pass" "$salt_hex")"
  aes_key_hex="${keymat_hex:0:64}"
  hmac_key_hex="${keymat_hex:64:64}"

  local calc_hmac_hex
  calc_hmac_hex=$("$openssl_bin" dgst -sha256 -mac HMAC -macopt hexkey:"$hmac_key_hex" "$tmp_data" | awk '{print $2}')

  [ "$calc_hmac_hex" = "$stored_hmac_hex" ] || die "HMAC failed: wrong password or modified file"

  # ciphertext begins after 32 bytes
  tail -c +33 "$tmp_data" > "$tmp_cipher"

  local tmp_plain
  tmp_plain="$(mktemp)"
  trap 'rm -f "$tmp_in" "$tmp_data" "$tmp_cipher" "$tmp_plain"' RETURN

  "$openssl_bin" enc -aes-256-cbc -d \
    -K "$aes_key_hex" -iv "$iv_hex" \
    -in "$tmp_cipher" -out "$tmp_plain"

  if [ "$out" = "-" ]; then
    cat "$tmp_plain"
  else
    cat "$tmp_plain" > "$out"
  fi

  log "Decrypted OK."
}

case "$mode" in
  encrypt)
    encrypt_file "$infile" "$outfile"
    ;;
  decrypt)
    decrypt_file "$infile" "$outfile"
    ;;
  *)
    usage
    ;;
esac
