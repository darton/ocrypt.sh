#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

progname="$(basename "$0")"

FORCE=0
QUIET=0
FORCE_OPENSSL=0
FORCE_AGE=0

log() { [ "$QUIET" -eq 1 ] || echo "$@"; }
die() { echo "Error: $*" >&2; exit 1; }

usage() {
cat <<EOF
$progname - encrypt/decrypt using age (preferred) or OpenSSL fallback

Usage:
  $progname encrypt [options] <input> <output>
  $progname decrypt [options] <input> <output>

input/output can be '-' (stdin/stdout)

Options:
  -f, --force       overwrite output file
  -q, --quiet       suppress messages
      --age         force age (encrypt only)
      --openssl     force OpenSSL fallback (encrypt only)
  -h, --help        show help

Auto-detect (decrypt):
  - age format header:     "age-encryption.org/"
  - openssl fallback header: "OCPT1"

OpenSSL fallback format:
  [OCPT1(5)][salt(16)][iv(16)][ciphertext...][hmac(32)]

Examples:
  $progname encrypt secret.txt secret.enc
  $progname decrypt secret.enc secret.txt

  cat secret.txt | $progname encrypt - - > secret.enc
  $progname decrypt secret.enc - > secret.txt
EOF
exit 0
}

have_age=0
command -v age >/dev/null 2>&1 && have_age=1

have_openssl=0
command -v openssl >/dev/null 2>&1 && have_openssl=1

stat_size() {
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
  local pass="$1"
  local salt_hex="$2"

  printf '%s' "$pass" | openssl kdf \
    -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt iter:1000000 \
    -kdfopt salt:"$salt_hex" \
    PBKDF2 | tr -d '\n'
}

detect_format_file() {
  local file="$1"

  local head20
  head20="$(head -c 20 "$file" 2>/dev/null || true)"

  if [[ "$head20" == age-encryption.org/* ]]; then
    echo "age"
    return 0
  fi

  local head5
  head5="$(head -c 5 "$file" 2>/dev/null || true)"
  if [ "$head5" = "OCPT1" ]; then
    echo "openssl"
    return 0
  fi

  echo "unknown"
}

detect_format_stdin() {
  # Read first 20 bytes from stdin safely, store them + rest in temp file
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"

  local fmt
  fmt="$(detect_format_file "$tmp")"

  echo "$fmt $tmp"
}

age_encrypt() {
  local in="$1"
  local out="$2"

  log "Using age (password mode)."

  if [ "$in" = "-" ] && [ "$out" = "-" ]; then
    age -p
  elif [ "$in" = "-" ]; then
    age -p -o "$out"
  elif [ "$out" = "-" ]; then
    age -p "$in"
  else
    age -p -o "$out" "$in"
  fi
}

age_decrypt() {
  local in="$1"
  local out="$2"

  log "Using age (password mode)."

  if [ "$in" = "-" ] && [ "$out" = "-" ]; then
    age -d
  elif [ "$in" = "-" ]; then
    age -d -o "$out"
  elif [ "$out" = "-" ]; then
    age -d "$in"
  else
    age -d -o "$out" "$in"
  fi
}

openssl_encrypt() {
  local in="$1"
  local out="$2"

  [ "$have_openssl" -eq 1 ] || die "openssl not installed"

  local pass salt_hex iv_hex keymat_hex aes_key_hex hmac_key_hex
  pass="$(read_password_encrypt)"

  salt_hex="$(openssl rand -hex 16)"
  iv_hex="$(openssl rand -hex 16)"

  keymat_hex="$(derive_keys_hex "$pass" "$salt_hex")"
  aes_key_hex="${keymat_hex:0:64}"
  hmac_key_hex="${keymat_hex:64:64}"

  local tmp_plain tmp_cipher tmp_data
  tmp_plain="$(mktemp)"
  tmp_cipher="$(mktemp)"
  tmp_data="$(mktemp)"
  trap 'rm -f "$tmp_plain" "$tmp_cipher" "$tmp_data"' RETURN

  if [ "$in" = "-" ]; then
    cat > "$tmp_plain"
  else
    [ -f "$in" ] || die "input file not found: $in"
    cat "$in" > "$tmp_plain"
  fi

  openssl enc -aes-256-cbc \
    -K "$aes_key_hex" -iv "$iv_hex" \
    -in "$tmp_plain" -out "$tmp_cipher"

  {
    echo -n "OCPT1"
    echo -n "$salt_hex" | xxd -r -p
    echo -n "$iv_hex"   | xxd -r -p
    cat "$tmp_cipher"
  } > "$tmp_data"

  local hmac_hex
  hmac_hex="$(openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hmac_key_hex" "$tmp_data" | awk '{print $2}')"

  if [ "$out" = "-" ]; then
    cat "$tmp_data"
    echo -n "$hmac_hex" | xxd -r -p
  else
    cat "$tmp_data" > "$out"
    echo -n "$hmac_hex" | xxd -r -p >> "$out"
  fi
}

openssl_decrypt() {
  local in="$1"
  local out="$2"

  [ "$have_openssl" -eq 1 ] || die "openssl not installed"

  local pass
  pass="$(read_password_decrypt)"

  local tmp_in tmp_data tmp_cipher tmp_plain
  tmp_in="$(mktemp)"
  tmp_data="$(mktemp)"
  tmp_cipher="$(mktemp)"
  tmp_plain="$(mktemp)"
  trap 'rm -f "$tmp_in" "$tmp_data" "$tmp_cipher" "$tmp_plain"' RETURN

  if [ "$in" = "-" ]; then
    cat > "$tmp_in"
  else
    [ -f "$in" ] || die "input file not found: $in"
    cat "$in" > "$tmp_in"
  fi

  local magic
  magic="$(head -c 5 "$tmp_in" 2>/dev/null || true)"
  [ "$magic" = "OCPT1" ] || die "not an OCPT1 file (wrong format)"

  local filesize
  filesize="$(stat_size "$tmp_in")"

  local minsize=$((5 + 16 + 16 + 32))
  [ "$filesize" -ge "$minsize" ] || die "file too small/corrupted"

  local data_size=$((filesize - 32))

  head -c "$data_size" "$tmp_in" > "$tmp_data"

  local stored_hmac_hex
  stored_hmac_hex="$(tail -c 32 "$tmp_in" | xxd -p -c 256 | tr -d '\n')"

  local salt_hex iv_hex
  salt_hex="$(tail -c +6 "$tmp_data" | head -c 16 | xxd -p -c 256 | tr -d '\n')"
  iv_hex="$(tail -c +22 "$tmp_data" | head -c 16 | xxd -p -c 256 | tr -d '\n')"

  local keymat_hex aes_key_hex hmac_key_hex
  keymat_hex="$(derive_keys_hex "$pass" "$salt_hex")"
  aes_key_hex="${keymat_hex:0:64}"
  hmac_key_hex="${keymat_hex:64:64}"

  local calc_hmac_hex
  calc_hmac_hex="$(openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hmac_key_hex" "$tmp_data" | awk '{print $2}')"

  [ "$calc_hmac_hex" = "$stored_hmac_hex" ] || die "HMAC failed: wrong password or modified file"

  # ciphertext begins after header(5)+salt(16)+iv(16) = 37 bytes
  tail -c +38 "$tmp_data" > "$tmp_cipher"

  openssl enc -aes-256-cbc -d \
    -K "$aes_key_hex" -iv "$iv_hex" \
    -in "$tmp_cipher" -out "$tmp_plain"

  if [ "$out" = "-" ]; then
    cat "$tmp_plain"
  else
    cat "$tmp_plain" > "$out"
  fi
}

parse_args() {
  local args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -f|--force) FORCE=1 ;;
      -q|--quiet) QUIET=1 ;;
      --openssl) FORCE_OPENSSL=1 ;;
      --age) FORCE_AGE=1 ;;
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

if [ "$outfile" != "-" ]; then
  if [ -e "$outfile" ] && [ "$FORCE" -ne 1 ]; then
    die "output exists (use --force): $outfile"
  fi
fi

case "$mode" in
  encrypt)
    if [ "$FORCE_AGE" -eq 1 ] && [ "$FORCE_OPENSSL" -eq 1 ]; then
      die "cannot use --age and --openssl together"
    fi

    if [ "$FORCE_AGE" -eq 1 ]; then
      [ "$have_age" -eq 1 ] || die "age forced but not installed"
      age_encrypt "$infile" "$outfile"
      exit 0
    fi

    if [ "$FORCE_OPENSSL" -eq 1 ]; then
      log "Using OpenSSL fallback (forced)."
      openssl_encrypt "$infile" "$outfile"
      exit 0
    fi

    if [ "$have_age" -eq 1 ]; then
      age_encrypt "$infile" "$outfile"
    else
      log "age not found, using OpenSSL fallback."
      openssl_encrypt "$infile" "$outfile"
    fi
    ;;

  decrypt)
    if [ "$infile" = "-" ]; then
      # buffer stdin to detect format
      read fmt tmpfile < <(detect_format_stdin)
      trap 'rm -f "$tmpfile"' EXIT

      case "$fmt" in
        age)
          [ "$have_age" -eq 1 ] || die "age format detected but age not installed"
          age_decrypt "$tmpfile" "$outfile"
          ;;
        openssl)
          openssl_decrypt "$tmpfile" "$outfile"
          ;;
        *)
          die "unknown input format (stdin)"
          ;;
      esac
      exit 0
    fi

    [ -f "$infile" ] || die "input file not found: $infile"

    fmt="$(detect_format_file "$infile")"
    case "$fmt" in
      age)
        [ "$have_age" -eq 1 ] || die "age format detected but age not installed"
        age_decrypt "$infile" "$outfile"
        ;;
      openssl)
        openssl_decrypt "$infile" "$outfile"
        ;;
      *)
        die "unknown file format"
        ;;
    esac
    ;;

  *)
    usage
    ;;
esac

log "OK"