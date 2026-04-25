#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

progname="$(basename "$0")"

FORCE=0
QUIET=0
INFO=0
LIST=0
NO_PROMPT=0
FORCE_OPENSSL=0
FORCE_AGE=0

log() { [ "$QUIET" -eq 1 ] || echo "$@"; }
die() { echo "Error: $*" >&2; exit 1; }

usage() {
cat <<EOF
$progname - hybrid encryption tool (age preferred, OpenSSL fallback)

Usage:
  $progname encrypt [options] <input> <output>
  $progname decrypt [options] <input> <output>

Options:
  -f, --force         overwrite output
  -q, --quiet         silent mode
  -i, --info          show file detection info
      --list-backends show available engines
      --openssl       force OpenSSL (encrypt only)
      --age           force age (encrypt only)
      --no-prompt     use OCYPT_PASS env (CI mode)
  -h, --help

Auto-detect (decrypt):
  age:     age-encryption.org/*
  openssl: OCPT1 header

OpenSSL format:
  OCPT1 + salt + iv + ciphertext + hmac

Env (CI mode):
  OCYPT_PASS="password"

Examples:
  $progname encrypt file.txt file.enc
  $progname decrypt file.enc file.txt
EOF
exit 0
}

have_age=0
have_openssl=0
command -v age >/dev/null 2>&1 && have_age=1
command -v openssl >/dev/null 2>&1 && have_openssl=1

stat_size() {
  if stat -c%s "$1" >/dev/null 2>&1; then stat -c%s "$1"; else stat -f%z "$1"; fi
}

read_pass_enc() {
  if [ "$NO_PROMPT" -eq 1 ]; then
    [ -n "${OCYPT_PASS:-}" ] || die "OCYPT_PASS not set"
    echo "$OCYPT_PASS"
    return
  fi

  local p1 p2
  read -s -p "Password: " p1; echo >&2
  read -s -p "Confirm: " p2; echo >&2
  [ "$p1" = "$p2" ] || die "password mismatch"
  printf '%s' "$p1"
}

read_pass_dec() {
  if [ "$NO_PROMPT" -eq 1 ]; then
    [ -n "${OCYPT_PASS:-}" ] || die "OCYPT_PASS not set"
    echo "$OCYPT_PASS"
    return
  fi

  local p
  read -s -p "Password: " p; echo >&2
  printf '%s' "$p"
}

derive_keys() {
  local pass="$1"
  local salt="$2"

  printf '%s' "$pass" | openssl kdf \
    -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt iter:1000000 \
    -kdfopt salt:"$salt" \
    PBKDF2 | tr -d '\n'
}

detect_file() {
  local f="$1"

  local h20 h5
  h20="$(head -c 20 "$f" 2>/dev/null || true)"

  if [[ "$h20" == age-encryption.org/* ]]; then
    echo "age"
    return
  fi

  h5="$(head -c 5 "$f" 2>/dev/null || true)"
  if [ "$h5" = "OCPT1" ]; then
    echo "openssl"
    return
  fi

  echo "unknown"
}

info_file() {
  local f="$1"

  echo "File: $f"

  if [ "$f" = "-" ]; then
    echo "Source: stdin (cannot fully inspect)"
    return
  fi

  local fmt
  fmt="$(detect_file "$f")"

  case "$fmt" in
    age) echo "Format: age" ;;
    openssl) echo "Format: OCPT1 (openssl fallback)" ;;
    *) echo "Format: unknown" ;;
  esac
}

age_enc() {
  [ "$have_age" -eq 1 ] || die "age not installed"

  if [ "$1" = "-" ] && [ "$2" = "-" ]; then
    age -p
  elif [ "$1" = "-" ]; then
    age -p -o "$2"
  elif [ "$2" = "-" ]; then
    age -p "$1"
  else
    age -p -o "$2" "$1"
  fi
}

age_dec() {
  if [ "$1" = "-" ] && [ "$2" = "-" ]; then
    age -d
  elif [ "$1" = "-" ]; then
    age -d -o "$2"
  elif [ "$2" = "-" ]; then
    age -d "$1"
  else
    age -d -o "$2" "$1"
  fi
}

openssl_enc() {
  [ "$have_openssl" -eq 1 ] || die "openssl not installed"

  local pass salt iv keymat aes hmac
  pass="$(read_pass_enc)"

  salt="$(openssl rand -hex 16)"
  iv="$(openssl rand -hex 16)"

  keymat="$(derive_keys "$pass" "$salt")"
  aes="${keymat:0:64}"
  hmac="${keymat:64:64}"

  local t1 t2 t3
  t1="$(mktemp)"
  t2="$(mktemp)"
  t3="$(mktemp)"
  trap 'rm -f "$t1" "$t2" "$t3"' RETURN

  if [ "$1" = "-" ]; then cat > "$t1"; else cat "$1" > "$t1"; fi

  openssl enc -aes-256-cbc -K "$aes" -iv "$iv" -in "$t1" -out "$t2"

  {
    echo -n "OCPT1"
    echo -n "$salt" | xxd -r -p
    echo -n "$iv" | xxd -r -p
    cat "$t2"
  } > "$t3"

  local mac
  mac="$(openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hmac" "$t3" | awk '{print $2}')"

  if [ "$2" = "-" ]; then
    cat "$t3"
    echo -n "$mac" | xxd -r -p
  else
    cat "$t3" > "$2"
    echo -n "$mac" | xxd -r -p >> "$2"
  fi
}

openssl_dec() {
  local pass tmp fsize

  pass="$(read_pass_dec)"

  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  if [ "$1" = "-" ]; then cat > "$tmp"; else cat "$1" > "$tmp"; fi

  fsize="$(stat_size "$tmp")"
  [ "$fsize" -gt 70 ] || die "too small"

  local hdr
  hdr="$(head -c 5 "$tmp")"
  [ "$hdr" = "OCPT1" ] || die "invalid OCPT1"

  local data_len
  data_len=$((fsize - 32))

  local data mac salt iv
  data="$(mktemp)"
  trap 'rm -f "$tmp" "$data"' RETURN

  head -c "$data_len" "$tmp" > "$data"
  mac="$(tail -c 32 "$tmp" | xxd -p -c 256)"

  salt="$(tail -c +6 "$data" | head -c 16 | xxd -p -c 256)"
  iv="$(tail -c +22 "$data" | head -c 16 | xxd -p -c 256)"

  local keymat aes hmac calc
  keymat="$(derive_keys "$pass" "$salt")"
  aes="${keymat:0:64}"
  hmac="${keymat:64:64}"

  calc="$(openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hmac" "$data" | awk '{print $2}')"

  [ "$calc" = "$mac" ] || die "HMAC fail"

  local cipher out
  cipher="$(mktemp)"
  out="$(mktemp)"
  trap 'rm -f "$tmp" "$data" "$cipher" "$out"' RETURN

  tail -c +38 "$data" > "$cipher"

  openssl enc -aes-256-cbc -d -K "$aes" -iv "$iv" -in "$cipher" -out "$out"

  if [ "$2" = "-" ]; then cat "$out"; else cat "$out" > "$2"; fi
}

# CLI
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--force) FORCE=1 ;;
    -q|--quiet) QUIET=1 ;;
    -i|--info) INFO=1 ;;
    --list-backends) LIST=1 ;;
    --openssl) FORCE_OPENSSL=1 ;;
    --age) FORCE_AGE=1 ;;
    --no-prompt) NO_PROMPT=1 ;;
    -h|--help) usage ;;
    --) shift; break ;;
    *) break ;;
  esac
  shift
done

if [ "$LIST" -eq 1 ]; then
  echo "age: $have_age"
  echo "openssl: $have_openssl"
  exit 0
fi

mode="${1:-}"
in="${2:-}"
out="${3:-}"

[ -n "$mode" ] || usage

if [ "$INFO" -eq 1 ]; then
  info_file "$in"
  exit 0
fi

case "$mode" in
  encrypt)
    if [ "$FORCE_AGE" -eq 1 ]; then
      age_enc "$in" "$out"
    elif [ "$FORCE_OPENSSL" -eq 1 ]; then
      openssl_enc "$in" "$out"
    elif [ "$have_age" -eq 1 ]; then
      age_enc "$in" "$out"
    else
      openssl_enc "$in" "$out"
    fi
    ;;
  decrypt)
    fmt="$(detect_file "$in")"

    case "$fmt" in
      age) age_dec "$in" "$out" ;;
      openssl) openssl_dec "$in" "$out" ;;
      *) die "unknown format" ;;
    esac
    ;;
  *) usage ;;
esac

log "OK"