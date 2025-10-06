#!/usr/bin/env bash
# usage: ./verifymail.sh email.eml
set -Eeuo pipefail

EML="${1:-}"
OUTDIR="extractedSignatureData"

# Always cleanup, even on error or Ctrl-C
cleanup() {
  # keep artifacts if KEEP=1
  [[ "${KEEP:-0}" == "1" ]] && return 0
  rm -rf "$OUTDIR" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -z "$EML" ]]; then
  echo "Usage: $0 <email_file.eml>"
  exit 1
fi

# 1) Run your Python extraction script
python3 prepareVerification.py "$EML"

# 2) Verify with GPG (in a conditional so set -e won't kill the script)
echo -e "\033[1;34m🔍 Running GPG verification...\033[0m\n"
if gpg --verify "$OUTDIR/signature.asc" "$OUTDIR/message.txt"; then
  echo -e "\n\033[1;32m🔺 Processing Complete -- See Details Above 🔺\033[0m\n"
  exit_code=0
else
  echo -e "\n\033[1;31m🔺 Verification Failed -- See Details Above 🔺\033[0m\n"
  exit_code=1
fi

# 3) Exit with gpg's result (cleanup still runs via trap)
exit "$exit_code"
