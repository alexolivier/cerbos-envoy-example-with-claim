#!/usr/bin/env bash

set -euo pipefail

subjects=(alice bob carol)
paths=(/api/acct-123/documents /api/acct-456/documents /api/admin)

for subject in "${subjects[@]}"; do
  TOKEN=$(python3 tokens/emit_token.py "$subject")
  echo
  echo "===== ${subject} token ====="

  for path in "${paths[@]}"; do
    echo
    echo "### GET ${path}"
    curl -isS -H "Authorization: Bearer ${TOKEN}" "http://localhost:18000${path}" | sed 's/^/    /'
  done
done

echo
