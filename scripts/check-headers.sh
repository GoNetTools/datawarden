#!/usr/bin/env bash
# Copyright 2026 The piiflow Authors
# SPDX-License-Identifier: Apache-2.0
#
# Fails if a Go source file (outside testdata/ directories) lacks the license header.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=0
while IFS= read -r f; do
  if ! head -n 5 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
    echo "missing license header: $f" >&2
    missing=1
  fi
done < <(git ls-files --cached --others --exclude-standard -- '*.go' ':(exclude,glob)**/testdata/**')

if [ "$missing" -ne 0 ]; then
  cat >&2 <<'MSG'

Start each Go file with:

// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0
MSG
  exit 1
fi
