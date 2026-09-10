#!/bin/sh
set -eu
make generate
# Generation is deterministic; a Git checkout can additionally run git diff --exit-code.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --exit-code -- internal/db internal/web/components
fi
