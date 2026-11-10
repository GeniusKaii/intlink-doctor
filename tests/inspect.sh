#!/usr/bin/env bash
set -u
W="${1:?work dir}"
E="$(find "$W/x1" -type d -name evidence | head -1)"
echo "E=$E"
for f in 30_sockets.tsv 35_filter_hints.txt 34_endpoint_candidates.tsv 20_procs.tsv; do
  echo "=== $f ==="
  cat "$E/$f" 2>/dev/null | head -25
done
echo "=== 55_fd_evidence.txt ==="
head -30 "$E/55_fd_evidence.txt" 2>/dev/null
echo "=== 91_parse_gaps ==="
cat "$E/91_parse_gaps.txt" 2>/dev/null
