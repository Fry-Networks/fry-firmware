#!/usr/bin/env bash
# Flash a PlatformIO env to an explicit port, retrying past a transient port-busy lock (pio
# upload has no built-in retry). PROTOCOL.md section 8.
# Usage: tools/flash.sh <env> <port>
set -u
ENVNAME="${1:?usage: tools/flash.sh <env> <port>}"
PORT="${2:?usage: tools/flash.sh <env> <port>}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
cd "$repo" || exit 2
for i in $(seq 1 15); do
  echo "=== flash attempt $i env=$ENVNAME port=$PORT ==="
  if pio run -e "$ENVNAME" -t upload --upload-port "$PORT"; then
    echo "FLASH_OK attempt=$i port=$PORT"
    exit 0
  fi
  echo "attempt $i failed; retry in 4s"
  sleep 4
done
echo "FLASH_FAILED after 15 attempts"
exit 1
