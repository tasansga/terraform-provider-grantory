#!/usr/bin/env sh
set -eu

DATA_DIR_PATH=${DATA_DIR:-/data}

if [ "${1:-}" != "grantory" ]; then
  set -- grantory "$@"
fi

if [ "$(id -u)" = "0" ]; then
  if [ -d "$DATA_DIR_PATH" ]; then
    chown -R grantory:grantory "$DATA_DIR_PATH" || true
  fi
  exec gosu grantory "$@"
fi

exec "$@"
