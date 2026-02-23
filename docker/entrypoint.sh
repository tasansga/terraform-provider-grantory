#!/usr/bin/env sh
set -eu

DATABASE_VALUE=${DATABASE:-/data}

if [ "${1:-}" != "grantory" ]; then
  set -- grantory "$@"
fi

if [ "$(id -u)" = "0" ]; then
  case "$DATABASE_VALUE" in
    postgres://*|postgresql://*)
      ;;
    *)
      if [ -d "$DATABASE_VALUE" ]; then
        chown -R grantory:grantory "$DATABASE_VALUE" || true
      fi
      ;;
  esac
  exec gosu grantory "$@"
fi

exec "$@"
