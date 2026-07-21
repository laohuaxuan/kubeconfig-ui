#!/bin/sh
set -eu

/app/server &
SERVER_PID=$!

nginx -g "daemon off;" &
NGINX_PID=$!

cleanup() {
  kill -TERM "$SERVER_PID" "$NGINX_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  wait "$NGINX_PID" 2>/dev/null || true
  exit 0
}

trap cleanup INT TERM

wait "$NGINX_PID"
kill -TERM "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
