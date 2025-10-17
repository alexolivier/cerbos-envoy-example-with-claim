#!/usr/bin/env sh
set -eu

adapter_cmd="/usr/local/bin/envoy-adapter"
cleanup_called=0

cleanup() {
  if [ "$cleanup_called" -eq 1 ]; then
    return
  fi
  cleanup_called=1

  if [ -n "${adapter_pid:-}" ] && kill -0 "$adapter_pid" 2>/dev/null; then
    kill "$adapter_pid" 2>/dev/null || true
  fi
  if [ -n "${envoy_pid:-}" ] && kill -0 "$envoy_pid" 2>/dev/null; then
    kill "$envoy_pid" 2>/dev/null || true
  fi
}

if [ "$#" -eq 0 ]; then
  set -- envoy -c /etc/envoy/envoy.yaml
else
  set -- envoy "$@"
fi

trap 'cleanup' INT TERM EXIT

"$adapter_cmd" &
adapter_pid=$!

"$@" &
envoy_pid=$!

status=0
while kill -0 "$adapter_pid" 2>/dev/null && kill -0 "$envoy_pid" 2>/dev/null; do
  sleep 1
done

if ! kill -0 "$adapter_pid" 2>/dev/null; then
  if ! wait "$adapter_pid"; then
    status=$?
  fi
else
  if ! wait "$envoy_pid"; then
    status=$?
  fi
fi

cleanup
wait "$adapter_pid" 2>/dev/null || true
wait "$envoy_pid" 2>/dev/null || true

exit "$status"
