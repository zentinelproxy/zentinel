#!/usr/bin/env bash
# Zentinel README demo driver. Every command shown is really run; only the
# typing is simulated. Recorded with:
#   asciinema rec -c 'bash demo.sh' --window-size 100x32 demo.cast
#   agg demo.cast demo.gif
# Run from .github/static/demo/ with the release `zentinel` on PATH, then copy
# demo.gif to .github/static/. The agg theme used for the README GIF:
#   agg --font-size 16 --idle-time-limit 5 --last-frame-duration 4 \
#     --theme 1e1e2e,cdd6f4,45475a,f38ba8,a6e3a1,f9e2af,89b4fa,cba6f7,94e2d5,bac2de,6c7086,f38ba8,a6e3a1,f9e2af,89b4fa,cba6f7,94e2d5,a6adc8 \
#     demo.cast demo.gif
set -u
P=$'\e[38;5;105m>\e[0m '

type_run() {
  printf '%s' "$P"
  local s=$1 i
  for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.04; done
  sleep 0.3; printf '\n'
  [[ $s == \#* ]] || eval "$s"
}

# Backend on :3000 (python's static file server), started before the recording shows anything.
python3 -m http.server 3000 --bind 127.0.0.1 -d www >/dev/null 2>&1 &
BACKEND=$!
trap 'kill $BACKEND ${PROXY:-} 2>/dev/null' EXIT
sleep 1; clear

type_run "# A backend is listening on :3000. Put Zentinel in front of it."
type_run "cat zentinel.kdl"
sleep 4; clear

type_run "# Validate the config"
type_run "zentinel test --strict -c zentinel.kdl"
sleep 3; clear

type_run "# Start the proxy"
printf '%s' "$P"; s="zentinel -c zentinel.kdl > zentinel.log 2>&1 &"
for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.04; done; sleep 0.3; printf '\n'
zentinel -c zentinel.kdl > zentinel.log 2>&1 &
PROXY=$!
sleep 1.5
type_run "grep -E 'HTTP listening|started successfully' zentinel.log"
sleep 2

type_run "# Send a request through it"
type_run "curl -si http://127.0.0.1:8080/"
sleep 5
printf '%s' "$P"
sleep 1
