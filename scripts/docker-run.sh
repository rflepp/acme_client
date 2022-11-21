#!/bin/bash

echo "Waiting until testing server is up (${1})..."
until curl -sL "$1" > /dev/null 2>&1; do :; done &
trap 'kill $!' SIGINT
wait $!
trap - SIGINT
echo "${1} is up"

python3 "$(dirname "$0")/launcher.py" "${1}"
