#!/bin/bash
which strace > /dev/null || (echo "ERROR: strace not found" && exit 1)
strace -o /tmp/log.txt -e trace=connect "$@"
if grep -q connect /tmp/log.txt; then
    printf '\033[1;31m%s\033[0m\n' "ERROR: network activity detected"
    exit 1
fi
