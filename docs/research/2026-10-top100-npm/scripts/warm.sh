#!/bin/bash
p="$1"; f="work/warm/$(echo "$p" | tr '/@' '__').log"
start=$(date +%s)
timeout 240 npx -y -p "$p" -- true >"$f" 2>&1; rc=$?
echo "$p rc=$rc secs=$(( $(date +%s) - start ))" >> work/warm/_summary.txt
