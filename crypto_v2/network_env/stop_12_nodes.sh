#!/bin/bash
echo 'Stopping all 12 nodes...'
kill 129077 129089 129095 129100 129107 129125 129130 129151 129156 129161 129168 129176 2>/dev/null
sleep 2
pkill -f 'crypto_v2/node.py' 2>/dev/null
echo 'Cleanup complete.'
