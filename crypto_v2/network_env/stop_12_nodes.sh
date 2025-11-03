#!/bin/bash
echo 'Stopping all 12 nodes...'
kill 104537 104560 104571 104576 104584 104589 104594 104599 104604 104626 104633 104664 2>/dev/null
sleep 2
pkill -f 'crypto_v2/node.py' 2>/dev/null
echo 'Cleanup complete.'
