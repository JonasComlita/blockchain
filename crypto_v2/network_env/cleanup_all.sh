#!/bin/bash
# Complete cleanup script for blockchain testnet

BASE_MONITORING_PORT=9090
NUM_NODES=12

echo "=== Complete Cleanup ==="

# Kill all node processes
echo "1. Killing all node processes..."
pkill -9 -f "crypto_v2/node.py" 2>/dev/null
sleep 2

# Force kill anything on monitoring ports
echo "2. Freeing monitoring ports ($BASE_MONITORING_PORT-$((BASE_MONITORING_PORT + NUM_NODES - 1)))..."
for port in $(seq $BASE_MONITORING_PORT $((BASE_MONITORING_PORT + NUM_NODES - 1))); do
    if lsof -ti :$port > /dev/null 2>&1; then
        echo "  Killing process on port $port..."
        lsof -ti :$port | xargs kill -9 2>/dev/null
    fi
done

# Wait for ports to be fully released
echo "3. Waiting for ports to be released..."
sleep 3

# Verify all ports are free
echo "4. Verifying port status..."
all_free=true
for port in $(seq $BASE_MONITORING_PORT $((BASE_MONITORING_PORT + NUM_NODES - 1))); do
    if lsof -i :$port > /dev/null 2>&1; then
        echo "  WARNING: Port $port is still in use!"
        lsof -i :$port
        all_free=false
    fi
done

if [ "$all_free" = true ]; then
    echo "  ✓ All monitoring ports are free"
else
    echo "  ✗ Some ports are still in use. You may need to manually kill processes."
    exit 1
fi

# Remove data directories
echo "5. Cleaning data directories..."
rm -rf /tmp/blockchain_testnet

echo ""
echo "=== Cleanup Complete ==="
echo "All processes killed and ports freed."
echo "You can now run ./run_12_nodes.sh"