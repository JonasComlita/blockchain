#!/bin/bash
# Script to run 12 blockchain nodes locally for testing

# --- Configuration ---
NUM_NODES=12
BASE_PORT=9000
BASE_MONITORING_PORT=9090
HOST="127.0.0.1"
DATA_DIR_BASE="/tmp/blockchain_testnet"
LOG_DIR_BASE="/tmp/blockchain_testnet/logs"
GENESIS_DB_PATH="/tmp/genesis_db" # Path to the master genesis DB
PIDS=()

# --- Pre-flight Check ---
if [ ! -d "$GENESIS_DB_PATH" ]; then
    echo "Error: Genesis database not found at '$GENESIS_DB_PATH'"
    echo "Please create it first using the genesis_tool.py"
    exit 1
fi

# --- Kill any existing nodes ---
echo "Checking for existing node processes..."
pkill -f "crypto_v2/node.py" 2>/dev/null && echo "Killed existing node processes" || echo "No existing processes found"

# Wait for ports to be released
echo "Waiting for ports to be released..."
sleep 5

# Verify ports are free
echo "Checking port availability..."
for port in $(seq $BASE_MONITORING_PORT $((BASE_MONITORING_PORT + NUM_NODES - 1))); do
    if lsof -i :$port > /dev/null 2>&1; then
        echo "WARNING: Port $port is still in use. Attempting to force kill..."
        lsof -ti :$port | xargs kill -9 2>/dev/null
        sleep 1
    fi
done

# --- Cleanup previous runs ---
echo "Cleaning up previous node data and logs..."
rm -rf $DATA_DIR_BASE
mkdir -p $DATA_DIR_BASE
mkdir -p $LOG_DIR_BASE

# --- Generate Peer List ---
# Use the first 3 nodes as initial peers for discovery
PEER_ARGS=""
for i in $(seq 0 2); do
    PORT=$((BASE_PORT + i))
    PEER_ARGS+=" --peer $HOST:$PORT"
done
echo "Using initial peer arguments:$PEER_ARGS"

# --- Start Validator Node (Node 0) ---
echo "Setting up Validator Node 0..."
NODE_0_PORT=$BASE_PORT
NODE_0_MONITORING_PORT=$BASE_MONITORING_PORT
NODE_0_DATA_DIR="$DATA_DIR_BASE/node_0"
NODE_0_DB_PATH="$NODE_0_DATA_DIR/blockchain"
NODE_0_LOG_FILE="$LOG_DIR_BASE/node_0.log"
NODE_0_KEYS_DIR="$NODE_0_DATA_DIR/keys"

# Create directories for Node 0
mkdir -p "$NODE_0_DATA_DIR"
mkdir -p "$NODE_0_KEYS_DIR"

# Copy genesis DB and validator keys
echo "Initializing Node 0 with genesis DB and validator keys..."
cp -r "$GENESIS_DB_PATH" "$NODE_0_DB_PATH"
cp -r "$(pwd)/validator_keys"/* "$NODE_0_KEYS_DIR/"

echo "Starting Validator Node 0: Port=$NODE_0_PORT, Monitoring=$NODE_0_MONITORING_PORT, DB=$NODE_0_DB_PATH"
PYTHONPATH="/home/jonas/Downloads/NetPlay-master" \
python3 /home/jonas/Downloads/NetPlay-master/crypto_v2/node.py \
    --port $NODE_0_PORT \
    --monitoring-port $NODE_0_MONITORING_PORT \
    --data-dir $NODE_0_DATA_DIR \
    $PEER_ARGS \
    --validator \
    > "$NODE_0_LOG_FILE" 2>&1 &
PIDS+=($!)

# Give Node 0 time to start and bind its ports
echo "Waiting for Node 0 to initialize..."
sleep 3

# --- Start Regular Nodes (1 to 11) ---
echo "Starting regular nodes..."
for i in $(seq 1 $((NUM_NODES - 1))); do
    PORT=$((BASE_PORT + i))
    MONITORING_PORT=$((BASE_MONITORING_PORT + i))
    NODE_DATA_DIR="$DATA_DIR_BASE/node_$i"
    DB_PATH="$NODE_DATA_DIR/blockchain"
    LOG_FILE="$LOG_DIR_BASE/node_$i.log"
    
    # Create directory and copy genesis DB
    mkdir -p "$NODE_DATA_DIR"
    echo "Initializing Node $i with genesis DB..."
    cp -r "$GENESIS_DB_PATH" "$DB_PATH"
    
    echo "Starting Node $i: Port=$PORT, Monitoring=$MONITORING_PORT, DB=$DB_PATH"
    
    # Set PYTHONPATH to the project root to resolve modules correctly
    PYTHONPATH="/home/jonas/Downloads/NetPlay-master" \
    python3 /home/jonas/Downloads/NetPlay-master/crypto_v2/node.py \
        --port $PORT \
        --monitoring-port $MONITORING_PORT \
        --data-dir $NODE_DATA_DIR \
        $PEER_ARGS \
        > "$LOG_FILE" 2>&1 &
    
    PIDS+=($!)
    
    # Small delay between node starts to avoid race conditions
    sleep 0.5
done

# --- Create Stop Script ---
STOP_SCRIPT_PATH="$(pwd)/stop_12_nodes.sh"
echo "#!/bin/bash" > $STOP_SCRIPT_PATH
echo "echo 'Stopping all 12 nodes...'" >> $STOP_SCRIPT_PATH
echo "kill ${PIDS[@]} 2>/dev/null" >> $STOP_SCRIPT_PATH
echo "sleep 2" >> $STOP_SCRIPT_PATH
echo "pkill -f 'crypto_v2/node.py' 2>/dev/null" >> $STOP_SCRIPT_PATH
echo "echo 'Cleanup complete.'" >> $STOP_SCRIPT_PATH
chmod +x $STOP_SCRIPT_PATH

# --- Output ---
echo ""
echo "All $NUM_NODES nodes have been started."
echo "Logs are being written to: $LOG_DIR_BASE"
echo "To stop all nodes, run: ./stop_12_nodes.sh"
echo ""
echo "PIDs of running nodes: ${PIDS[@]}"
echo ""
echo "Port allocation:"
echo "  P2P ports: $BASE_PORT - $((BASE_PORT + NUM_NODES - 1))"
echo "  Monitoring ports: $BASE_MONITORING_PORT - $((BASE_MONITORING_PORT + NUM_NODES - 1))"
echo ""
echo "Network launch script finished. Nodes are running in the background."
echo "Check logs with: tail -f $LOG_DIR_BASE/node_0.log"