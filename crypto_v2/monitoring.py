# crypto_v2/monitoring.py
import time
import psutil
import os
import socket
from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry
from prometheus_client.exposition import make_wsgi_app
from wsgiref.simple_server import make_server, WSGIServer
from socketserver import ThreadingMixIn
import threading
import logging

logger = logging.getLogger(__name__)

# Create a threaded WSGI server for the Prometheus metrics
class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """A WSGI server that runs in a separate thread to not block the main application."""
    allow_reuse_address = True  # Allow reusing the address immediately
    pass

class Monitor:
    def __init__(self, blockchain, host="127.0.0.1", port=9090):
        self.blockchain = blockchain
        self.host = host
        self.port = port
        self.server = None
        self.thread = None

        # Initialize variables for TPS calculation
        self.last_time = time.time()
        self.last_tx_count = 0
        
        # Create a new, isolated registry for this node
        self.registry = CollectorRegistry()

        # Register metrics with the new registry
        self.tx_counter = Counter('blockchain_transactions_total', 'Total number of transactions processed', ['status'], registry=self.registry)
        self.block_latency = Histogram('blockchain_block_latency_seconds', 'Latency of block processing', registry=self.registry)
        self.mempool_size = Gauge('blockchain_mempool_size', 'Number of transactions in the mempool', registry=self.registry)
        self.chain_height = Gauge('blockchain_chain_height', 'Current height of the blockchain', registry=self.registry)
        self.cpu_usage = Gauge('system_cpu_percent', 'Current CPU usage percent', registry=self.registry)
        self.memory_usage = Gauge('system_memory_percent', 'Current memory usage percent', registry=self.registry)
        self.tps = Gauge('blockchain_tps', 'Transactions per second', registry=self.registry)
        self.oracle_round = Gauge('oracle_round_current', 'Active oracle round', registry=self.registry)
        self.validator_count = Gauge('validator_count', 'Number of active validators', registry=self.registry)
        self.amm_k = Gauge('amm_invariant_k', 'Constant product k', registry=self.registry)
        self.tx_latency = Histogram('tx_processing_latency_seconds', 'Time to process a tx', registry=self.registry)
        self.oracle_finalized = Counter('oracle_round_finalized_total', 'Oracle rounds finalized', registry=self.registry)
        
        # Manually set up and start the server in a separate thread
        self.start_server()

    def start_server(self):
        """Manually creates and starts the Prometheus HTTP server with retry logic."""
        app = make_wsgi_app(self.registry)
        
        max_retries = 5
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                # Create server with address reuse enabled
                self.server = make_server(self.host, self.port, app, ThreadingWSGIServer)
                
                # Enable SO_REUSEADDR at socket level as well
                self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                self.thread = threading.Thread(target=self.server.serve_forever)
                self.thread.daemon = True
                self.thread.start()
                logger.info(f"Prometheus server started on http://{self.host}:{self.port}")
                return
            except OSError as e:
                if e.errno == 98:  # Address already in use
                    if attempt < max_retries - 1:
                        logger.warning(f"Port {self.port} in use, retrying in {retry_delay}s (attempt {attempt+1}/{max_retries})...")
                        time.sleep(retry_delay)
                    else:
                        logger.error(f"Failed to bind to port {self.port} after {max_retries} attempts")
                        raise
                else:
                    raise

    def stop_server(self):
        """Stops the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Prometheus server stopped.")

    def update(self):
        latest = self.blockchain.get_latest_block()
        self.chain_height.set(latest.height)

        # TPS
        now = time.time()
        elapsed = now - self.last_time
        if elapsed > 0:
            tps = (self.blockchain.total_transactions - self.last_tx_count) / elapsed
            self.tps.set(tps)
        self.last_tx_count = self.blockchain.total_transactions
        self.last_time = now

        self.mempool_size.set(len(self.blockchain.mempool.transactions))
        self.oracle_round.set(self.blockchain.current_oracle_round)
        self.validator_count.set(len(self.blockchain._get_validator_set(self.blockchain.state_trie)))

        # AMM
        try:
            pool = self.blockchain._get_liquidity_pool_state(self.blockchain.state_trie)
            self.amm_k.set(pool.token_reserve * pool.usd_reserve)
        except:
            pass

        self.cpu_usage.set(psutil.cpu_percent())
        self.memory_usage.set(psutil.virtual_memory().percent)

    def record_tx(self, status: str, latency: float):
        self.tx_counter.labels(status=status).inc()
        self.tx_latency.observe(latency)

    def record_block(self, latency: float):
        self.block_latency.observe(latency)
        self.oracle_finalized.inc() if self.blockchain.oracle_rounds else None