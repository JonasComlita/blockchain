# crypto_v2/monitoring.py
import time
import psutil
from prometheus_client import Counter, Gauge, Histogram, start_http_server

# --- Prometheus Metrics ---
BLOCK_HEIGHT = Gauge('blockchain_height', 'Current block height')
TPS = Gauge('blockchain_tps', 'Transactions per second')
MEMPOOL_SIZE = Gauge('mempool_size', 'Number of pending txs')
ORACLE_ROUND = Gauge('oracle_round_current', 'Active oracle round')
ORACLE_SUBMISSIONS = Gauge('oracle_submissions', 'Submissions in current round')
VALIDATOR_COUNT = Gauge('validator_count', 'Number of active validators')
AMM_K = Gauge('amm_invariant_k', 'Constant product k')
CPU_USAGE = Gauge('system_cpu_percent', 'CPU usage %')
MEMORY_USAGE = Gauge('system_memory_percent', 'Memory usage %')

TX_LATENCY = Histogram('tx_processing_latency_seconds', 'Time to process a tx')
BLOCK_TIME = Histogram('block_production_time_seconds', 'Time to produce a block')

# --- Counters ---
TX_PROCESSED = Counter('tx_processed_total', 'Total transactions processed', ['status'])  # success/fail
ORACLE_FINALIZED = Counter('oracle_round_finalized_total', 'Oracle rounds finalized')

class Monitor:
    def __init__(self, blockchain):
        self.chain = blockchain
        self.last_tx_count = 0
        self.last_time = time.time()
        start_http_server(9090)  # Prometheus scrape endpoint

    def update(self):
        latest = self.chain.get_latest_block()
        BLOCK_HEIGHT.set(latest.height)

        # TPS
        now = time.time()
        elapsed = now - self.last_time
        if elapsed > 0:
            tps = (self.chain.total_transactions - self.last_tx_count) / elapsed
            TPS.set(tps)
        self.last_tx_count = self.chain.total_transactions
        self.last_time = now

        MEMPOOL_SIZE.set(len(self.chain.mempool.transactions))
        ORACLE_ROUND.set(self.chain.current_oracle_round)
        VALIDATOR_COUNT.set(len(self.chain._get_validator_set(self.chain.state_trie)))

        # AMM
        try:
            pool = self.chain._get_liquidity_pool_state(self.chain.state_trie)
            AMM_K.set(pool.token_reserve * pool.usd_reserve)
        except:
            pass

        CPU_USAGE.set(psutil.cpu_percent())
        MEMORY_USAGE.set(psutil.virtual_memory().percent)

    def record_tx(self, status: str, latency: float):
        TX_PROCESSED.labels(status=status).inc()
        TX_LATENCY.observe(latency)

    def record_block(self, latency: float):
        BLOCK_TIME.observe(latency)
        ORACLE_FINALIZED.inc() if self.chain.oracle_rounds else None