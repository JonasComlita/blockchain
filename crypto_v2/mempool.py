"""
Improved mempool with validation, fee prioritization, and nonce gap handling.
"""
import time
import logging
import threading
from collections import defaultdict
from typing import Optional, Callable
from crypto_v2.core import Transaction
from crypto_v2.crypto import public_key_to_address

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mempool configuration
MAX_MEMPOOL_SIZE = 10000
MAX_TXS_PER_ACCOUNT = 100
MIN_FEE = 1
TX_EXPIRY_TIME = 3600  # 1 hour


class Mempool:
    def __init__(self, get_account_state: Optional[Callable] = None):
        """
        Args:
            get_account_state: Function to get account state (address -> dict with 'balance', 'nonce')
        """
        # {sender_address_hex: {nonce: Transaction}}
        self.pending_txs = defaultdict(dict)
        # Track transaction IDs to prevent duplicates
        self.tx_ids = set()
        # Get account state from blockchain
        self.get_account_state = get_account_state
        # Thread-safety
        self.lock = threading.Lock()
        # Statistics
        self.stats = {
            'total_added': 0,
            'total_rejected': 0,
            'total_removed': 0,
        }

    def add_transaction(self, tx: Transaction) -> tuple[bool, str]:
        """
        Adds a transaction to the mempool after validation.
        Returns (success, error_message)
        """
        with self.lock:
            try:
                # Check mempool size limit
                if self.size() >= MAX_MEMPOOL_SIZE:
                    self._evict_low_fee_transactions()
                    if self.size() >= MAX_MEMPOOL_SIZE:
                        self.stats['total_rejected'] += 1
                        return False, "Mempool full"
                
                # Basic validation
                is_valid, error = tx.validate_basic()
                if not is_valid:
                    self.stats['total_rejected'] += 1
                    return False, f"Validation failed: {error}"
                
                # Check minimum fee
                if tx.fee < MIN_FEE:
                    self.stats['total_rejected'] += 1
                    return False, f"Fee too low: {tx.fee} < {MIN_FEE}"
                
                # Check for duplicate transaction ID
                if tx.id in self.tx_ids:
                    self.stats['total_rejected'] += 1
                    return False, "Duplicate transaction"
                
                sender_address = public_key_to_address(tx.sender_public_key).hex()
                
                # Check per-account transaction limit
                if len(self.pending_txs[sender_address]) >= MAX_TXS_PER_ACCOUNT:
                    self.stats['total_rejected'] += 1
                    return False, f"Too many pending transactions for account"
                
                # Prevent duplicate nonce
                if tx.nonce in self.pending_txs[sender_address]:
                    existing_tx = self.pending_txs[sender_address][tx.nonce]
                    # Allow replacement if new fee is higher
                    if tx.fee > existing_tx.fee:
                        logger.info(f"Replacing transaction {existing_tx.id.hex()[:16]} with higher fee")
                        self.tx_ids.remove(existing_tx.id)
                    else:
                        self.stats['total_rejected'] += 1
                        return False, "Duplicate nonce with lower fee"
                
                # Validate against current state if possible
                if self.get_account_state:
                    account = self.get_account_state(bytes.fromhex(sender_address))
                    
                    # Check nonce ordering (allow future nonces for pipelining)
                    if tx.nonce < account['nonce']:
                        self.stats['total_rejected'] += 1
                        return False, f"Nonce too low: {tx.nonce} < {account['nonce']}"
                    
                    # Check if sender has sufficient balance (rough estimate)
                    estimated_cost = tx.fee
                    if tx.tx_type == 'TRANSFER':
                        estimated_cost += tx.data.get('amount', 0)
                    elif tx.tx_type == 'STAKE':
                        estimated_cost += tx.data.get('amount', 0)
                    
                    if account['balance'] < estimated_cost:
                        self.stats['total_rejected'] += 1
                        return False, "Insufficient balance"
                
                # Add transaction
                self.pending_txs[sender_address][tx.nonce] = tx
                self.tx_ids.add(tx.id)
                self.stats['total_added'] += 1
                
                logger.debug(f"Added transaction {tx.id.hex()[:16]} to mempool")
                return True, ""
                
            except Exception as e:
                logger.error(f"Error adding transaction: {e}")
                self.stats['total_rejected'] += 1
                return False, str(e)

    def get_pending_transactions(self, max_txs: int = 1000) -> list[Transaction]:
        """
        Retrieves transactions for block creation, prioritized by fee.
        Returns only executable transactions (no nonce gaps).
        """
        with self.lock:
            if not self.get_account_state:
                # Fallback to simple ordering if no state access
                return self._get_transactions_simple(max_txs)
            
            executable_txs = []
            
            # Get all accounts sorted by their highest fee transaction
            accounts_by_fee = []
            for address_hex in self.pending_txs:
                max_fee = max(tx.fee for tx in self.pending_txs[address_hex].values())
                accounts_by_fee.append((max_fee, address_hex))
            
            accounts_by_fee.sort(reverse=True)
            
            for _, address_hex in accounts_by_fee:
                if len(executable_txs) >= max_txs:
                    break
                
                # Get current nonce for this account
                account = self.get_account_state(bytes.fromhex(address_hex))
                expected_nonce = account['nonce']
                
                # Add consecutive transactions starting from expected nonce
                sorted_nonces = sorted(self.pending_txs[address_hex].keys())
                for nonce in sorted_nonces:
                    if nonce != expected_nonce:
                        break  # Stop at first nonce gap
                    
                    if len(executable_txs) >= max_txs:
                        break
                    
                    tx = self.pending_txs[address_hex][nonce]
                    
                    # Check if transaction hasn't expired
                    if time.time() - tx.timestamp < TX_EXPIRY_TIME:
                        executable_txs.append(tx)
                        expected_nonce += 1
                    else:
                        logger.debug(f"Skipping expired transaction {tx.id.hex()[:16]}")
            
            # Sort by fee (descending) for final ordering
            executable_txs.sort(key=lambda tx: tx.fee, reverse=True)
            
            return executable_txs[:max_txs]

    def _get_transactions_simple(self, max_txs: int) -> list[Transaction]:
        """Simple transaction selection without state validation."""
        txs = []
        
        # Collect all transactions
        all_txs = []
        for address_hex in self.pending_txs:
            for nonce, tx in self.pending_txs[address_hex].items():
                if time.time() - tx.timestamp < TX_EXPIRY_TIME:
                    all_txs.append(tx)
        
        # Sort by fee (descending), then by timestamp (ascending)
        all_txs.sort(key=lambda tx: (-tx.fee, tx.timestamp))
        
        return all_txs[:max_txs]

    def remove_transactions(self, txs: list[Transaction]):
        """Removes transactions from mempool (after block inclusion)."""
        with self.lock:
            for tx in txs:
                sender_address = public_key_to_address(tx.sender_public_key).hex()
                if sender_address in self.pending_txs and tx.nonce in self.pending_txs[sender_address]:
                    del self.pending_txs[sender_address][tx.nonce]
                    self.tx_ids.discard(tx.id)
                    self.stats['total_removed'] += 1
                    
                    if not self.pending_txs[sender_address]:
                        del self.pending_txs[sender_address]

    def remove_transaction_by_id(self, tx_id: bytes) -> bool:
        """Removes a specific transaction by ID."""
        for address_hex in list(self.pending_txs.keys()):
            for nonce, tx in list(self.pending_txs[address_hex].items()):
                if tx.id == tx_id:
                    del self.pending_txs[address_hex][nonce]
                    self.tx_ids.discard(tx_id)
                    self.stats['total_removed'] += 1
                    
                    if not self.pending_txs[address_hex]:
                        del self.pending_txs[address_hex]
                    return True
        return False

    def has_transaction(self, tx_id: bytes) -> bool:
        """Check if transaction exists in mempool."""
        return tx_id in self.tx_ids

    def get_transaction(self, tx_id: bytes) -> Optional[Transaction]:
        """Get a transaction by ID."""
        for address_hex in self.pending_txs:
            for nonce, tx in self.pending_txs[address_hex].items():
                if tx.id == tx_id:
                    return tx
        return None

    def get_pending_nonces(self, address: bytes) -> list[int]:
        """Get all pending nonces for an address."""
        address_hex = address.hex()
        if address_hex in self.pending_txs:
            return sorted(self.pending_txs[address_hex].keys())
        return []

    def size(self) -> int:
        """Returns total number of transactions in mempool."""
        return len(self.tx_ids)

    def clear(self):
        """Clears all transactions from mempool."""
        with self.lock:
            count = self.size()
            self.pending_txs.clear()
            self.tx_ids.clear()
            self.stats['total_removed'] += count
            logger.info(f"Cleared {count} transactions from mempool")

    def clean_expired(self):
        """Removes expired transactions."""
        with self.lock:
            current_time = time.time()
            expired_count = 0
            
            for address_hex in list(self.pending_txs.keys()):
                for nonce in list(self.pending_txs[address_hex].keys()):
                    tx = self.pending_txs[address_hex][nonce]
                    if current_time - tx.timestamp >= TX_EXPIRY_TIME:
                        del self.pending_txs[address_hex][nonce]
                        self.tx_ids.discard(tx.id)
                        expired_count += 1
                
                if not self.pending_txs[address_hex]:
                    del self.pending_txs[address_hex]
            
            if expired_count > 0:
                self.stats['total_removed'] += expired_count
                logger.info(f"Removed {expired_count} expired transactions")

    def _evict_low_fee_transactions(self, target_size: int = None):
        """Evicts lowest fee transactions to make room."""
        if target_size is None:
            target_size = int(MAX_MEMPOOL_SIZE * 0.9)  # Remove 10%
        
        # Collect all transactions with their fees
        all_txs = []
        for address_hex in self.pending_txs:
            for nonce, tx in self.pending_txs[address_hex].items():
                all_txs.append((tx.fee, tx))
        
        # Sort by fee (ascending) to evict lowest fees first
        all_txs.sort(key=lambda x: x[0])
        
        # Evict until we reach target size
        evicted = 0
        for _, tx in all_txs:
            if self.size() <= target_size:
                break
            
            if self.remove_transaction_by_id(tx.id):
                evicted += 1
        
        if evicted > 0:
            logger.info(f"Evicted {evicted} low-fee transactions")

    def get_stats(self) -> dict:
        """Returns mempool statistics."""
        return {
            **self.stats,
            'current_size': self.size(),
            'accounts': len(self.pending_txs),
        }

    def __len__(self):
        """Support len() function."""
        return self.size()