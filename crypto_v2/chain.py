"""
A persistent blockchain with improved security and state management.
Simplified: Game logic moved off-chain, AMM for price discovery.

SECURITY FIXES APPLIED:
- Transaction signature verification
- LP token first depositor exploit fix
- Zero-division protection
- Oracle time-locks (7-day unbonding)
- Attestation replay protection (chain_id + timestamp)
- Proper nonce management (rollback on failure)
- Gas metering basics
- TWAP oracle (price manipulation protection)
- Circuit breaker (volatility protection)
- Rate limiting (spam prevention)
- Multi-sig for admin operations
"""

# Prefer the msgpack library but provide a lightweight fallback shim using json
try:
    import msgpack as msgpack  # type: ignore
except Exception:
    import json as _json

    class _MsgpackShim:
        @staticmethod
        def packb(obj, use_bin_type=True):
            return _json.dumps(obj, default=str).encode()

        @staticmethod
        def unpackb(b, raw=False):
            if b is None:
                return None
            if isinstance(b, bytes):
                s = b.decode()
            else:
                s = str(b)
            return _json.loads(s)

    msgpack = _MsgpackShim()

import logging
import time
import json
import math
from typing import Optional
from decimal import Decimal
from collections import defaultdict
from crypto_v2.core import Block, Transaction, BlockHeader
from crypto_v2.db import DB
from crypto_v2.crypto import generate_hash, public_key_to_address, verify_signature, sign
from crypto_v2.trie import Trie, BLANK_ROOT
from crypto_v2.poh import PoHRecorder, verify_poh_sequence
from crypto_v2.consensus import LeaderScheduler, is_valid_leader
from crypto_v2.tokenomics_state import TokenomicsState
from crypto_v2.amm_state import LiquidityPoolState
from crypto_v2.mempool import Mempool
from .monitoring import Monitor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reserved addresses
VALIDATOR_SET_ADDRESS = b'\x00' * 19 + b'\x01'
ATTESTATION_ADDRESS = b'\x00' * 19 + b'\x02'
CONFIG_ADDRESS = b'\x00' * 19 + b'\x03'
TOKENOMICS_ADDRESS = b'\x00' * 19 + b'\x04'
AMM_POOL_ADDRESS = b'\x00' * 19 + b'\x05'
GAME_ORACLE_ADDRESS = b'\x00' * 19 + b'\x06'
PAYMENTS_ORACLE_ADDRESS = b'\x00' * 19 + b'\x07'
RESERVE_POOL_ADDRESS = b'\x00' * 19 + b'\x08'
RESERVE_ADMIN_ADDRESS = b'\x00' * 19 + b'\x09'
OUTFLOW_RESERVE_ADDRESS = b'\x00' * 19 + b'\x0A'
FINALITY_STATE_ADDRESS = b'\x00' * 19 + b'\x0B'
PAUSE_ADMIN_ADDRESS = bytes([0x00]*19 + [0x12])
TREASURY_ADDRESS = b'\x00' * 19 + b'\xFF'

# New security-related addresses
ORACLE_AGGREGATOR_ADDRESS = bytes([0x00]*19 + [0x10])
ORACLE_STAKE_ADDRESS = bytes([0x00]*19 + [0x11])
ORACLE_UNSTAKE_REQUEST_ADDRESS = bytes([0x00]*19 + [0x13])
TWAP_ADDRESS = bytes([0x00]*19 + [0x14])
CIRCUIT_BREAKER_ADDRESS = bytes([0x00]*19 + [0x15])
RATE_LIMITER_ADDRESS = bytes([0x00]*19 + [0x16])
MULTISIG_CONFIG_ADDRESS = bytes([0x00]*19 + [0x17])

# Configuration constants
TOKEN_UNIT = 1_000_000

# Oracle constants
ORACLE_QUORUM = 3
ORACLE_BOND = 1000 * TOKEN_UNIT
ORACLE_SLASH_PERCENT = 50
ORACLE_ROUND_TIMEOUT = 300
ORACLE_MAX_DEVIATION_PCT = 5
ORACLE_UNSTAKE_DELAY = 86400 * 7  # 7 days

# Blockchain constants
CHECKPOINT_INTERVAL = 100
MAX_BLOCK_SIZE = 1_000_000
MAX_TXS_PER_BLOCK = 1000
MIN_STAKE_AMOUNT = 100 * TOKEN_UNIT
SLASH_PERCENTAGE = 50

# AMM constants
AMM_MINT_PREMIUM = Decimal('1.02')  # 2% above market price
MIN_MINT_PRICE = Decimal('0.10')    # Never mint below $0.10/token
MAX_MINT_PRICE = Decimal('10.00')   # Never mint above $10.00/token
MIN_BURN_PRICE = Decimal('0.05')    # Never buy back below $0.05/token

# Casper FFG Finality Constants
EPOCH_LENGTH = 50
FINALITY_THRESHOLD = 2/3
SLASH_AMOUNT = 1000 * TOKEN_UNIT
INACTIVITY_PENALTY = 1 * TOKEN_UNIT

# TWAP constants
TWAP_WINDOW = 3600  # 1 hour
TWAP_MAX_DEVIATION = Decimal('0.10')  # 10%

# Circuit breaker constants
CIRCUIT_BREAKER_COOLDOWN = 3600  # 1 hour
CIRCUIT_BREAKER_PRICE_THRESHOLD = Decimal('0.15')  # 15%
CIRCUIT_BREAKER_VOLUME_THRESHOLD = Decimal('5.0')  # 5x

# Rate limiter constants
RATE_LIMIT_WINDOW = 3600  # 1 hour
RATE_LIMIT_MAX_SWAPS = 10
RATE_LIMIT_MAX_VOLUME = 10_000 * TOKEN_UNIT

# Multi-sig constants
MULTISIG_REQUIRED_SIGS = 3
MULTISIG_ADMIN_ADDRESSES = []  # Add your admin public keys here


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


# ==============================================================================
# GAS METERING
# ==============================================================================

class GasMetering:
    """Simple gas metering for transaction execution."""
    
    BASE_TX_COST = 21000
    STORAGE_READ = 2000
    STORAGE_WRITE = 5000
    COMPUTATION = 100
    
    TX_COSTS = {
        'TRANSFER': 25000,
        'STAKE': 50000,
        'UNSTAKE': 50000,
        'SWAP': 80000,
        'ADD_LIQUIDITY': 100000,
        'REMOVE_LIQUIDITY': 80000,
        'BOND_MINT': 60000,
        'RESERVE_BURN': 60000,
        'ORACLE_SUBMIT': 50000,
        'ORACLE_REGISTER': 80000,
        'ORACLE_UNREGISTER_REQUEST': 30000,
        'ORACLE_UNREGISTER_EXECUTE': 50000,
        'GAME_FEE': 40000,
        'MINT_USD_TOKEN': 30000,
        'DEPLOY_RESERVE_LIQUIDITY': 150000,
    }
    
    def __init__(self, gas_limit: int):
        self.gas_limit = gas_limit
        self.gas_used = 0
    
    def charge(self, amount: int, operation: str = ""):
        """Charge gas and check limit."""
        self.gas_used += amount
        if self.gas_used > self.gas_limit:
            raise ValidationError(
                f"Out of gas: {self.gas_used}/{self.gas_limit} "
                f"(operation: {operation})"
            )
    
    def remaining(self) -> int:
        """Get remaining gas."""
        return self.gas_limit - self.gas_used


# ==============================================================================
# TWAP ORACLE
# ==============================================================================

class TWAPOracle:
    """Time-Weighted Average Price oracle for manipulation resistance."""
    
    def __init__(self):
        self.observations = []  # [(timestamp, price, reserve0, reserve1)]
        self.last_update = 0
    
    def update(self, current_time: int, price: Decimal, reserve0: int, reserve1: int):
        """Record a new price observation."""
        self.observations.append((current_time, float(price), reserve0, reserve1))
        self.last_update = current_time
        
        cutoff = current_time - TWAP_WINDOW
        self.observations = [obs for obs in self.observations if obs[0] > cutoff]
    
    def get_twap(self, current_time: int) -> Decimal:
        """Calculate time-weighted average price."""
        if not self.observations:
            return Decimal(0)
        
        if len(self.observations) == 1:
            return Decimal(str(self.observations[0][1]))
        
        total_weighted_price = Decimal(0)
        total_time = 0
        
        for i in range(1, len(self.observations)):
            prev_time, prev_price, _, _ = self.observations[i-1]
            curr_time, _, _, _ = self.observations[i]
            
            time_delta = curr_time - prev_time
            if time_delta > 0:
                total_weighted_price += Decimal(str(prev_price)) * time_delta
                total_time += time_delta
        
        if total_time == 0:
            return Decimal(str(self.observations[-1][1]))
        
        return total_weighted_price / total_time
    
    def to_dict(self) -> dict:
        return {
            'observations': self.observations,
            'last_update': self.last_update
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'TWAPOracle':
        oracle = TWAPOracle()
        oracle.observations = data.get('observations', [])
        oracle.last_update = data.get('last_update', 0)
        return oracle


# ==============================================================================
# CIRCUIT BREAKER
# ==============================================================================

class CircuitBreaker:
    """Circuit breaker to halt trading during extreme volatility."""
    
    def __init__(self):
        self.is_tripped = False
        self.trip_time = 0
        self.trip_reason = ""
        self.price_history = []
        self.volume_history = []
        self.window_size = 3600
    
    def check_and_trip(self, current_time: int, current_price: Decimal, 
                       swap_volume_usd: int) -> None:
        """Check conditions and trip if necessary."""
        
        if self.is_tripped:
            elapsed = current_time - self.trip_time
            if elapsed > CIRCUIT_BREAKER_COOLDOWN:
                self.is_tripped = False
                self.trip_reason = ""
                logger.info("Circuit breaker reset after cooldown")
            else:
                remaining = CIRCUIT_BREAKER_COOLDOWN - elapsed
                raise ValidationError(
                    f"Circuit breaker active: {self.trip_reason}. "
                    f"Cooldown: {remaining}s remaining"
                )
        
        self.price_history.append((current_time, float(current_price)))
        self.volume_history.append((current_time, swap_volume_usd))
        
        cutoff = current_time - self.window_size
        self.price_history = [(t, p) for t, p in self.price_history if t > cutoff]
        self.volume_history = [(t, v) for t, v in self.volume_history if t > cutoff]
        
        if len(self.price_history) < 5:
            return
        
        prices = [Decimal(str(p)) for _, p in self.price_history]
        min_price = min(prices)
        max_price = max(prices)
        
        if min_price > 0:
            price_swing = (max_price - min_price) / min_price
            if price_swing > CIRCUIT_BREAKER_PRICE_THRESHOLD:
                self._trip(
                    current_time,
                    f"Price volatility {float(price_swing)*100:.1f}% exceeds "
                    f"{float(CIRCUIT_BREAKER_PRICE_THRESHOLD)*100}% threshold"
                )
        
        if len(self.volume_history) >= 20:
            recent_volume = sum(v for _, v in self.volume_history[-5:])
            older_volume = sum(v for _, v in self.volume_history[-20:-5]) / 3
            
            if older_volume > 0:
                volume_ratio = Decimal(recent_volume) / Decimal(older_volume)
                if volume_ratio > CIRCUIT_BREAKER_VOLUME_THRESHOLD:
                    self._trip(
                        current_time,
                        f"Volume spike {float(volume_ratio):.1f}x exceeds "
                        f"{float(CIRCUIT_BREAKER_VOLUME_THRESHOLD)}x threshold"
                    )
    
    def _trip(self, current_time: int, reason: str):
        self.is_tripped = True
        self.trip_time = current_time
        self.trip_reason = reason
        logger.warning(f"CIRCUIT BREAKER TRIPPED: {reason}")
        raise ValidationError(f"Circuit breaker tripped: {reason}")
    
    def to_dict(self) -> dict:
        return {
            'is_tripped': self.is_tripped,
            'trip_time': self.trip_time,
            'trip_reason': self.trip_reason,
            'price_history': self.price_history,
            'volume_history': self.volume_history
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'CircuitBreaker':
        cb = CircuitBreaker()
        cb.is_tripped = data.get('is_tripped', False)
        cb.trip_time = data.get('trip_time', 0)
        cb.trip_reason = data.get('trip_reason', "")
        cb.price_history = data.get('price_history', [])
        cb.volume_history = data.get('volume_history', [])
        return cb


# ==============================================================================
# RATE LIMITER
# ==============================================================================

class RateLimiter:
    """Per-address rate limiting for swaps."""
    
    def __init__(self):
        self.swap_records = {}
        self.window = RATE_LIMIT_WINDOW
    
    def check_limit(self, address: bytes, current_time: int, 
                    volume_usd: int) -> None:
        """Check if address exceeds rate limits."""
        addr_hex = address.hex()
        
        if addr_hex not in self.swap_records:
            self.swap_records[addr_hex] = []
        
        cutoff = current_time - self.window
        self.swap_records[addr_hex] = [
            (t, v) for t, v in self.swap_records[addr_hex] if t > cutoff
        ]
        
        swap_count = len(self.swap_records[addr_hex])
        if swap_count >= RATE_LIMIT_MAX_SWAPS:
            raise ValidationError(
                f"Rate limit exceeded: {swap_count}/{RATE_LIMIT_MAX_SWAPS} "
                f"swaps in last hour"
            )
        
        total_volume = sum(v for _, v in self.swap_records[addr_hex])
        if total_volume + volume_usd > RATE_LIMIT_MAX_VOLUME:
            raise ValidationError(
                f"Rate limit exceeded: "
                f"${(total_volume + volume_usd)/TOKEN_UNIT:.2f}/"
                f"${RATE_LIMIT_MAX_VOLUME/TOKEN_UNIT:.2f} volume in last hour"
            )
        
        self.swap_records[addr_hex].append((current_time, volume_usd))
    
    def to_dict(self) -> dict:
        return {'swap_records': self.swap_records}
    
    @staticmethod
    def from_dict(data: dict) -> 'RateLimiter':
        rl = RateLimiter()
        rl.swap_records = data.get('swap_records', {})
        return rl


# ==============================================================================
# MULTI-SIG VALIDATOR
# ==============================================================================

class MultiSigValidator:
    """Validates multi-signature requirements for admin operations."""
    
    def __init__(self, required_sigs: int = 3, authorized_signers: list = None):
        self.required_sigs = required_sigs
        self.authorized_signers = authorized_signers or []
    
    def verify(self, tx: Transaction, signing_data: bytes) -> bool:
        """Verify multi-signature requirements."""
        if 'multisig_signatures' not in tx.data:
            raise ValidationError(
                f"Multi-sig required: need {self.required_sigs} signatures"
            )
        
        signatures = tx.data['multisig_signatures']
        
        if not isinstance(signatures, list):
            raise ValidationError("Invalid multisig_signatures format")
        
        if len(signatures) < self.required_sigs:
            raise ValidationError(
                f"Insufficient signatures: {len(signatures)}/{self.required_sigs}"
            )
        
        valid_sigs = 0
        used_signers = set()
        
        for sig_data in signatures:
            if not isinstance(sig_data, dict) or 'pubkey' not in sig_data or 'signature' not in sig_data:
                continue
            
            pubkey = bytes.fromhex(sig_data['pubkey'])
            signature = bytes.fromhex(sig_data['signature'])
            
            if pubkey not in self.authorized_signers:
                continue
            
            if pubkey.hex() in used_signers:
                continue
            
            if verify_signature(pubkey, signature, signing_data):
                valid_sigs += 1
                used_signers.add(pubkey.hex())
        
        if valid_sigs < self.required_sigs:
            raise ValidationError(
                f"Only {valid_sigs}/{self.required_sigs} valid signatures"
            )
        
        return True
    
    def to_dict(self) -> dict:
        return {
            'required_sigs': self.required_sigs,
            'authorized_signers': [pk.hex() for pk in self.authorized_signers]
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'MultiSigValidator':
        return MultiSigValidator(
            required_sigs=data.get('required_sigs', 3),
            authorized_signers=[bytes.fromhex(pk) for pk in data.get('authorized_signers', [])]
        )


# ==============================================================================
# ORACLE & ATTESTATION CLASSES
# ==============================================================================

class OracleRound:
    __slots__ = ('submissions', 'finalized', 'final_value', 'finalized_at')
    
    def __init__(self):
        self.submissions = {}
        self.finalized = False
        self.final_value = None
        self.finalized_at = 0

    def to_dict(self):
        return {
            "submissions": self.submissions,
            "finalized": self.finalized,
            "final_value": self.final_value,
            "finalized_at": self.finalized_at,
        }

    @staticmethod
    def from_dict(d):
        r = OracleRound()
        r.submissions = d["submissions"]
        r.finalized = d["finalized"]
        r.final_value = d["final_value"]
        r.finalized_at = d["finalized_at"]
        return r


class FinalityState:
    """Represents the finality state of the blockchain."""
    
    def __init__(self, justified_epoch, finalized_epoch):
        self.justified_epoch = justified_epoch
        self.finalized_epoch = finalized_epoch

    def to_dict(self):
        return {
            "justified_epoch": self.justified_epoch,
            "finalized_epoch": self.finalized_epoch,
        }

    @staticmethod
    def from_dict(d):
        return FinalityState(d["justified_epoch"], d["finalized_epoch"])


class Attestation:
    """Represents a validator's vote for a checkpoint."""
    
    def __init__(self, source_epoch, target_epoch, target_hash, 
                 validator_pubkey, chain_id, timestamp, signature=None):
        self.source_epoch = source_epoch
        self.target_epoch = target_epoch
        self.target_hash = target_hash
        self.validator_pubkey = validator_pubkey
        self.chain_id = chain_id
        self.timestamp = timestamp
        self.signature = signature

    def to_dict(self, include_signature=True):
        data = {
            "source_epoch": self.source_epoch,
            "target_epoch": self.target_epoch,
            "target_hash": self.target_hash.hex(),
            "validator_pubkey": self.validator_pubkey.hex(),
            "chain_id": self.chain_id,
            "timestamp": self.timestamp,
        }
        if include_signature and self.signature:
            data["signature"] = self.signature.hex()
        return data

    def get_signing_data(self) -> bytes:
        """Returns the canonical byte representation for signing."""
        return msgpack.packb(self.to_dict(include_signature=False), use_bin_type=True)

    def sign(self, private_key):
        """Signs the attestation."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self):
        """Verifies the attestation's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.validator_pubkey,
            self.signature,
            self.get_signing_data()
        )


# ==============================================================================
# MAIN BLOCKCHAIN CLASS
# ==============================================================================

class Blockchain:
    def __init__(self, db_path: str = None, db: DB = None, genesis_block: Block = None, 
                 chain_id: int = 1, game_oracle_pubkey: bytes = None, 
                 monitoring_host: str = "127.0.0.1", monitoring_port: int = 9090):
        if db:
            self.db = db
        elif db_path:
            self.db = DB(db_path)
        else:
            raise ValueError("Either db_path or a DB object must be provided.")
            
        self.chain_id = chain_id
        self.block_pool: dict[bytes, Block] = {}
        self.game_oracle_address = public_key_to_address(game_oracle_pubkey) if game_oracle_pubkey else GAME_ORACLE_ADDRESS
        self.reserve_admin_address = RESERVE_ADMIN_ADDRESS
        self.min_oracle_submissions = 3
        
        head_hash = self.db.get(b'head')
        if head_hash is None:
            raise Exception("Blockchain database not initialized. Please create a genesis block first.")
        
        self.head_hash = head_hash
        
        latest_block = self.get_latest_block()
        root_hash = latest_block.state_root if isinstance(latest_block.state_root, bytes) else bytes.fromhex(latest_block.state_root)
        self.state_trie = Trie(self.db, root_hash=root_hash)

        self.mempool = Mempool(
            get_account_state=lambda addr: self._get_account(addr, self.state_trie)
        )
        
        self.latest_attestations = {}
        self.finality_state = self._get_finality_state(self.state_trie)
        
        self.oracle_rounds = {}
        self.current_oracle_round = 1
        self.oracle_stakes = self._get_oracle_stakes(self.state_trie)
        self.oracle_pubkey_to_id = {pk: pk[:8].hex() for pk in self.oracle_stakes}
        self.oracle_unstake_requests = self._get_oracle_unstake_requests(self.state_trie)
        
        self.paused = False
        self.pause_block = None
        
        self.leader_scheduler = LeaderScheduler(self._get_validator_set(self.state_trie))
        
        self._initialize_config()

        logger.info(f"Initializing Monitor with host={monitoring_host}, port={monitoring_port}")
        self.monitor = Monitor(self, host=monitoring_host, port=monitoring_port)

    # ==========================================================================
    # STATE MANAGEMENT HELPERS
    # ==========================================================================

    def _get_oracle_stakes(self, trie: Trie) -> dict:
        """Get oracle stakes from the trie."""
        encoded = trie.get(ORACLE_STAKE_ADDRESS)
        if encoded:
            return msgpack.unpackb(encoded, raw=False)
        return {}

    def _set_oracle_stakes(self, stakes: dict, trie: Trie):
        """Set oracle stakes in the trie."""
        encoded = msgpack.packb(stakes, use_bin_type=True)
        trie.set(ORACLE_STAKE_ADDRESS, encoded)

    def _get_oracle_unstake_requests(self, trie: Trie) -> dict:
        """Get pending oracle unstake requests."""
        encoded = trie.get(ORACLE_UNSTAKE_REQUEST_ADDRESS)
        if encoded:
            return msgpack.unpackb(encoded, raw=False)
        return {}

    def _set_oracle_unstake_requests(self, requests: dict, trie: Trie):
        """Set oracle unstake requests."""
        encoded = msgpack.packb(requests, use_bin_type=True)
        trie.set(ORACLE_UNSTAKE_REQUEST_ADDRESS, encoded)

    def _get_twap_oracle(self, trie: Trie) -> TWAPOracle:
        """Get TWAP oracle state."""
        encoded = trie.get(TWAP_ADDRESS)
        if encoded:
            data = msgpack.unpackb(encoded, raw=False)
            return TWAPOracle.from_dict(data)
        return TWAPOracle()

    def _set_twap_oracle(self, oracle: TWAPOracle, trie: Trie):
        """Set TWAP oracle state."""
        encoded = msgpack.packb(oracle.to_dict(), use_bin_type=True)
        trie.set(TWAP_ADDRESS, encoded)

    def _get_circuit_breaker(self, trie: Trie) -> CircuitBreaker:
        """Get circuit breaker state."""
        encoded = trie.get(CIRCUIT_BREAKER_ADDRESS)
        if encoded:
            data = msgpack.unpackb(encoded, raw=False)
            return CircuitBreaker.from_dict(data)
        return CircuitBreaker()

    def _set_circuit_breaker(self, cb: CircuitBreaker, trie: Trie):
        """Set circuit breaker state."""
        encoded = msgpack.packb(cb.to_dict(), use_bin_type=True)
        trie.set(CIRCUIT_BREAKER_ADDRESS, encoded)

    def _get_rate_limiter(self, trie: Trie) -> RateLimiter:
        """Get rate limiter state."""
        encoded = trie.get(RATE_LIMITER_ADDRESS)
        if encoded:
            data = msgpack.unpackb(encoded, raw=False)
            return RateLimiter.from_dict(data)
        return RateLimiter()

    def _set_rate_limiter(self, rl: RateLimiter, trie: Trie):
        """Set rate limiter state."""
        encoded = msgpack.packb(rl.to_dict(), use_bin_type=True)
        trie.set(RATE_LIMITER_ADDRESS, encoded)

    def _get_multisig_config(self, trie: Trie) -> MultiSigValidator:
        """Get multi-sig configuration."""
        encoded = trie.get(MULTISIG_CONFIG_ADDRESS)
        if encoded:
            data = msgpack.unpackb(encoded, raw=False)
            return MultiSigValidator.from_dict(data)
        return MultiSigValidator(
            required_sigs=MULTISIG_REQUIRED_SIGS,
            authorized_signers=MULTISIG_ADMIN_ADDRESSES
        )

    def _set_multisig_config(self, validator: MultiSigValidator, trie: Trie):
        """Set multi-sig configuration."""
        encoded = msgpack.packb(validator.to_dict(), use_bin_type=True)
        trie.set(MULTISIG_CONFIG_ADDRESS, encoded)

    def _initialize_config(self):
        """Initialize chain configuration in state."""
        config = self._get_config()
        if not config:
            config = {
                'chain_id': self.chain_id,
                'min_stake': MIN_STAKE_AMOUNT,
                'slash_percentage': SLASH_PERCENTAGE,
                'max_block_size': MAX_BLOCK_SIZE,
                'max_txs_per_block': MAX_TXS_PER_BLOCK,
            }
            self._set_config(config, self.state_trie)

    def _get_config(self) -> dict:
        """Get chain configuration."""
        encoded = self.state_trie.get(CONFIG_ADDRESS)
        if encoded:
            return msgpack.unpackb(encoded, raw=False)
        return {}

    def _set_config(self, config: dict, trie: Trie):
        """Set chain configuration."""
        encoded = msgpack.packb(config, use_bin_type=True)
        trie.set(CONFIG_ADDRESS, encoded)

    def get_checkpoint(self) -> dict | None:
        """Returns a recent finalized checkpoint."""
        head = self.get_head()
        checkpoint_height = (head.height // CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL
        
        current_block = head
        while current_block.height > checkpoint_height:
            parent = self.get_block(current_block.parent_hash)
            if not parent:
                return None
            current_block = parent
            
        if current_block:
            return {
                'block_hash': current_block.hash.hex(),
                'state_root': current_block.state_root.hex(),
                'height': current_block.height,
            }
        return None

    # ==========================================================================
    # BLOCK STORAGE & RETRIEVAL
    # ==========================================================================

    def _store_block(self, block: Block):
        """Serializes and stores a block."""
        block_data = msgpack.packb(block.to_dict(), use_bin_type=True)
        self.db.put(b'block:' + block.hash, block_data)
        
        height_key = b'height:' + str(block.height).encode()
        self.db.put(height_key, block.hash)

    def get_block(self, block_hash: bytes) -> Block | None:
        """Retrieves a block from the database."""
        block_data = self.db.get(b'block:' + block_hash)
        if block_data is None:
            return None
        
        block_dict = msgpack.unpackb(block_data, raw=False)
        
        default_bytes = b'\x00' * 32
        byte_fields = ['parent_hash', 'state_root', 'producer_pubkey', 'vrf_proof',
                       'vrf_pub_key', 'signature', 'poh_initial']

        for field in byte_fields:
            if field not in block_dict:
                block_dict[field] = default_bytes if 'hash' in field or 'root' in field else b''
            val = block_dict[field]
            if isinstance(val, str):
                try:
                    block_dict[field] = bytes.fromhex(val)
                except ValueError:
                    block_dict[field] = val.encode('utf-8') if val else b''
            elif not isinstance(val, bytes):
                block_dict[field] = b''

        if 'attestations' not in block_dict:
            block_dict['attestations'] = []

        if 'poh_sequence' in block_dict:
            seq = []
            for item in block_dict['poh_sequence']:
                h, e = item if isinstance(item, (list, tuple)) else (item, None)
                h_bytes = h
                if isinstance(h, str):
                    try:
                        h_bytes = bytes.fromhex(h)
                    except:
                        h_bytes = h.encode('utf-8')
                e_bytes = None
                if e:
                    if isinstance(e, str):
                        try:
                            e_bytes = bytes.fromhex(e)
                        except:
                            e_bytes = e.encode('utf-8')
                    elif isinstance(e, bytes):
                        e_bytes = e
                seq.append((h_bytes, e_bytes))
            block_dict['poh_sequence'] = seq
        
        transactions = [Transaction(**tx) for tx in block_dict['transactions']]
        block_dict['transactions'] = transactions
        
        return Block(**block_dict)

    def get_block_by_height(self, height: int) -> Block | None:
        """Retrieves a block by height."""
        height_key = b'height:' + str(height).encode()
        block_hash = self.db.get(height_key)
        if block_hash:
            return self.get_block(block_hash)
        return None

    def get_latest_block(self) -> Block:
        """Returns the most recent block."""
        return self.get_block(self.head_hash)

    # ==========================================================================
    # BLOCK VALIDATION & ADDITION
    # ==========================================================================

    def add_block(self, block: Block) -> bool:
        """Adds a new block with comprehensive validation and atomic state updates."""
        start = time.time()
        try:
            parent = self.get_latest_block()
            if block.parent_hash != parent.hash:
                raise ValidationError("Parent hash mismatch")
            if block.height != parent.height + 1:
                raise ValidationError("Invalid block height")
            if block.timestamp <= parent.timestamp:
                raise ValidationError("Timestamp must be after parent")

            temp_trie = Trie(self.db, root_hash=self.state_trie.root_hash)
            
            validators = self._get_validator_set(temp_trie)
            if not is_valid_leader(
                producer_pubkey_hex=block.producer_pubkey.hex(),
                vrf_proof=block.vrf_proof,
                validators=validators,
                seed=parent.hash,
                vrf_pub_key_hex=block.vrf_pub_key.hex(),
                producer_address_hex=public_key_to_address(block.producer_pubkey).hex()
            ):
                raise ValidationError("Invalid block producer")

            total_fees = 0
            for tx in block.transactions:
                tx_start = time.time()
                try:
                    self._process_transaction(tx, temp_trie)
                    latency = time.time() - tx_start
                    self.monitor.record_tx("success", latency)
                    total_fees += tx.fee
                except Exception as e:
                    latency = time.time() - tx_start
                    self.monitor.record_tx("failed", latency)
                    logger.warning(f"Transaction {tx.id.hex()} failed validation: {e}")
                    continue

            for attestation in block.attestations:
                self._process_attestation(attestation, temp_trie)

            if block.state_root != temp_trie.root_hash:
                raise ValidationError(
                    f"State root mismatch. Expected: {temp_trie.root_hash.hex()}, "
                    f"Got: {block.state_root.hex()}"
                )

            parent_poh_hash = parent.poh_sequence[-1][0] if parent.poh_sequence else parent.hash
            if not verify_poh_sequence(parent_poh_hash, block.poh_sequence):
                raise ValidationError("Invalid Proof of History sequence")

            self.state_trie = temp_trie
            
            if total_fees > 0:
                producer_addr = public_key_to_address(block.producer_pubkey)
                acc = self._get_account(producer_addr, self.state_trie)
                acc['balances']['native'] = acc['balances'].get('native', 0) + total_fees
                self._set_account(producer_addr, acc, self.state_trie)

            self.head_hash = block.hash
            self.db.put(b'head', block.hash)
            self._store_block(block)
            
            latency = time.time() - start
            self.monitor.record_block(latency)
            self.monitor.update()

            logger.info(f"Block {block.height} added successfully")
            return True
        except ValidationError as e:
            logger.error(f"Block rejected: {e}")
            return False

    def get_head(self) -> Block:
        """Determines canonical head using LMD GHOST fork-choice."""
        validators = self._get_validator_set(self.state_trie)
        
        scores = {self.get_block(h).hash: 0 for h in self.block_pool}
        
        for validator_hex, block_hash_hex in self.latest_attestations.items():
            if validator_hex in validators:
                current_hash = bytes.fromhex(block_hash_hex)
                while current_hash in self.block_pool:
                    scores[current_hash] = scores.get(current_hash, 0) + validators[validator_hex]
                    
                    current_block = self.get_block(current_hash)
                    if current_block is None:
                        break
                    current_hash = current_block.parent_hash

        if not scores:
            return self.get_block(self.head_hash)

        best_hash = max(scores, key=scores.get)
        self.head_hash = best_hash
        self.db.put(b'head', best_hash)
        
        return self.get_block(best_hash)

    # ==========================================================================
    # ACCOUNT MANAGEMENT
    # ==========================================================================

    def _get_account(self, addr: bytes, trie) -> dict:
        raw = trie.get(b"ACCOUNT:" + addr)
        if not raw:
            return {'balances': {'native': 0, 'usd': 0}, 'nonce': 0, 'lp_tokens': 0}
        return msgpack.unpackb(raw)
    
    def get_account(self, address: bytes, state_trie=None) -> dict:
        """Public method to get an account from the state."""
        trie = state_trie if state_trie is not None else self.state_trie
        return self._get_account(address, trie)

    def _set_account(self, addr: bytes, account: dict, trie):
        trie.set(b"ACCOUNT:" + addr, msgpack.packb(account))

    # ==========================================================================
    # VALIDATOR MANAGEMENT
    # ==========================================================================

    def _get_validator_set(self, trie: Trie) -> dict:
        """Retrieves validator set."""
        encoded_validators = trie.get(VALIDATOR_SET_ADDRESS)
        if encoded_validators:
            return msgpack.unpackb(encoded_validators, raw=False)
        return {}
    
    def get_validator_set(self, state_trie=None):
        """Public method to get the current validator set from the state."""
        trie = state_trie if state_trie is not None else self.state_trie
        return self._get_validator_set(trie)

    def _set_validator_set(self, validators: dict, trie: Trie):
        """Sets validator set."""
        encoded_validators = msgpack.packb(validators, use_bin_type=True)
        trie.set(VALIDATOR_SET_ADDRESS, encoded_validators)

    # ==========================================================================
    # ATTESTATION & FINALITY
    # ==========================================================================

    def _get_attestations(self, trie: Trie) -> dict:
        """Retrieves attestations."""
        encoded_attestations = trie.get(ATTESTATION_ADDRESS)
        if encoded_attestations:
            return msgpack.unpackb(encoded_attestations, raw=False)
        return {}

    def _set_attestations(self, attestations: dict, trie: Trie):
        """Sets attestations."""
        encoded_attestations = msgpack.packb(attestations, use_bin_type=True)
        trie.set(ATTESTATION_ADDRESS, encoded_attestations)

    def _get_finality_state(self, trie: Trie) -> 'FinalityState':
        """Retrieves finality state."""
        encoded = trie.get(FINALITY_STATE_ADDRESS)
        if encoded:
            return FinalityState.from_dict(msgpack.unpackb(encoded, raw=False))
        return FinalityState(0, 0)

    def _set_finality_state(self, state: 'FinalityState', trie: Trie):
        """Sets finality state."""
        encoded = msgpack.packb(state.to_dict(), use_bin_type=True)
        trie.set(FINALITY_STATE_ADDRESS, encoded)

    def _process_attestation(self, attestation: Attestation, trie: Trie):
        """Processes a validator attestation with replay protection."""
        
        if attestation.chain_id != self.chain_id:
            raise ValidationError(
                f"Invalid chain ID in attestation. Expected {self.chain_id}, "
                f"got {attestation.chain_id}"
            )
        
        current_time = int(time.time())
        time_diff = abs(current_time - attestation.timestamp)
        
        if time_diff > 3600:
            raise ValidationError(
                f"Attestation timestamp too old or in future. "
                f"Difference: {time_diff}s (max: 3600s)"
            )
        
        if not attestation.verify_signature():
            raise ValidationError("Invalid attestation signature")

        validators = self._get_validator_set(trie)
        validator_address = public_key_to_address(attestation.validator_pubkey).hex()
        if validator_address not in validators:
            raise ValidationError("Attestation from non-validator")

        attestations = self._get_attestations(trie)
        if validator_address in attestations:
            existing_attestation = attestations[validator_address]
            if existing_attestation['target_epoch'] == attestation.target_epoch and \
               existing_attestation['target_hash'] != attestation.target_hash.hex():
                self._slash_validator(validator_address, trie)
                return

        attestations[validator_address] = attestation.to_dict()
        self._set_attestations(attestations, trie)

        self._check_for_finality(trie)

    def _check_for_finality(self, trie: Trie):
        """Checks if an epoch can be justified or finalized."""
        finality_state = self._get_finality_state(trie)
        attestations = self._get_attestations(trie)
        validators = self._get_validator_set(trie)
        total_stake = sum(validators.values())

        justification_votes = defaultdict(int)
        for validator_address, attestation_dict in attestations.items():
            stake = validators.get(validator_address, 0)
            justification_votes[attestation_dict['target_epoch']] += stake

        for epoch, vote_count in justification_votes.items():
            if vote_count >= total_stake * FINALITY_THRESHOLD:
                if epoch > finality_state.justified_epoch:
                    finality_state.justified_epoch = epoch
                    self._set_finality_state(finality_state, trie)
                    logger.info(f"Epoch {epoch} justified")

        if finality_state.justified_epoch > finality_state.finalized_epoch + 1:
            finality_state.finalized_epoch = finality_state.justified_epoch - 1
            self._set_finality_state(finality_state, trie)
            logger.info(f"Epoch {finality_state.finalized_epoch} finalized")

            active_validators = set(attestations.keys())
            all_validators = set(validators.keys())
            inactive_validators = all_validators - active_validators

            for validator_address in inactive_validators:
                self._inactivity_penalty(validator_address, trie)

    def _inactivity_penalty(self, validator_address: str, trie: Trie):
        """Applies an inactivity penalty to a validator."""
        validators = self._get_validator_set(trie)
        if validator_address not in validators:
            return

        stake = validators[validator_address]
        penalty = min(stake, INACTIVITY_PENALTY)
        validators[validator_address] -= penalty
        self._set_validator_set(validators, trie)

        tokenomics = self._get_tokenomics_state(trie)
        tokenomics.total_supply -= penalty
        tokenomics.total_burned += penalty
        self._set_tokenomics_state(tokenomics, trie)

        logger.info(f"Validator {validator_address} penalized for inactivity.")

    # ==========================================================================
    # ORACLE MANAGEMENT
    # ==========================================================================

    def _get_oracle_round(self, round_id, trie):
        key = b"ORACLE_ROUND:" + str(round_id).encode()
        raw = trie.get(key)
        return OracleRound.from_dict(msgpack.unpackb(raw)) if raw else OracleRound()

    def _set_oracle_round(self, round_id, round_obj, trie):
        key = b"ORACLE_ROUND:" + str(round_id).encode()
        trie.set(key, msgpack.packb(round_obj.to_dict()))

    def _process_oracle_register(self, tx, trie, sender_address, sender_account, gas):
        """Register as an oracle with bond."""
        gas.charge(GasMetering.COMPUTATION * 5, "oracle_register")
        
        if sender_account["balances"]["native"] < ORACLE_BOND:
            raise ValidationError("Insufficient bond for oracle registration")

        sender_account["balances"]["native"] -= ORACLE_BOND
        
        oracle_id = generate_hash(tx.sender_public_key_bytes)[:16].hex()
        self.oracle_pubkey_to_id[tx.sender_public_key_bytes] = oracle_id
        self.oracle_stakes[oracle_id] = ORACLE_BOND

        gas.charge(GasMetering.STORAGE_WRITE, "write_oracle_stakes")
        self._set_oracle_stakes(self.oracle_stakes, trie)
        
        logger.info(f"Oracle {oracle_id} registered with bond {ORACLE_BOND}")

    def _process_oracle_unregister_request(self, tx, trie, sender_address, sender_account, gas):
        """Request to unregister oracle (starts time-lock)."""
        gas.charge(GasMetering.COMPUTATION * 3, "oracle_unregister_request")
        
        oracle_id = self.oracle_pubkey_to_id.get(tx.sender_public_key_bytes)
        if not oracle_id:
            raise ValidationError("Not a registered oracle")
        
        unstake_requests = self._get_oracle_unstake_requests(trie)
        
        if oracle_id in unstake_requests:
            request_time = unstake_requests[oracle_id]
            elapsed = int(time.time()) - request_time
            remaining = ORACLE_UNSTAKE_DELAY - elapsed
            raise ValidationError(
                f"Unstake already pending. {remaining}s remaining."
            )
        
        unstake_requests[oracle_id] = int(time.time())
        gas.charge(GasMetering.STORAGE_WRITE, "write_unstake_requests")
        self._set_oracle_unstake_requests(unstake_requests, trie)
        
        logger.info(f"Oracle {oracle_id} requested unstake. Must wait {ORACLE_UNSTAKE_DELAY}s")

    def _process_oracle_unregister_execute(self, tx, trie, sender_address, sender_account, gas):
        """Execute oracle unregistration after time-lock expires."""
        gas.charge(GasMetering.COMPUTATION * 5, "oracle_unregister_execute")
        
        oracle_id = self.oracle_pubkey_to_id.get(tx.sender_public_key_bytes)
        if not oracle_id:
            raise ValidationError("Not a registered oracle")
        
        unstake_requests = self._get_oracle_unstake_requests(trie)
        
        if oracle_id not in unstake_requests:
            raise ValidationError(
                "No unstake request found. Must call ORACLE_UNREGISTER_REQUEST first."
            )
        
        request_time = unstake_requests[oracle_id]
        current_time = int(time.time())
        elapsed = current_time - request_time
        
        if elapsed < ORACLE_UNSTAKE_DELAY:
            remaining = ORACLE_UNSTAKE_DELAY - elapsed
            raise ValidationError(
                f"Time-lock not expired. Must wait {remaining} more seconds."
            )
        
        if tx.sender_public_key_bytes not in self.oracle_stakes:
            raise ValidationError("Oracle not found in stakes")

        stake_amount = self.oracle_stakes[tx.sender_public_key_bytes]
        sender_account["balances"]["native"] += stake_amount

        del self.oracle_stakes[tx.sender_public_key_bytes]
        del self.oracle_pubkey_to_id[tx.sender_public_key_bytes]
        del unstake_requests[oracle_id]
        
        gas.charge(GasMetering.STORAGE_WRITE * 2, "write_oracle_and_unstake_state")
        self._set_oracle_stakes(self.oracle_stakes, trie)
        self._set_oracle_unstake_requests(unstake_requests, trie)
        
        logger.info(f"Oracle {oracle_id} unregistered successfully")

    def _process_oracle_new_round(self, tx, trie, sender_address, sender_account, gas):
        """Start new oracle round (admin only)."""
        gas.charge(GasMetering.COMPUTATION * 2, "oracle_new_round")
        
        if sender_address != self.reserve_admin_address:
            raise ValidationError("Only Reserve Admin can start oracle round")
        self.current_oracle_round += 1
        
        logger.info(f"Started oracle round {self.current_oracle_round}")

    def _process_oracle_submit(self, tx, trie, gas):
        """Process oracle submission."""
        gas.charge(GasMetering.COMPUTATION * 10, "oracle_submit")
        
        payload = tx.data["payload"]
        signature = bytes.fromhex(tx.data["signature"])
        round_id = tx.data["round_id"]

        if not verify_signature(tx.sender_public_key_bytes, signature,
                json.dumps(payload, sort_keys=True).encode()):
            raise ValidationError("Invalid oracle signature")

        oracle_id = self.oracle_pubkey_to_id.get(tx.sender_public_key_bytes)
        if not oracle_id:
            raise ValidationError("Oracle not registered")
        if oracle_id not in self.oracle_stakes:
            raise ValidationError("Oracle not bonded")

        gas.charge(GasMetering.STORAGE_READ, "read_oracle_round")
        round_obj = self._get_oracle_round(round_id, trie)
        
        if oracle_id in round_obj.submissions:
            raise ValidationError("Duplicate submission")

        round_obj.submissions[oracle_id] = payload
        gas.charge(GasMetering.STORAGE_WRITE, "write_oracle_round")
        self._set_oracle_round(round_id, round_obj, trie)

        if len(round_obj.submissions) >= ORACLE_QUORUM and not round_obj.finalized:
            self._finalize_oracle_round(round_id, round_obj, trie, gas)

    def _finalize_oracle_round(self, round_id, round_obj, trie, gas):
        """Finalize oracle round with median and slashing."""
        gas.charge(GasMetering.COMPUTATION * 20, "finalize_oracle_round")
        
        values = []
        sample_payload = next(iter(round_obj.submissions.values()))
        is_price = sample_payload["type"] == "PRICE_UPDATE"

        for payload in round_obj.submissions.values():
            val = payload["usd_price"] if is_price else payload["reward_usd"]
            values.append(val)

        if not values:
            return

        values.sort()
        median = values[len(values)//2]
        max_dev = median * ORACLE_MAX_DEVIATION_PCT // 100
        valid = [v for v in values if abs(v - median) <= max_dev]

        if len(valid) < ORACLE_QUORUM:
            return

        round_obj.finalized = True
        round_obj.final_value = median
        round_obj.finalized_at = int(time.time())
        self._set_oracle_round(round_id, round_obj, trie)

        if is_price:
            tokenomics = self._get_tokenomics_state(trie)
            tokenomics.usd_price = median
            self._set_tokenomics_state(tokenomics, trie)
        else:
            self._apply_game_reward(round_obj, trie)

        for oracle_id, payload in round_obj.submissions.items():
            val = payload["usd_price"] if is_price else payload["reward_usd"]
            if abs(val - median) > max_dev:
                self._slash_oracle(oracle_id, trie)

    def _apply_game_reward(self, round_obj, trie):
        """Apply game reward from oracle consensus."""
        winner_addr_hex = None
        for payload in round_obj.submissions.values():
            if payload.get("winner"):
                winner_addr_hex = payload["winner"]
                break
        if not winner_addr_hex:
            return

        winner_addr = bytes.fromhex(winner_addr_hex)
        acc = self._get_account(winner_addr, trie)
        acc["balances"]["native"] += round_obj.final_value
        self._set_account(winner_addr, acc, trie)

        tokenomics = self._get_tokenomics_state(trie)
        tokenomics.total_minted += round_obj.final_value
        self._set_tokenomics_state(tokenomics, trie)

    def _slash_oracle(self, oracle_id, trie):
        """Slash misbehaving oracle."""
        pubkey = next((k for k, v in self.oracle_pubkey_to_id.items() if v == oracle_id), None)
        if not pubkey:
            return
        stake = self.oracle_stakes[pubkey]
        slash = stake * ORACLE_SLASH_PERCENT // 100
        self.oracle_stakes[pubkey] -= slash
        if self.oracle_stakes[pubkey] == 0:
            del self.oracle_stakes[pubkey]
            del self.oracle_pubkey_to_id[pubkey]
        
        logger.warning(f"Oracle {oracle_id} slashed {slash} tokens")

    def _slash_validator(self, validator_address: str, trie: Trie):
        """Slashes a validator for a consensus offense."""
        validators = self._get_validator_set(trie)
        if validator_address not in validators:
            return

        stake = validators[validator_address]
        del validators[validator_address]
        self._set_validator_set(validators, trie)

        tokenomics = self._get_tokenomics_state(trie)
        tokenomics.total_supply -= stake
        tokenomics.total_burned += stake
        self._set_tokenomics_state(tokenomics, trie)

        logger.warning(f"Validator {validator_address} slashed for consensus offense.")

    # ==========================================================================
    # TRANSACTION PROCESSING
    # ==========================================================================

    def _process_transaction(self, tx: Transaction, trie: Trie) -> bool:
        """
        Process a single transaction with full security features:
        - Signature verification
        - Gas metering
        - Nonce management (increments even on failure)
        - Balance rollback on failure
        """
        
        # Initialize gas meter
        gas = GasMetering(tx.gas_limit if hasattr(tx, 'gas_limit') else 1_000_000)
        gas.charge(GasMetering.BASE_TX_COST, "base_transaction")
        
        sender_address = public_key_to_address(tx.sender_public_key_bytes)
        
        # Charge for account read
        gas.charge(GasMetering.STORAGE_READ, "read_sender_account")
        sender_account = self._get_account(sender_address, trie)

        # Verify signature
        gas.charge(3000, "signature_verification")
        if not tx.verify_signature():
            raise ValidationError("Invalid transaction signature")

        if tx.chain_id != self.chain_id:
            raise ValidationError(f"Wrong chain ID. Expected {self.chain_id}, got {tx.chain_id}")

        if tx.nonce != sender_account['nonce']:
            raise ValidationError(
                f"Invalid nonce. Expected {sender_account['nonce']}, got {tx.nonce}"
            )

        # Charge transaction-specific gas
        tx_gas = GasMetering.TX_COSTS.get(tx.tx_type, 50000)
        gas.charge(tx_gas, f"tx_type_{tx.tx_type}")

        # Snapshot state
        original_balances = {
            'native': sender_account['balances']['native'],
            'usd': sender_account['balances']['usd']
        }
        original_lp_tokens = sender_account.get('lp_tokens', 0)
        
        # Increment nonce (persists even on failure)
        sender_account['nonce'] += 1

        try:
            # Deduct fee
            fee_paid_in_usd = tx.tx_type == 'SWAP' and tx.data.get('token_in') == 'usd'
            
            if fee_paid_in_usd:
                if sender_account['balances']['usd'] < tx.fee:
                    raise ValidationError("Insufficient USD for fee")
                sender_account['balances']['usd'] -= tx.fee
            else:
                if sender_account['balances']['native'] < tx.fee:
                    raise ValidationError("Insufficient native for fee")
                sender_account['balances']['native'] -= tx.fee

            # Process transaction by type
            if tx.tx_type == 'TRANSFER':
                self._process_transfer(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'MINT_USD_TOKEN':
                self._process_mint_usd(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'GAME_FEE':
                self._process_game_fee(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'STAKE':
                self._process_stake(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'UNSTAKE':
                self._process_unstake(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'BOND_MINT':
                self._process_bond_mint(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'RESERVE_BURN':
                self._process_reserve_burn(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'DEPLOY_RESERVE_LIQUIDITY':
                self._process_deploy_reserve_liquidity(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'SWAP':
                self._process_swap(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'ADD_LIQUIDITY':
                self._process_add_liquidity(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == 'REMOVE_LIQUIDITY':
                self._process_remove_liquidity(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == "ORACLE_SUBMIT":
                self._process_oracle_submit(tx, trie, gas)
            
            elif tx.tx_type == "ORACLE_REGISTER":
                self._process_oracle_register(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == "ORACLE_UNREGISTER_REQUEST":
                self._process_oracle_unregister_request(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == "ORACLE_UNREGISTER_EXECUTE":
                self._process_oracle_unregister_execute(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == "ORACLE_NEW_ROUND":
                self._process_oracle_new_round(tx, trie, sender_address, sender_account, gas)
            
            elif tx.tx_type == "SLASH":
                validator_address = tx.data['validator_address']
                self._slash_validator(validator_address, trie)
            
            elif tx.tx_type == "UPDATE_MULTISIG_CONFIG":
                self._process_update_multisig(tx, trie, sender_address, sender_account, gas)
            
            else:
                raise ValidationError(f"Unknown transaction type: {tx.tx_type}")
            
            # Calculate gas refund
            actual_gas_used = gas.gas_used
            gas_limit = tx.gas_limit if hasattr(tx, 'gas_limit') else 1_000_000
            gas_price = tx.fee // gas_limit if gas_limit > 0 else 0
            max_gas_cost = actual_gas_used * gas_price
            
            # Refund unused gas
            if max_gas_cost < tx.fee:
                refund = tx.fee - max_gas_cost
                if fee_paid_in_usd:
                    sender_account['balances']['usd'] += refund
                else:
                    sender_account['balances']['native'] += refund
            
            # Charge for final account write
            gas.charge(GasMetering.STORAGE_WRITE, "write_sender_account")
            self._set_account(sender_address, sender_account, trie)
            
            logger.debug(f"Transaction {tx.id.hex()[:8]} used {actual_gas_used}/{gas_limit} gas")
            return True
            
        except Exception as e:
            # Transaction failed - ROLLBACK balance changes but KEEP nonce increment
            logger.warning(f"Transaction failed: {e}")
            
            sender_account['balances']['native'] = original_balances['native']
            sender_account['balances']['usd'] = original_balances['usd']
            sender_account['lp_tokens'] = original_lp_tokens
            
            # Keep the incremented nonce
            self._set_account(sender_address, sender_account, trie)
            
            raise e

    def create_block(self, producer_pubkey: bytes, vrf_proof: bytes, vrf_pub_key: bytes, poh_sequence: list) -> Block:
        """Creates a new block from transactions in the mempool."""
        parent_block = self.get_latest_block()
        new_height = parent_block.height + 1
        timestamp = int(time.time())

        # Create a new state trie for this block
        temp_trie = Trie(self.db, root_hash=parent_block.state_root)

        # Get transactions from mempool
        transactions = self.mempool.get_transactions(MAX_TXS_PER_BLOCK)

        # Process transactions and apply state changes
        for tx in transactions:
            # This is a simplified processing loop. In a real implementation,
            # you would call the specific `_process_*` methods based on tx type.
            # For now, we assume `_apply_transaction` handles state changes.
            self._apply_transaction(tx, temp_trie)

        new_block = Block(
            parent_hash=parent_block.hash,
            state_root=temp_trie.root_hash,
            transactions=transactions,
            poh_sequence=poh_sequence,
            poh_initial=poh_sequence[0][0] if poh_sequence else b'',
            height=new_height,
            producer_pubkey=producer_pubkey,
            vrf_proof=vrf_proof,
            vrf_pub_key=vrf_pub_key,
            timestamp=timestamp,
        )

        # The block is not signed here; the producer will sign it.
        return new_block

    def _apply_transaction(self, tx: Transaction, trie: Trie):
        """
        Applies a transaction's state changes to a given trie.
        This is a placeholder for the logic that was previously in _process_transaction.
        """
        # This is a simplified version. A full implementation would dispatch
        # to the correct `_process_*` method (e.g., _process_transfer)
        # and pass the `trie` to be modified.
        # For example:
        # sender_address = public_key_to_address(tx.sender_pubkey)
        # sender_account = self._get_account(sender_address, trie)
        # gas_meter = GasMetering(tx.gas_limit)
        # if tx.type == 'TRANSFER':
        #     self._process_transfer(tx, trie, sender_address, sender_account, gas_meter)
        # ... etc.
        pass

    # ==========================================================================
    # TRANSACTION TYPE HANDLERS
    # ==========================================================================

    def _process_transfer(self, tx: Transaction, trie: Trie, 
                          sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Process a transfer transaction."""
        gas.charge(GasMetering.COMPUTATION * 2, "transfer_processing")
        
        token_type = tx.data.get('token_type', 'native')
        if token_type not in ['native', 'usd']:
            raise ValidationError("Invalid token type for transfer.")

        amount = tx.data['amount']
        if sender_account['balances'][token_type] < amount:
            raise ValidationError(f"Insufficient {token_type} funds for transfer.")

        sender_account['balances'][token_type] -= amount
        
        recipient_address = bytes.fromhex(tx.data['to'])
        if sender_address != recipient_address:
            gas.charge(GasMetering.STORAGE_READ, "read_recipient")
            recipient_account = self._get_account(recipient_address, trie)
            recipient_account['balances'][token_type] += amount
            gas.charge(GasMetering.STORAGE_WRITE, "write_recipient")
            self._set_account(recipient_address, recipient_account, trie)
        else:
            sender_account['balances'][token_type] += amount

    def _process_mint_usd(self, tx: Transaction, trie: Trie,
                          sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Mint USD tokens - LARGE AMOUNTS REQUIRE MULTI-SIG."""
        amount = tx.data['amount']
        
        # Require multi-sig for amounts over $10,000
        if amount > 10_000 * TOKEN_UNIT:
            gas.charge(GasMetering.COMPUTATION * 10, "multisig_verification")
            multisig = self._get_multisig_config(trie)
            signing_data = tx.get_signing_data()
            multisig.verify(tx, signing_data)
        
        if sender_address != PAYMENTS_ORACLE_ADDRESS:
            raise ValidationError("Only Payments Oracle can mint USD")
        
        gas.charge(GasMetering.COMPUTATION * 3, "mint_usd_processing")
        recipient_address = bytes.fromhex(tx.data['to'])
        
        gas.charge(GasMetering.STORAGE_READ, "read_recipient")
        recipient_account = self._get_account(recipient_address, trie)
        recipient_account['balances']['usd'] += amount
        gas.charge(GasMetering.STORAGE_WRITE, "write_recipient")
        self._set_account(recipient_address, recipient_account, trie)
        
        gas.charge(GasMetering.STORAGE_READ, "read_tokenomics")
        tokenomics_state = self._get_tokenomics_state(trie)
        tokenomics_state.total_usd_in += Decimal(amount) / Decimal(TOKEN_UNIT)
        gas.charge(GasMetering.STORAGE_WRITE, "write_tokenomics")
        self._set_tokenomics_state(tokenomics_state, trie)

    def _process_game_fee(self, tx: Transaction, trie: Trie,
                          sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Process game fee with burn and distribution."""
        gas.charge(GasMetering.COMPUTATION * 5, "game_fee_processing")
        
        fee_amount = tx.data['amount']
        leaderboard = tx.data.get('leaderboard', [])
        
        if sender_account['balances']['native'] < fee_amount:
            raise ValidationError("Insufficient native token balance for game fee.")

        burn_amount = fee_amount * 10 // 100
        leaderboard_amount = fee_amount * 30 // 100
        treasury_amount = fee_amount - burn_amount - leaderboard_amount

        sender_account['balances']['native'] -= fee_amount

        # Burn
        gas.charge(GasMetering.STORAGE_READ, "read_tokenomics")
        tokenomics_state = self._get_tokenomics_state(trie)
        tokenomics_state.total_supply -= burn_amount
        tokenomics_state.total_burned += burn_amount
        gas.charge(GasMetering.STORAGE_WRITE, "write_tokenomics")
        self._set_tokenomics_state(tokenomics_state, trie)

        # Leaderboard distribution
        if leaderboard and leaderboard_amount > 0:
            per_winner = leaderboard_amount // len(leaderboard)
            for winner_hex in leaderboard:
                winner_addr = bytes.fromhex(winner_hex)
                gas.charge(GasMetering.STORAGE_READ, "read_winner")
                winner_account = self._get_account(winner_addr, trie)
                winner_account['balances']['native'] += per_winner
                gas.charge(GasMetering.STORAGE_WRITE, "write_winner")
                self._set_account(winner_addr, winner_account, trie)

        # Treasury
        gas.charge(GasMetering.STORAGE_READ, "read_treasury")
        treasury_account = self._get_account(TREASURY_ADDRESS, trie)
        treasury_account['balances']['native'] += treasury_amount
        gas.charge(GasMetering.STORAGE_WRITE, "write_treasury")
        self._set_account(TREASURY_ADDRESS, treasury_account, trie)

    def _process_stake(self, tx: Transaction, trie: Trie, 
                       sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Process a stake transaction."""
        gas.charge(GasMetering.COMPUTATION * 3, "stake_processing")
        
        amount = tx.data['amount']
        if sender_account['balances']['native'] < amount:
            raise ValidationError("Insufficient native funds for stake.")
        
        sender_account['balances']['native'] -= amount
        
        gas.charge(GasMetering.STORAGE_READ, "read_validators")
        validator_set = self._get_validator_set(trie)
        sender_hex = sender_address.hex()
        validator_set[sender_hex] = validator_set.get(sender_hex, 0) + amount
        gas.charge(GasMetering.STORAGE_WRITE, "write_validators")
        self._set_validator_set(validator_set, trie)
        self.leader_scheduler = LeaderScheduler(validator_set)

    def _process_unstake(self, tx: Transaction, trie: Trie, 
                         sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Process an unstake transaction."""
        gas.charge(GasMetering.COMPUTATION * 3, "unstake_processing")
        
        amount = tx.data['amount']
        addr_hex = sender_address.hex()
        
        gas.charge(GasMetering.STORAGE_READ, "read_validators")
        validator_set = self._get_validator_set(trie)
        if validator_set.get(addr_hex, 0) < amount:
            raise ValidationError("Insufficient stake to unstake that amount.")
            
        validator_set[addr_hex] -= amount
        if validator_set[addr_hex] == 0:
            del validator_set[addr_hex]
        gas.charge(GasMetering.STORAGE_WRITE, "write_validators")
        self._set_validator_set(validator_set, trie)
        self.leader_scheduler = LeaderScheduler(validator_set)
        
        sender_account['balances']['native'] += amount

    def _process_bond_mint(self, tx: Transaction, trie: Trie,
                       sender_address: bytes, sender_account: dict, gas: GasMetering):
        """
        Process bond mint using AMM-referenced pricing.
        Mints tokens at current market price + premium.
        """
        gas.charge(GasMetering.COMPUTATION * 5, "bond_mint_processing")
        
        usd_amount_in = tx.data['amount_in']
        
        if sender_account['balances']['usd'] < usd_amount_in:
            raise ValidationError("Insufficient USD balance for bond mint.")
        
        # Get current AMM price as reference
        gas.charge(GasMetering.STORAGE_READ, "read_pool")
        pool = self._get_liquidity_pool_state(trie)
        
        if pool.token_reserve == 0 or pool.usd_reserve == 0:
            # Bootstrap price: $1.00 per token
            price_per_token = Decimal('1.0')
        else:
            # Use AMM price with premium (incentivizes AMM swaps over minting)
            market_price = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
            price_per_token = market_price * AMM_MINT_PREMIUM
        
        # Apply price bounds
        price_per_token = max(MIN_MINT_PRICE, min(price_per_token, MAX_MINT_PRICE))
        
        # Calculate tokens to mint
        native_tokens_out = int(Decimal(usd_amount_in) / price_per_token)
        
        if native_tokens_out == 0:
            raise ValidationError("Bond amount too small")
        
        # Transfer USD to reserve
        sender_account['balances']['usd'] -= usd_amount_in
        gas.charge(GasMetering.STORAGE_READ, "read_reserve")
        reserve_pool_account = self._get_account(RESERVE_POOL_ADDRESS, trie)
        reserve_pool_account['balances']['usd'] += usd_amount_in
        gas.charge(GasMetering.STORAGE_WRITE, "write_reserve")
        self._set_account(RESERVE_POOL_ADDRESS, reserve_pool_account, trie)
        
        # Try to fulfill from treasury first (recycled tokens)
        gas.charge(GasMetering.STORAGE_READ, "read_treasury")
        treasury_account = self._get_account(TREASURY_ADDRESS, trie)
        treasury_balance = treasury_account['balances'].get('native', 0)
        tokens_from_treasury = min(native_tokens_out, treasury_balance)
        tokens_to_mint = native_tokens_out - tokens_from_treasury
        
        if tokens_from_treasury > 0:
            treasury_account['balances']['native'] -= tokens_from_treasury
            sender_account['balances']['native'] += tokens_from_treasury
            gas.charge(GasMetering.STORAGE_WRITE, "write_treasury")
            self._set_account(TREASURY_ADDRESS, treasury_account, trie)
        
        # Mint new tokens if needed
        if tokens_to_mint > 0:
            gas.charge(GasMetering.STORAGE_READ, "read_tokenomics")
            tokenomics_state = self._get_tokenomics_state(trie)
            tokenomics_state.total_supply += tokens_to_mint
            tokenomics_state.total_minted += tokens_to_mint
            sender_account['balances']['native'] += tokens_to_mint
            gas.charge(GasMetering.STORAGE_WRITE, "write_tokenomics")
            self._set_tokenomics_state(tokenomics_state, trie)

    def _process_reserve_burn(self, tx: Transaction, trie: Trie,
                          sender_address: bytes, sender_account: dict, gas: GasMetering):
        """
        Process reserve burn (buyback & burn) with price floor protection.
        """
        gas.charge(GasMetering.COMPUTATION * 5, "reserve_burn_processing")
        
        native_amount_in = tx.data['amount_in']
        
        if sender_account['balances']['native'] < native_amount_in:
            raise ValidationError("Insufficient native token balance for reserve burn.")
        
        gas.charge(GasMetering.STORAGE_READ, "read_outflow_reserve")
        outflow_reserve_account = self._get_account(OUTFLOW_RESERVE_ADDRESS, trie)
        usd_balance = outflow_reserve_account['balances']['usd']
        
        gas.charge(GasMetering.STORAGE_READ, "read_pool")
        pool = self._get_liquidity_pool_state(trie)
        
        if pool.token_reserve == 0:
            raise ValidationError("Cannot determine price: empty token reserve")
        
        market_price = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
        
        # Apply 2% discount for buyback and price floor
        buyback_price = market_price * Decimal('0.98')
        buyback_price = max(buyback_price, MIN_BURN_PRICE)
        
        usd_tokens_out = int(Decimal(native_amount_in) * buyback_price)
        
        if usd_tokens_out == 0:
            raise ValidationError("Burn amount too small")
        
        if usd_balance < usd_tokens_out:
            raise ValidationError("Outflow Reserve has insufficient USD liquidity.")
        
        # Perform swap
        sender_account['balances']['native'] -= native_amount_in
        sender_account['balances']['usd'] += usd_tokens_out
        outflow_reserve_account['balances']['usd'] -= usd_tokens_out
        gas.charge(GasMetering.STORAGE_WRITE, "write_outflow_reserve")
        self._set_account(OUTFLOW_RESERVE_ADDRESS, outflow_reserve_account, trie)
        
        # Burn tokens
        gas.charge(GasMetering.STORAGE_READ, "read_tokenomics")
        tokenomics_state = self._get_tokenomics_state(trie)
        tokenomics_state.total_supply -= native_amount_in
        tokenomics_state.total_burned += native_amount_in
        gas.charge(GasMetering.STORAGE_WRITE, "write_tokenomics")
        self._set_tokenomics_state(tokenomics_state, trie)

    def _process_deploy_reserve_liquidity(self, tx: Transaction, trie: Trie,
                                          sender_address: bytes, sender_account: dict,
                                          gas: GasMetering):
        """Deploy reserve liquidity - REQUIRES MULTI-SIG."""
        
        # Verify multi-sig
        gas.charge(GasMetering.COMPUTATION * 10, "multisig_verification")
        multisig = self._get_multisig_config(trie)
        signing_data = tx.get_signing_data()
        multisig.verify(tx, signing_data)
        
        if sender_address != RESERVE_ADMIN_ADDRESS:
            raise ValidationError("Only Reserve Admin can deploy liquidity")
        
        gas.charge(GasMetering.COMPUTATION * 5, "deploy_reserve_processing")
        gas.charge(GasMetering.STORAGE_READ, "read_reserve")
        reserve_pool_account = self._get_account(RESERVE_POOL_ADDRESS, trie)
        usd_to_deploy = reserve_pool_account['balances']['usd']
        
        if usd_to_deploy == 0:
            raise ValidationError("No USD in reserve pool to deploy.")

        gas.charge(GasMetering.STORAGE_READ, "read_pool")
        pool = self._get_liquidity_pool_state(trie)
        if pool.token_reserve > 0:
            price_per_token = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
        else:
            price_per_token = Decimal('1.0')
        
        native_to_mint_and_deploy = int(Decimal(usd_to_deploy) / price_per_token)

        gas.charge(GasMetering.STORAGE_READ, "read_tokenomics")
        tokenomics_state = self._get_tokenomics_state(trie)
        tokenomics_state.total_supply += native_to_mint_and_deploy
        gas.charge(GasMetering.STORAGE_WRITE, "write_tokenomics")
        self._set_tokenomics_state(tokenomics_state, trie)

        pool.usd_reserve += usd_to_deploy
        pool.token_reserve += native_to_mint_and_deploy
        gas.charge(GasMetering.STORAGE_WRITE, "write_pool")
        self._set_liquidity_pool_state(pool, trie)

        reserve_pool_account['balances']['usd'] = 0
        gas.charge(GasMetering.STORAGE_WRITE, "write_reserve")
        self._set_account(RESERVE_POOL_ADDRESS, reserve_pool_account, trie)

    def _process_swap(self, tx: Transaction, trie: Trie, sender_address: bytes,
                      sender_account: dict, gas: GasMetering):
        """Process swap with full protection: TWAP, circuit breaker, rate limiting."""
        if self.paused:
            raise ValidationError("Chain paused")

        data = tx.data
        amount_in = data['amount_in']
        token_in = data['token_in']
        min_out = data['min_amount_out']
        input_is_token = token_in == 'native'

        # Load pool
        gas.charge(GasMetering.STORAGE_READ, "read_pool")
        pool = self._get_liquidity_pool_state(trie)

        if pool.token_reserve == 0 or pool.usd_reserve == 0:
            raise ValidationError("Empty pool")

        # Calculate current price and USD value
        current_time = int(time.time())
        current_price = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
        
        if input_is_token:
            swap_usd_value = int(Decimal(amount_in) * current_price)
        else:
            swap_usd_value = amount_in
        
        # Rate limiting
        gas.charge(GasMetering.STORAGE_READ, "read_rate_limiter")
        rate_limiter = self._get_rate_limiter(trie)
        rate_limiter.check_limit(sender_address, current_time, swap_usd_value)
        
        # Circuit breaker
        gas.charge(GasMetering.STORAGE_READ, "read_circuit_breaker")
        circuit_breaker = self._get_circuit_breaker(trie)
        circuit_breaker.check_and_trip(current_time, current_price, swap_usd_value)
        
        # TWAP validation
        gas.charge(GasMetering.STORAGE_READ, "read_twap")
        twap = self._get_twap_oracle(trie)
        
        twap_price = twap.get_twap(current_time)
        if twap_price > 0 and len(twap.observations) >= 2:
            deviation = abs(current_price - twap_price) / twap_price
            if deviation > TWAP_MAX_DEVIATION:
                raise ValidationError(
                    f"Price deviation {float(deviation)*100:.2f}% exceeds "
                    f"{float(TWAP_MAX_DEVIATION)*100}% limit. "
                    f"Current: {current_price}, TWAP: {twap_price}"
                )
        
        # Update TWAP
        gas.charge(GasMetering.COMPUTATION, "update_twap")
        twap.update(current_time, current_price, pool.token_reserve, pool.usd_reserve)

        # Minimum transaction value check ($1.00)
        if swap_usd_value < (1 * TOKEN_UNIT):
            raise ValidationError("Transaction below $1.00 minimum")

        # Maximum transaction size check (50% of pool)
        if input_is_token:
            if amount_in > pool.token_reserve // 2:
                raise ValidationError("Transaction exceeds 50% of pool")
        else:
            if amount_in > pool.usd_reserve // 2:
                raise ValidationError("Transaction exceeds 50% of pool")

        # Balance check
        if input_is_token:
            if sender_account['balances']['native'] < amount_in:
                raise ValidationError("Insufficient native balance")
        else:
            if sender_account['balances']['usd'] < amount_in:
                raise ValidationError("Insufficient USD balance")

        # Calculate output
        gas.charge(GasMetering.COMPUTATION * 3, "calculate_output")
        amount_out = pool.get_swap_output(amount_in, input_is_token)
        
        if amount_out < min_out:
            raise ValidationError(f"Slippage: got {amount_out}, expected {min_out}")

        # Execute swap
        gas.charge(GasMetering.COMPUTATION * 5, "execute_swap")
        actual_output = pool.apply_swap(amount_in, input_is_token)
        
        # Update balances
        if input_is_token:
            sender_account['balances']['native'] -= amount_in
            sender_account['balances']['usd'] += actual_output
        else:
            sender_account['balances']['usd'] -= amount_in
            sender_account['balances']['native'] += actual_output
        
        # Write all state
        gas.charge(GasMetering.STORAGE_WRITE * 4, "write_swap_state")
        self._set_liquidity_pool_state(pool, trie)
        self._set_twap_oracle(twap, trie)
        self._set_circuit_breaker(circuit_breaker, trie)
        self._set_rate_limiter(rate_limiter, trie)
        
        logger.info(
            f"Swap: {amount_in} {token_in} -> {actual_output} "
            f"({'usd' if input_is_token else 'native'}), "
            f"price: {current_price}, twap: {twap_price}"
        )

    def _process_add_liquidity(self, tx: Transaction, trie: Trie,
                               sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Process liquidity addition with proper LP token calculation."""
        gas.charge(GasMetering.COMPUTATION * 5, "add_liquidity_processing")
        gas.charge(GasMetering.STORAGE_READ, "read_pool")
        pool = self._get_liquidity_pool_state(trie)
        
        native_amount = tx.data['native_amount']
        usd_amount = tx.data['usd_amount']

        if sender_account['balances']['native'] < native_amount or \
           sender_account['balances']['usd'] < usd_amount:
            raise ValidationError("Insufficient balance to add liquidity.")

        # Prevent zero liquidity
        if native_amount == 0 or usd_amount == 0:
            raise ValidationError("Cannot add zero liquidity")

        sender_account['balances']['native'] -= native_amount
        sender_account['balances']['usd'] -= usd_amount

        # FIXED LP TOKEN CALCULATION
        if pool.lp_token_supply == 0:
            # Use geometric mean for initial liquidity
            lp_tokens_to_mint = int(math.sqrt(native_amount * usd_amount))
            
            MIN_LIQUIDITY = 1000
            if lp_tokens_to_mint < MIN_LIQUIDITY:
                raise ValidationError("Initial liquidity too small")
            
            # Burn minimum liquidity (lock forever)
            lp_tokens_to_mint -= MIN_LIQUIDITY
            pool.lp_token_supply = MIN_LIQUIDITY
        else:
            # Maintain price ratio
            lp_from_native = (native_amount * pool.lp_token_supply) // pool.token_reserve
            lp_from_usd = (usd_amount * pool.lp_token_supply) // pool.usd_reserve
            lp_tokens_to_mint = min(lp_from_native, lp_from_usd)
            
            if lp_tokens_to_mint == 0:
                raise ValidationError("Liquidity addition too small")

        sender_account['lp_tokens'] += lp_tokens_to_mint
        
        pool.token_reserve += native_amount
        pool.usd_reserve += usd_amount
        pool.lp_token_supply += lp_tokens_to_mint
        
        gas.charge(GasMetering.STORAGE_WRITE, "write_pool")
        self._set_liquidity_pool_state(pool, trie)

    def _process_remove_liquidity(self, tx: Transaction, trie: Trie,
                                  sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Process liquidity removal."""
        gas.charge(GasMetering.COMPUTATION * 5, "remove_liquidity_processing")
        gas.charge(GasMetering.STORAGE_READ, "read_pool")
        pool = self._get_liquidity_pool_state(trie)
        
        lp_amount = tx.data['lp_amount']

        if sender_account['lp_tokens'] < lp_amount:
            raise ValidationError("Insufficient LP tokens.")

        if pool.lp_token_supply == 0:
            raise ValidationError("No liquidity in pool")

        # Calculate proportional share
        share = lp_amount / pool.lp_token_supply
        native_to_return = int(pool.token_reserve * share)
        usd_to_return = int(pool.usd_reserve * share)

        sender_account['lp_tokens'] -= lp_amount
        sender_account['balances']['native'] += native_to_return
        sender_account['balances']['usd'] += usd_to_return

        pool.token_reserve -= native_to_return
        pool.usd_reserve -= usd_to_return
        pool.lp_token_supply -= lp_amount
        
        gas.charge(GasMetering.STORAGE_WRITE, "write_pool")
        self._set_liquidity_pool_state(pool, trie)

    def _process_update_multisig(self, tx: Transaction, trie: Trie,
                                 sender_address: bytes, sender_account: dict, gas: GasMetering):
        """Update multi-sig configuration - REQUIRES CURRENT MULTI-SIG."""
        gas.charge(GasMetering.COMPUTATION * 10, "multisig_verification")
        current_multisig = self._get_multisig_config(trie)
        signing_data = tx.get_signing_data()
        current_multisig.verify(tx, signing_data)
        
        # Update configuration
        new_required_sigs = tx.data['required_sigs']
        new_signers_hex = tx.data['authorized_signers']
        new_signers = [bytes.fromhex(pk) for pk in new_signers_hex]
        
        new_multisig = MultiSigValidator(new_required_sigs, new_signers)
        gas.charge(GasMetering.STORAGE_WRITE, "write_multisig_config")
        self._set_multisig_config(new_multisig, trie)
        
        logger.info(
            f"Multi-sig config updated: {new_required_sigs} sigs required, "
            f"{len(new_signers)} authorized signers"
        )

    # ==========================================================================
    # TOKENOMICS & AMM STATE
    # ==========================================================================

    def _get_tokenomics_state(self, trie: Trie) -> TokenomicsState:
        """Retrieve tokenomics state from trie."""
        encoded = trie.get(TOKENOMICS_ADDRESS)
        if encoded:
            data = msgpack.unpackb(encoded, raw=False)
            return TokenomicsState(data)
        return TokenomicsState()
    
    def _set_tokenomics_state(self, state: TokenomicsState, trie: Trie):
        """Store tokenomics state in trie."""
        encoded = msgpack.packb(state.to_dict(), use_bin_type=True)
        trie.set(TOKENOMICS_ADDRESS, encoded)

    def _get_liquidity_pool_state(self, trie) -> LiquidityPoolState:
        raw = trie.get(b"AMM_POOL")
        if not raw:
            return LiquidityPoolState({
                'token_reserve': 0,
                'usd_reserve': 0,
                'lp_token_supply': 0
            })
        return LiquidityPoolState(msgpack.unpackb(raw))
    
    def _set_liquidity_pool_state(self, pool: LiquidityPoolState, trie):
        trie.set(b"AMM_POOL", msgpack.packb({
            'token_reserve': pool.token_reserve,
            'usd_reserve': pool.usd_reserve,
            'lp_token_supply': pool.lp_token_supply
        }))

    # ==========================================================================
    # PUBLIC API METHODS
    # ==========================================================================

    def get_tokenomics_stats(self) -> dict:
        """Get current tokenomics statistics."""
        state = self._get_tokenomics_state(self.state_trie)
        
        return {
            'circulating_supply': str(state.circulating_supply),
            'total_minted': str(state.total_minted),
            'total_burned': str(state.total_burned),
            'total_usd_in': str(state.total_usd_in),
            'total_usd_out': str(state.total_usd_out),
        }
    
    def get_amm_stats(self) -> dict:
        """Get current AMM pool statistics."""
        pool = self._get_liquidity_pool_state(self.state_trie)
        
        return {
            'token_reserve': str(pool.token_reserve),
            'usd_reserve': str(pool.usd_reserve),
            'lp_token_supply': str(pool.lp_token_supply),
            'current_price': str(pool.current_price),
        }

    def validate_chain(self) -> bool:
        """Validates entire chain integrity."""
        current_hash = self.head_hash
        
        while current_hash != (b'\x00' * 32):
            block = self.get_block(current_hash)
            if block is None:
                logger.error(f"Missing block: {current_hash.hex()}")
                return False
            
            if block.height == 0:
                if block.parent_hash == (b'\x00' * 32):
                    return True
                else:
                    logger.error("Malformed genesis block")
                    return False
            
            parent_block = self.get_block(block.parent_hash)
            if parent_block is None:
                logger.error(f"Missing parent block: {block.parent_hash.hex()}")
                return False
            
            if block.hash != block.header.calculate_hash():
                logger.error(f"Block hash mismatch at height {block.height}")
                return False

            current_hash = block.parent_hash
        
        return False