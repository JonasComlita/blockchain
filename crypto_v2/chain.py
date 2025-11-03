"""
A persistent blockchain with improved security and state management.
Simplified: Game logic moved off-chain, AMM for price discovery.
"""
# Prefer the msgpack library but provide a lightweight fallback shim using json
try:
    import msgpack as msgpack  # type: ignore
except Exception:
    import json as _json

    class _MsgpackShim:
        @staticmethod
        def packb(obj, use_bin_type=True):
            # Encode to JSON bytes; non-serializable objects are converted to str
            return _json.dumps(obj, default=str).encode()

        @staticmethod
        def unpackb(b, raw=False):
            # Decode from bytes to Python objects
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
OUTFLOW_RESERVE_ADDRESS = b'\x00' * 19 + b'\x0A' # New address for the buyback & burn contract
FINALITY_STATE_ADDRESS = b'\x00' * 19 + b'\x0B'
PAUSE_ADMIN_ADDRESS = bytes([0x00]*19 + [0x12])
TREASURY_ADDRESS = b'\x00' * 19 + b'\xFF'

# Configuration constants
TOKEN_UNIT = 1_000_000

# --- ORACLE CONSTANTS -------------------------------------------------
ORACLE_AGGREGATOR_ADDRESS = bytes([0x00]*19 + [0x10])
ORACLE_STAKE_ADDRESS      = bytes([0x00]*19 + [0x11])

ORACLE_QUORUM            = 3          # minimum agreeing oracles
ORACLE_BOND              = 1000 * TOKEN_UNIT
ORACLE_SLASH_PERCENT     = 50         # % of bond slashed for misbehavior
ORACLE_ROUND_TIMEOUT     = 300        # seconds
ORACLE_MAX_DEVIATION_PCT = 5          # 5 % max deviation from median
# --------------------------------------------------------------------

CHECKPOINT_INTERVAL = 100
MAX_BLOCK_SIZE = 1_000_000
MAX_TXS_PER_BLOCK = 1000
MIN_STAKE_AMOUNT = 100 * TOKEN_UNIT
SLASH_PERCENTAGE = 50

# Configuration constants for the Bonding Curve
BONDING_CURVE_BASE_PRICE = Decimal('0.10') # $0.10
BONDING_CURVE_SLOPE = Decimal('0.00000001')

# --- Casper FFG Finality Constants ---
EPOCH_LENGTH = 50  # blocks
FINALITY_THRESHOLD = 2/3  # 2/3 of validators must attest
SLASH_AMOUNT = 1000 * TOKEN_UNIT
INACTIVITY_PENALTY = 1 * TOKEN_UNIT


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


class OracleRound:
    __slots__ = ('submissions', 'finalized', 'final_value', 'finalized_at')
    def __init__(self):
        self.submissions   = {}   # oracle_id -> signed payload dict
        self.finalized     = False
        self.final_value   = None
        self.finalized_at  = 0

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
        r.submissions   = d["submissions"]
        r.finalized     = d["finalized"]
        r.final_value   = d["final_value"]
        r.finalized_at  = d["finalized_at"]
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
    def __init__(self, source_epoch, target_epoch, target_hash, validator_pubkey, signature=None):
        self.source_epoch = source_epoch
        self.target_epoch = target_epoch
        self.target_hash = target_hash
        self.validator_pubkey = validator_pubkey
        self.signature = signature

    def to_dict(self, include_signature=True):
        data = {
            "source_epoch": self.source_epoch,
            "target_epoch": self.target_epoch,
            "target_hash": self.target_hash.hex(),
            "validator_pubkey": self.validator_pubkey.hex(),
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


class Blockchain:
    def __init__(self, db_path: str = None, db: DB = None, genesis_block: Block = None, 
                 chain_id: int = 1, game_oracle_pubkey: bytes = None, monitoring_host: str = "127.0.0.1", monitoring_port: int = 9090):
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

        self.latest_attestations = {}
        self.finality_state = self._get_finality_state(self.state_trie)
        
        self.oracle_rounds        = {}   # round_id -> OracleRound
        self.current_oracle_round = 1
        self.oracle_stakes        = self._get_oracle_stakes(self.state_trie)
        self.oracle_pubkey_to_id  = {pk: pk[:8].hex() for pk in self.oracle_stakes}
        
        self.paused = False
        self.pause_block = None  # block height when paused
        
        self.leader_scheduler = LeaderScheduler(self._get_validator_set(self.state_trie))
        
        self._initialize_config()

        logger.info(f"Initializing Monitor with host={monitoring_host}, port={monitoring_port}")
        self.monitor = Monitor(self, host=monitoring_host, port=monitoring_port)

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

    def _store_block(self, block: Block):
        """Serializes and stores a block."""
        block_data = msgpack.packb(block.to_dict(), use_bin_type=True)
        self.db.put(block.hash, block_data)
        
        height_key = b'height:' + str(block.height).encode()
        self.db.put(height_key, block.hash)

    def get_block(self, block_hash: bytes) -> Block | None:
        """Retrieves a block from the database."""
        block_data = self.db.get(b'block:' + block_hash)
        if block_data is None:
            return None
        
        block_dict = msgpack.unpackb(block_data, raw=False)
        
        # --- Full Migration & Type Safety ---
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

        # Fix poh_sequence
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

    def add_block(self, block: Block) -> bool:
        """Adds a new block with comprehensive validation and atomic state updates."""
        start = time.time()
        try:
            # -----------------------------------------------------------------
            #  2. PARENT / HEIGHT CHECK
            # -----------------------------------------------------------------
            parent = self.get_latest_block()
            if block.parent_hash != parent.hash:
                raise ValidationError("Parent hash mismatch")
            if block.height != parent.height + 1:
                raise ValidationError("Invalid block height")
            if block.timestamp <= parent.timestamp:
                raise ValidationError("Timestamp must be after parent")

            # -----------------------------------------------------------------
            #  3. RE-PROCESS TRANSACTIONS → STATE ROOT + FEE COLLECTION
            # -----------------------------------------------------------------
            temp_trie = Trie(self.db, root_hash=self.state_trie.root_hash)
            
            # Producer Validation
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
            # Optimization: If state root matches, we can skip re-processing
            if block.state_root != self.state_trie.root_hash:
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
                        # Do not re-raise; continue processing other transactions

                # Process attestations before state root validation
                for attestation in block.attestations:
                    self._process_attestation(attestation, temp_trie)

                if block.state_root != temp_trie.root_hash:
                    raise ValidationError(
                        f"State root mismatch. Expected: {temp_trie.root_hash.hex()}, "
                        f"Got: {block.state_root.hex()}"
                    )
            else:
                for tx in block.transactions:
                    total_fees += tx.fee

            # -----------------------------------------------------------------
            #  4. PoH VALIDATION
            # -----------------------------------------------------------------
            parent_poh_hash = parent.poh_sequence[-1][0] if parent.poh_sequence else parent.hash
            if not verify_poh_sequence(parent_poh_hash, block.poh_sequence):
                raise ValidationError("Invalid Proof of History sequence")

            # -----------------------------------------------------------------
            #  5. COMMIT NEW STATE
            # -----------------------------------------------------------------
            self.state_trie = temp_trie
            
            # -----------------------------------------------------------------
            #  6. REWARD PRODUCER WITH COLLECTED FEES
            # -----------------------------------------------------------------
            if total_fees > 0:
                producer_addr = public_key_to_address(block.producer_pubkey)
                acc = self._get_account(producer_addr, self.state_trie)
                acc['balances']['native'] = acc['balances'].get('native', 0) + total_fees
                self._set_account(producer_addr, acc, self.state_trie)            # -----------------------------------------------------------------
            #  7. UPDATE HEAD & STORE BLOCK
            # -----------------------------------------------------------------
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

    def _get_oracle_round(self, round_id, trie):
        key = b"ORACLE_ROUND:" + str(round_id).encode()
        raw = trie.get(key)
        return OracleRound.from_dict(msgpack.unpackb(raw)) if raw else OracleRound()

    def _set_oracle_round(self, round_id, round_obj, trie):
        key = b"ORACLE_ROUND:" + str(round_id).encode()
        trie.set(key, msgpack.packb(round_obj.to_dict()))

    def _process_transaction(self, tx: Transaction, trie: Trie) -> bool:
        """
        Process a single transaction and update the state trie.
        This is the heart of the state transition logic.
        """
        sender_address = public_key_to_address(tx.sender_public_key)
        sender_account = self._get_account(sender_address, trie)

        # 0. Verify chain ID to prevent replay attacks
        if tx.chain_id != self.chain_id:
            raise ValidationError(f"Wrong chain ID. Expected {self.chain_id}, got {tx.chain_id}")

        # 1. Verify nonce
        if tx.nonce != sender_account['nonce']:
            raise ValidationError(f"Invalid nonce. Expected {sender_account['nonce']}, got {tx.nonce}")

        # 2. Increment nonce
        sender_account['nonce'] += 1

        # 3. Deduct fee
        fee_paid_in_usd = tx.tx_type == 'SWAP' and tx.data.get('token_in') == 'usd'
        
        if fee_paid_in_usd:
            if sender_account['balances']['usd'] < tx.fee:
                raise ValidationError("Insufficient USD funds for fee")
            sender_account['balances']['usd'] -= tx.fee
        else:
            if sender_account['balances']['native'] < tx.fee:
                raise ValidationError("Insufficient native funds for fee")
            sender_account['balances']['native'] -= tx.fee

        # --- Transaction-specific logic ---

        if tx.tx_type == 'TRANSFER':
            token_type = tx.data.get('token_type', 'native') # Default to native token
            if token_type not in ['native', 'usd']:
                raise ValidationError("Invalid token type for transfer.")

            amount = tx.data['amount']
            if sender_account['balances'][token_type] < amount:
                raise ValidationError(f"Insufficient {token_type} funds for transfer.")

            sender_account['balances'][token_type] -= amount
            
            recipient_address = bytes.fromhex(tx.data['to'])
            if sender_address != recipient_address:
                recipient_account = self._get_account(recipient_address, trie)
                recipient_account['balances'][token_type] += amount
                self._set_account(recipient_address, recipient_account, trie)
            else:
                sender_account['balances'][token_type] += amount

        elif tx.tx_type == 'MINT_USD_TOKEN':
            # This is a permissioned action for our trusted Payments Gateway
            if sender_address != PAYMENTS_ORACLE_ADDRESS:
                raise ValidationError("Sender is not authorized to mint USD tokens.")

            amount = tx.data['amount']
            recipient_address = bytes.fromhex(tx.data['to'])
            
            recipient_account = self._get_account(recipient_address, trie)
            recipient_account['balances']['usd'] += amount
            self._set_account(recipient_address, recipient_account, trie)
            
            # Update tokenomics for tracking purposes
            tokenomics_state = self._get_tokenomics_state(trie)
            tokenomics_state.total_usd_in += Decimal(amount) / Decimal(TOKEN_UNIT)
            self._set_tokenomics_state(tokenomics_state, trie)

        elif tx.tx_type == 'STAKE':
            self._process_stake(tx, trie, sender_address, sender_account)

        elif tx.tx_type == 'UNSTAKE':
            self._process_unstake(tx, trie, sender_address, sender_account)

        elif tx.tx_type == 'BOND_MINT':
            tokenomics_state = self._get_tokenomics_state(trie)
            usd_amount_in = tx.data['amount_in']

            if sender_account['balances']['usd'] < usd_amount_in:
                raise ValidationError("Insufficient USD balance for bond mint.")

            # Calculate tokens to mint based on the bonding curve
            # This is a simplified integration; a real one would be more complex
            price_per_token = BONDING_CURVE_BASE_PRICE + (BONDING_CURVE_SLOPE * tokenomics_state.total_supply)
            native_tokens_out = int(Decimal(usd_amount_in) / price_per_token)

            # Transfer USD to the reserve pool
            sender_account['balances']['usd'] -= usd_amount_in
            reserve_pool_account = self._get_account(RESERVE_POOL_ADDRESS, trie)
            reserve_pool_account['balances']['usd'] += usd_amount_in
            self._set_account(RESERVE_POOL_ADDRESS, reserve_pool_account, trie)

            # Mint new native tokens to the user
            tokenomics_state.total_supply += native_tokens_out
            sender_account['balances']['native'] += native_tokens_out
            self._set_tokenomics_state(tokenomics_state, trie)

        elif tx.tx_type == 'RESERVE_BURN':
            native_amount_in = tx.data['amount_in']

            if sender_account['balances']['native'] < native_amount_in:
                raise ValidationError("Insufficient native token balance for reserve burn.")

            # A simple reverse curve: the price offered decreases as the reserve's USD balance dwindles.
            outflow_reserve_account = self._get_account(OUTFLOW_RESERVE_ADDRESS, trie)
            usd_balance = outflow_reserve_account['balances']['usd']
            
            # For simplicity, let's say the reserve offers a price slightly below the main market price.
            pool = self._get_liquidity_pool_state(trie)
            market_price = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
            buyback_price = market_price * Decimal('0.98') # Offer 98% of market price
            
            usd_tokens_out = int(Decimal(native_amount_in) * buyback_price)

            if usd_balance < usd_tokens_out:
                raise ValidationError("Outflow Reserve has insufficient USD liquidity for this sale.")

            # Perform the swap
            sender_account['balances']['native'] -= native_amount_in
            sender_account['balances']['usd'] += usd_tokens_out
            outflow_reserve_account['balances']['usd'] -= usd_tokens_out
            self._set_account(OUTFLOW_RESERVE_ADDRESS, outflow_reserve_account, trie)

            # Burn the received native tokens
            tokenomics_state = self._get_tokenomics_state(trie)
            tokenomics_state.total_supply -= native_amount_in
            tokenomics_state.total_burned += native_amount_in
            self._set_tokenomics_state(tokenomics_state, trie)

        elif tx.tx_type == 'DEPLOY_RESERVE_LIQUIDITY':
            if sender_address != RESERVE_ADMIN_ADDRESS:
                raise ValidationError("Only the Reserve Admin can deploy liquidity.")

            reserve_pool_account = self._get_account(RESERVE_POOL_ADDRESS, trie)
            usd_to_deploy = reserve_pool_account['balances']['usd']
            if usd_to_deploy == 0:
                raise ValidationError("No USD in reserve pool to deploy.")

            # For simplicity, we'll mint a corresponding amount of native tokens
            # A real implementation might use a different strategy
            pool = self._get_liquidity_pool_state(trie)
            if pool.token_reserve > 0:
                price_per_token = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
            else:
                price_per_token = Decimal('1.0')  # Default price for initial liquidity
            native_to_mint_and_deploy = int(Decimal(usd_to_deploy) / price_per_token)

            tokenomics_state = self._get_tokenomics_state(trie)
            tokenomics_state.total_supply += native_to_mint_and_deploy
            self._set_tokenomics_state(tokenomics_state, trie)

            # Add the new liquidity to the AMM pool
            pool.usd_reserve += usd_to_deploy
            pool.token_reserve += native_to_mint_and_deploy
            # A real implementation would also mint and distribute LP tokens
            self._set_liquidity_pool_state(pool, trie)

            # Clear the reserve pool's USD balance
            reserve_pool_account['balances']['usd'] = 0
            self._set_account(RESERVE_POOL_ADDRESS, reserve_pool_account, trie)

        elif tx.tx_type == 'SWAP':
            self._process_swap(tx, trie, sender_account)

        elif tx.tx_type == 'ADD_LIQUIDITY':
            pool = self._get_liquidity_pool_state(trie)
            native_amount = tx.data['native_amount']
            usd_amount = tx.data['usd_amount']

            if sender_account['balances']['native'] < native_amount or sender_account['balances']['usd'] < usd_amount:
                raise ValidationError("Insufficient balance to add liquidity.")

            sender_account['balances']['native'] -= native_amount
            sender_account['balances']['usd'] -= usd_amount

            # Simplified LP token calculation (a more robust implementation would use sqrt)
            if pool.lp_token_supply == 0:
                lp_tokens_to_mint = 100 * TOKEN_UNIT # Initial liquidity provider gets a fixed amount
            else:
                lp_tokens_to_mint = (native_amount * pool.lp_token_supply) // pool.token_reserve

            sender_account['lp_tokens'] += lp_tokens_to_mint
            
            pool.token_reserve += native_amount
            pool.usd_reserve += usd_amount
            pool.lp_token_supply += lp_tokens_to_mint
            self._set_liquidity_pool_state(pool, trie)

        elif tx.tx_type == 'REMOVE_LIQUIDITY':
            pool = self._get_liquidity_pool_state(trie)
            lp_amount = tx.data['lp_amount']

            if sender_account['lp_tokens'] < lp_amount:
                raise ValidationError("Insufficient LP tokens.")

            # Calculate proportional share of reserves
            share = lp_amount / pool.lp_token_supply
            native_to_return = int(pool.token_reserve * share)
            usd_to_return = int(pool.usd_reserve * share)

            sender_account['lp_tokens'] -= lp_amount
            sender_account['balances']['native'] += native_to_return
            sender_account['balances']['usd'] += usd_to_return

            pool.token_reserve -= native_to_return
            pool.usd_reserve -= usd_to_return
            pool.lp_token_supply -= lp_amount
            self._set_liquidity_pool_state(pool, trie)

        elif tx.tx_type == "ORACLE_SUBMIT":
            self._process_oracle_submit(tx, trie)

        elif tx.tx_type == "ORACLE_REGISTER":
            self._process_oracle_register(tx, trie)

        elif tx.tx_type == "ORACLE_UNREGISTER":
            self._process_oracle_unregister(tx, trie)

        elif tx.tx_type == "ORACLE_NEW_ROUND":
            self._process_oracle_new_round(tx, trie)

        elif tx.tx_type == "UPGRADE_LOGIC":
            # Proxy handles this; skip in logic
            pass

        elif tx.tx_type == "SLASH":
            validator_address = tx.data['validator_address']
            self._slash_validator(validator_address, trie)

        elif tx.tx_type == "SWAP":
            self._process_swap(tx, trie)
        
        # --- End of transaction-specific logic ---

        # 4. Save the updated sender account
        self._set_account(sender_address, sender_account, trie)

        return True

    def _process_attestation(self, attestation: Attestation, trie: Trie):
        """Processes a validator attestation."""
        # 1. Verify signature
        if not attestation.verify_signature():
            raise ValidationError("Invalid attestation signature")

        # 2. Check if validator is in the current validator set
        validators = self._get_validator_set(trie)
        validator_address = public_key_to_address(attestation.validator_pubkey).hex()
        if validator_address not in validators:
            raise ValidationError("Attestation from non-validator")

        # 3. Check for double voting
        attestations = self._get_attestations(trie)
        if validator_address in attestations:
            existing_attestation = attestations[validator_address]
            if existing_attestation['target_epoch'] == attestation.target_epoch and \
               existing_attestation['target_hash'] != attestation.target_hash.hex():
                self._slash_validator(validator_address, trie)
                return  # Do not process the malicious attestation

        # 4. Store attestation
        attestations[validator_address] = attestation.to_dict()
        self._set_attestations(attestations, trie)

        # 5. Check for finality
        self._check_for_finality(trie)

    def _check_for_finality(self, trie: Trie):
        """Checks if an epoch can be justified or finalized."""
        finality_state = self._get_finality_state(trie)
        attestations = self._get_attestations(trie)
        validators = self._get_validator_set(trie)
        total_stake = sum(validators.values())

        # Check for justification
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

        # Check for finalization
        if finality_state.justified_epoch > finality_state.finalized_epoch + 1:
            finality_state.finalized_epoch = finality_state.justified_epoch - 1
            self._set_finality_state(finality_state, trie)
            logger.info(f"Epoch {finality_state.finalized_epoch} finalized")

            # Penalize inactive validators
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

        # Burn the penalty amount
        tokenomics = self._get_tokenomics_state(trie)
        tokenomics.total_supply -= penalty
        tokenomics.total_burned += penalty
        self._set_tokenomics_state(tokenomics, trie)

        logger.info(f"Validator {validator_address} penalized for inactivity.")

    def _process_swap(self, tx: Transaction, trie: Trie, sender_account: dict):
        """Processes a swap transaction using the constant product formula."""
        if self.paused:
            raise ValidationError("Chain paused")

        data = tx.data
        amount_in = data['amount_in']
        token_in = data['token_in']
        min_out = data['min_amount_out']
        input_is_token = token_in == 'native'

        pool = self._get_liquidity_pool_state(trie)

        # Gracefully handle empty pools to prevent division by zero
        if (input_is_token and pool.token_reserve == 0) or \
           (not input_is_token and pool.usd_reserve == 0):
             raise ValidationError("Swap with empty reserve")

        # --- WALLED GARDEN VALIDATION LOGIC ---
        # Rule 1: Enforce Minimum Transaction Value ($1.00)
        if pool.token_reserve > 0:
            current_price_decimal = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
        else:
            current_price_decimal = Decimal(0)

        if input_is_token:
            usd_value_of_input_int = int((Decimal(amount_in) * current_price_decimal))
        else: # Input is USD
            usd_value_of_input_int = amount_in
        
        if usd_value_of_input_int < (1 * TOKEN_UNIT):
            raise ValidationError("below the $1.00 minimum")

        # Rule 2: Enforce Maximum Transaction Size (50% of pool)
        if input_is_token:
            if amount_in >= pool.token_reserve / 2:
                raise ValidationError("Transaction size is too large and exceeds the 50% maximum pool limit.")
        else: # Input is USD
            if amount_in >= pool.usd_reserve / 2:
                raise ValidationError("Transaction size is too large and exceeds the 50% maximum pool limit.")

        # --- BALANCE CHECK ---
        if input_is_token:
            if sender_account['balances']['native'] < amount_in:
                raise ValidationError("Insufficient native token balance for swap.")
        else:
            if sender_account['balances']['usd'] < amount_in:
                raise ValidationError("Insufficient USD token balance for swap.")

        # --- SWAP CALCULATION & SLIPPAGE ---
        amount_out = pool.get_swap_output(amount_in, input_is_token)
        if amount_out < min_out:
            raise ValidationError(f"Output ({amount_out}) is less than minimum output ({min_out}).")

        # --- APPLY SWAP ---
        actual_output = pool.apply_swap(amount_in, input_is_token)
        
        # Update account balances
        if input_is_token:
            sender_account['balances']['native'] -= amount_in
            sender_account['balances']['usd'] += actual_output
        else:
            sender_account['balances']['usd'] -= amount_in
            sender_account['balances']['native'] += actual_output
        
        self._set_liquidity_pool_state(pool, trie)

    def _process_stake(self, tx: Transaction, trie: Trie, sender_address: bytes, sender_account: dict):
        """Processes a stake transaction."""
        amount = tx.data['amount']
        if sender_account['balances']['native'] < amount:
            raise ValidationError("Insufficient native funds for stake.")
        
        sender_account['balances']['native'] -= amount
        
        validator_set = self._get_validator_set(trie)
        sender_hex = sender_address.hex()
        validator_set[sender_hex] = validator_set.get(sender_hex, 0) + amount
        self._set_validator_set(validator_set, trie)
        self.leader_scheduler = LeaderScheduler(validator_set)

    def _process_unstake(self, tx: Transaction, trie: Trie, sender_address: bytes, sender_account: dict):
        """Processes an unstake transaction."""
        amount = tx.data['amount']
        addr_hex = sender_address.hex()
        
        validator_set = self._get_validator_set(trie)
        if validator_set.get(addr_hex, 0) < amount:
            raise ValidationError("Insufficient stake to unstake that amount.")
            
        validator_set[addr_hex] -= amount
        if validator_set[addr_hex] == 0:
            del validator_set[addr_hex]
        self._set_validator_set(validator_set, trie)
        self.leader_scheduler = LeaderScheduler(validator_set)
        
        sender_account['balances']['native'] += amount

    # ----------------------------------------------------------------------
    # ORACLE REGISTRATION
    # ----------------------------------------------------------------------
    def _process_oracle_register(self, tx, trie):
        sender_addr = public_key_to_address(tx.sender_public_key)
        sender_acc  = self._get_account(sender_addr, trie)

        if sender_acc["balances"]["native"] < ORACLE_BOND:
            raise ValidationError("Insufficient bond for oracle registration")

        sender_acc["balances"]["native"] -= ORACLE_BOND
        
        # oracle_id is a short string, e.g. hex of first 8 bytes of pubkey
        oracle_id = generate_hash(tx.sender_public_key)[:16].hex()
        self.oracle_pubkey_to_id[tx.sender_public_key] = oracle_id
        self.oracle_stakes[oracle_id] = ORACLE_BOND

        self._set_account(sender_addr, sender_acc, trie)
        self._set_oracle_stakes(self.oracle_stakes, trie)

    # ----------------------------------------------------------------------
    # ORACLE UNREGISTER
    # ----------------------------------------------------------------------
    def _process_oracle_unregister(self, tx, trie):
        if tx.sender_public_key not in self.oracle_stakes:
            raise ValidationError("Not a registered oracle")
        sender_addr = public_key_to_address(tx.sender_public_key)
        sender_acc  = self._get_account(sender_addr, trie)

        sender_acc["balances"]["native"] += self.oracle_stakes[tx.sender_public_key]
        del self.oracle_stakes[tx.sender_public_key]
        del self.oracle_pubkey_to_id[tx.sender_public_key]

        self._set_account(sender_addr, sender_acc, trie)

    # ----------------------------------------------------------------------
    # ORACLE NEW ROUND (admin only)
    # ----------------------------------------------------------------------
    def _process_oracle_new_round(self, tx, trie):
        sender_addr = public_key_to_address(tx.sender_public_key)
        if sender_addr != self.reserve_admin_address:
            raise ValidationError("Only Reserve Admin can start oracle round")
        self.current_oracle_round += 1

    # ----------------------------------------------------------------------
    # ORACLE SUBMISSION
    # ----------------------------------------------------------------------
    def _process_oracle_submit(self, tx, trie):
        payload   = tx.data["payload"]
        signature = bytes.fromhex(tx.data["signature"])
        round_id  = tx.data["round_id"]

        # 1. Verify signature
        if not verify_signature(tx.sender_public_key, signature,
                                json.dumps(payload, sort_keys=True).encode()):
            raise ValidationError("Invalid oracle signature")

        # 2. Must be registered and bonded
        oracle_id = self.oracle_pubkey_to_id.get(tx.sender_public_key)
        if not oracle_id:
            raise ValidationError("Oracle not registered")
        if oracle_id not in self.oracle_stakes:
            raise ValidationError("Oracle not bonded")
    
        # 3. Load / create round
        round = self._get_oracle_round(round_id, trie)        # 4. Prevent duplicates
        if oracle_id in round.submissions:
            raise ValidationError("Duplicate submission")
 
        round.submissions[oracle_id] = payload
        self._set_oracle_round(round_id, round, trie)

        # 5. Try to finalize when quorum reached
        if len(round.submissions) >= ORACLE_QUORUM and not round.finalized:
            self._finalize_oracle_round(round_id, round, trie)

    # ----------------------------------------------------------------------
    # FINALIZATION (median + deviation + slashing)
    # ----------------------------------------------------------------------
    def _finalize_oracle_round(self, round_id, round, trie):
        # Gather numeric values
        values = []
        sample_payload = next(iter(round.submissions.values()))
        is_price = sample_payload["type"] == "PRICE_UPDATE"

        for payload in round.submissions.values():
            val = payload["usd_price"] if is_price else payload["reward_usd"]
            values.append(val)

        if not values:
            return

        values.sort()
        median = values[len(values)//2]
        max_dev = median * ORACLE_MAX_DEVIATION_PCT // 100
        valid = [v for v in values if abs(v - median) <= max_dev]

        if len(valid) < ORACLE_QUORUM:
            return  # not enough consensus

        # ---- Finalize ----
        round.finalized   = True
        round.final_value = median
        round.finalized_at = int(time.time())
        self._set_oracle_round(round_id, round, trie)

        # ---- Apply to chain state ----
        if is_price:
            tokenomics = self._get_tokenomics_state(trie)
            tokenomics.usd_price = median
            self._set_tokenomics_state(tokenomics, trie)
        else:
            self._apply_game_reward(round, trie)

        # ---- Slash outliers ----
        for oracle_id, payload in round.submissions.items():
            val = payload["usd_price"] if is_price else payload["reward_usd"]
            if abs(val - median) > max_dev:
                self._slash_oracle(oracle_id, trie)

    # ----------------------------------------------------------------------
    # GAME REWARD MINTING
    # ----------------------------------------------------------------------
    def _apply_game_reward(self, round, trie):
        # All payloads should have the same winner
        winner_addr_hex = None
        for payload in round.submissions.values():
            if payload.get("winner"):
                winner_addr_hex = payload["winner"]
                break
        if not winner_addr_hex:
            return

        winner_addr = bytes.fromhex(winner_addr_hex)
        acc = self._get_account(winner_addr, trie)
        acc["balances"]["native"] += round.final_value
        self._set_account(winner_addr, acc, trie)

        tokenomics = self._get_tokenomics_state(trie)
        tokenomics.total_minted += round.final_value
        self._set_tokenomics_state(tokenomics, trie)

    # ----------------------------------------------------------------------
    # SLASHING
    # ----------------------------------------------------------------------
    def _slash_oracle(self, oracle_id, trie):
        # reverse lookup
        pubkey = next((k for k, v in self.oracle_pubkey_to_id.items() if v == oracle_id), None)
        if not pubkey:
            return
        stake = self.oracle_stakes[pubkey]
        slash = stake * ORACLE_SLASH_PERCENT // 100
        self.oracle_stakes[pubkey] -= slash
        if self.oracle_stakes[pubkey] == 0:
            del self.oracle_stakes[pubkey]
            del self.oracle_pubkey_to_id[pubkey]

    def _slash_validator(self, validator_address: str, trie: Trie):
        """Slashes a validator for a consensus offense."""
        validators = self._get_validator_set(trie)
        if validator_address not in validators:
            return

        stake = validators[validator_address]
        del validators[validator_address]
        self._set_validator_set(validators, trie)

        # Burn the validator's stake
        tokenomics = self._get_tokenomics_state(trie)
        tokenomics.total_supply -= stake
        tokenomics.total_burned += stake
        self._set_tokenomics_state(tokenomics, trie)

        logger.warning(f"Validator {validator_address} slashed for consensus offense.")

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