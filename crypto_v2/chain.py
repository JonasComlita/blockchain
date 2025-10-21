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
from typing import Optional
from decimal import Decimal
from crypto_v2.core import Block, Transaction, BlockHeader
from crypto_v2.db import DB
from crypto_v2.crypto import generate_hash, public_key_to_address
from crypto_v2.trie import Trie, BLANK_ROOT
from crypto_v2.poh import PoHRecorder, verify_poh_sequence
from crypto_v2.consensus import is_valid_leader
from crypto_v2.tokenomics_state import TokenomicsState
from crypto_v2.amm_state import LiquidityPoolState

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
TREASURY_ADDRESS = b'\x00' * 19 + b'\xFF'

# Configuration constants
TOKEN_UNIT = 1_000_000
CHECKPOINT_INTERVAL = 100
MAX_BLOCK_SIZE = 1_000_000
MAX_TXS_PER_BLOCK = 1000
MIN_STAKE_AMOUNT = 100 * TOKEN_UNIT
SLASH_PERCENTAGE = 50

# Configuration constants for the Bonding Curve
BONDING_CURVE_BASE_PRICE = Decimal('0.10') # $0.10
BONDING_CURVE_SLOPE = Decimal('0.00000001')


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


class Blockchain:
    def __init__(self, db_path: str = None, db: DB = None, genesis_block: Block = None, 
                 chain_id: int = 1, game_oracle_pubkey: bytes = None):
        if db:
            self.db = db
        elif db_path:
            self.db = DB(db_path)
        else:
            raise ValueError("Either db_path or a DB object must be provided.")
            
        self.chain_id = chain_id
        self.block_pool: dict[bytes, Block] = {}
        self.game_oracle_address = public_key_to_address(game_oracle_pubkey) if game_oracle_pubkey else GAME_ORACLE_ADDRESS
        
        head_hash = self.db.get(b'head')
        if head_hash is None:
            if genesis_block is None:
                genesis = self._create_genesis_block()
            else:
                genesis = genesis_block
                
            self._store_block(genesis)
            self.db.put(b'head', genesis.hash)
            self.head_hash = genesis.hash
        else:
            self.head_hash = head_hash
        
        self.latest_attestations = {}
        
        latest_block = self.get_latest_block()
        self.state_trie = Trie(self.db, root_hash=latest_block.state_root)
        
        self._initialize_config()

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

    def _create_genesis_block(self) -> Block:
        """Creates the genesis block."""
        initial_hash = b'\x00' * 32
        poh_recorder = PoHRecorder(initial_hash)
        poh_recorder.tick()

        return Block(
            parent_hash=b'\x00' * 32,
            state_root=BLANK_ROOT,
            transactions=[],
            poh_sequence=poh_recorder.sequence,
            height=0,
            producer=b'genesis',
            vrf_proof=b'genesis',
            timestamp=0.0,
            signature=b'genesis'
        )

    def _store_block(self, block: Block):
        """Serializes and stores a block."""
        block_data = msgpack.packb(block.to_dict(), use_bin_type=True)
        self.db.put(block.hash, block_data)
        
        height_key = b'height:' + str(block.height).encode()
        self.db.put(height_key, block.hash)

    def get_block(self, block_hash: bytes) -> Block | None:
        """Retrieves a block from the database."""
        block_data = self.db.get(block_hash)
        if block_data is None:
            return None
        
        block_dict = msgpack.unpackb(block_data, raw=False)
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
        try:
            self._validate_block(block)
            
            original_state_root = self.state_trie.root_hash
            temp_trie = Trie(self.db, root_hash=original_state_root)
            
            try:
                for tx in block.transactions:
                    if not self._process_transaction(tx, temp_trie):
                        raise ValidationError(f"Invalid transaction: {tx.id.hex()}")
                
                if temp_trie.root_hash != block.state_root:
                    raise ValidationError(
                        f"State root mismatch. Expected: {block.state_root.hex()}, "
                        f"Got: {temp_trie.root_hash.hex()}"
                    )
                
                self._store_block(block)
                self.db.put(b'head', block.hash)
                self.head_hash = block.hash
                
                self.state_trie = Trie(self.db, root_hash=block.state_root)
                
                logger.info(f"Block {block.height} added successfully: {block.hash.hex()[:16]}")
                return True
                
            except ValidationError as e:
                logger.error(f"Block validation failed: {e}")
                return False
                
        except ValidationError as e:
            logger.error(f"Block rejected: {e}")
            return False

    def _validate_block(self, block: Block):
        """Comprehensive block validation."""
        latest_block = self.get_latest_block()
        
        if block.parent_hash != latest_block.hash:
            raise ValidationError("Invalid parent hash")
        
        if block.height != latest_block.height + 1:
            raise ValidationError("Invalid block height")
        
        if block.timestamp <= latest_block.timestamp:
            raise ValidationError("Block timestamp must be greater than parent")
        
        block_size = len(msgpack.packb(block.to_dict(), use_bin_type=True))
        if block_size > MAX_BLOCK_SIZE:
            raise ValidationError(f"Block too large: {block_size} bytes")
        
        if len(block.transactions) > MAX_TXS_PER_BLOCK:
            raise ValidationError(f"Too many transactions: {len(block.transactions)}")
        
        if block.height > 0 and not block.verify_signature():
            raise ValidationError("Invalid block signature")
        
        validators = self._get_validator_set(self.state_trie)
        producer_addr = public_key_to_address(block.producer)
        producer_account = self._get_account(producer_addr, self.state_trie)
        
        vrf_pub_key_hex = producer_account.get('vrf_pub_key')
        if not vrf_pub_key_hex and block.height > 0:
            raise ValidationError("Producer has no VRF pubkey")
        
        if block.height > 0 and not is_valid_leader(
            block.producer,
            block.vrf_proof,
            validators,
            latest_block.hash,
            vrf_pub_key_hex,
            producer_addr.hex(),
            lambda addr: self._get_account(addr, self.state_trie)
        ):
            raise ValidationError("Invalid block producer")
        
        if latest_block.poh_sequence:
            initial_hash = latest_block.poh_sequence[-1][0]
        else:
            initial_hash = latest_block.hash
            
        if not verify_poh_sequence(initial_hash, block.poh_sequence):
            raise ValidationError("Invalid Proof of History sequence")
        
        seen_tx_ids = set()
        for tx in block.transactions:
            if tx.id in seen_tx_ids:
                raise ValidationError(f"Duplicate transaction in block: {tx.id.hex()}")
            seen_tx_ids.add(tx.id)
            
            is_valid, error = tx.validate_basic()
            if not is_valid:
                raise ValidationError(f"Invalid transaction: {error}")
            
            if tx.chain_id != self.chain_id:
                raise ValidationError(f"Wrong chain ID: {tx.chain_id}")

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

    def _get_account(self, address: bytes, trie: Trie) -> dict:
        """Get account data from the trie, providing a default structure if none exists."""
        encoded_account = trie.get(address)
        if encoded_account == b'':
            # Default structure for a new account with multi-asset balances
            return {
                'balances': {
                    'native': 0,  # Represents the native GAME-Token
                    'usd': 0         # Represents the USD-Token stablecoin
                },
                'nonce': 0,
                'lp_tokens': 0
            }
        return msgpack.unpackb(encoded_account)
    
    def get_account(self, address: bytes, state_trie=None) -> dict:
        """Public method to get an account from the state."""
        trie = state_trie if state_trie is not None else self.state_trie
        return self._get_account(address, trie)

    def _set_account(self, address: bytes, account: dict, trie: Trie):
        """Sets an account in state."""
        encoded_account = msgpack.packb(account, use_bin_type=True)
        trie.set(address, encoded_account)

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

    def _process_transaction(self, tx: Transaction, trie: Trie) -> bool:
        """
        Process a single transaction and update the state trie.
        This is the heart of the state transition logic.
        """
        sender_address = public_key_to_address(tx.sender_pubkey)
        sender_account = self._get_account(sender_address, trie)

        # 1. Verify nonce
        if tx.nonce != sender_account['nonce']:
            raise ValidationError(f"Invalid nonce. Expected {sender_account['nonce']}, got {tx.nonce}")

        # 2. Increment nonce
        sender_account['nonce'] += 1

        # 3. Deduct fee
        sender_account['balances']['native'] -= tx.fee
        if sender_account['balances']['native'] < 0:
            raise ValidationError("Insufficient funds for fee")

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
            recipient_account = self._get_account(recipient_address, trie)
            recipient_account['balances'][token_type] += amount
            self._set_account(recipient_address, recipient_account, trie)

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
            # Example of updating existing logic for the new balances structure
            amount = tx.data['amount']
            if sender_account['balances']['native'] < amount:
                raise ValidationError("Insufficient native funds for stake.")
            
            sender_account['balances']['native'] -= amount
            
            validator_set = self._get_validator_set(trie)
            sender_hex = sender_address.hex()
            validator_set[sender_hex] = validator_set.get(sender_hex, 0) + amount
            self._set_validator_set(validator_set, trie)

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
            price_per_token = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
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
            pool = self._get_liquidity_pool_state(trie)
            input_amount = tx.data['amount_in']
            min_output = tx.data['min_amount_out']
            input_is_token = tx.data['token_in'] == 'native'

            # --- NEW: WALLED GARDEN VALIDATION LOGIC ---

            # Rule 1: Enforce Minimum Transaction Value ($1.00)
            # We must use the integer representation for comparison
            if pool.token_reserve > 0:
                current_price_decimal = Decimal(pool.usd_reserve) / Decimal(pool.token_reserve)
            else:
                current_price_decimal = Decimal(0)

            if input_is_token:
                usd_value_of_input_int = int((Decimal(input_amount) * current_price_decimal))
            else: # Input is USD
                usd_value_of_input_int = input_amount
            
            if usd_value_of_input_int < (1 * TOKEN_UNIT):
                raise ValidationError(f"Transaction value is below the $1.00 minimum.")

            # Rule 2: Enforce Maximum Transaction Size (<50% of Pool Reserve)
            output_amount = pool.get_swap_output(input_amount, input_is_token=input_is_token)
            
            if input_is_token: # User is selling GAME-Token, claiming USD-Token
                target_reserve = pool.usd_reserve
            else: # User is buying GAME-Token, claiming GAME-Token
                target_reserve = pool.token_reserve

            if output_amount >= (target_reserve // 2): # Integer division for safety
                raise ValidationError("Transaction size is too large and exceeds the 50% maximum pool limit.")

            # --- END OF NEW VALIDATION ---

            if input_is_token:
                if sender_account['balances']['native'] < input_amount:
                    raise ValidationError("Insufficient native token balance for swap.")
                sender_account['balances']['native'] -= input_amount
                output_amount = pool.get_swap_output(input_amount, input_is_token=True)
                if output_amount < min_output:
                    raise ValidationError("Swap would result in less than minimum output.")
                sender_account['balances']['usd'] += output_amount
                pool.token_reserve += input_amount
                pool.usd_reserve -= output_amount
            else: # Input is USD
                if sender_account['balances']['usd'] < input_amount:
                    raise ValidationError("Insufficient USD token balance for swap.")
                sender_account['balances']['usd'] -= input_amount
                output_amount = pool.get_swap_output(input_amount, input_is_token=False)
                if output_amount < min_output:
                    raise ValidationError("Swap would result in less than minimum output.")
                sender_account['balances']['native'] += output_amount
                pool.usd_reserve += input_amount
                pool.token_reserve -= output_amount
            
            self._set_liquidity_pool_state(pool, trie)

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

        # --- End of transaction-specific logic ---

        # 4. Save the updated sender account
        self._set_account(sender_address, sender_account, trie)

        return True

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

    def _get_liquidity_pool_state(self, trie: Trie) -> LiquidityPoolState:
        """Retrieve liquidity pool state from trie."""
        encoded = trie.get(AMM_POOL_ADDRESS)
        if encoded:
            data = msgpack.unpackb(encoded, raw=False)
            return LiquidityPoolState(data)
        return LiquidityPoolState()
    
    def _set_liquidity_pool_state(self, state: LiquidityPoolState, trie: Trie):
        """Store liquidity pool state in trie."""
        encoded = msgpack.packb(state.to_dict(), use_bin_type=True)
        trie.set(AMM_POOL_ADDRESS, encoded)

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