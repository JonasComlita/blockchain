"""
A persistent blockchain with improved security and state management.
Simplified: Game logic moved off-chain, AMM for price discovery.
"""
import msgpack
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
TREASURY_ADDRESS = b'\x00' * 19 + b'\xFF'

# Configuration constants
TOKEN_UNIT = 1_000_000
CHECKPOINT_INTERVAL = 100
MAX_BLOCK_SIZE = 1_000_000
MAX_TXS_PER_BLOCK = 1000
MIN_STAKE_AMOUNT = 100 * TOKEN_UNIT
SLASH_PERCENTAGE = 50


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
        """Retrieves an account from state."""
        encoded_account = trie.get(address)
        if encoded_account:
            data = msgpack.unpackb(encoded_account, raw=False)
            data['balance'] = int(data.get('balance', 0))
            return data
        return {'balance': 0, 'nonce': 0}
    
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
        """Processes a transaction with proper validation."""
        sender_address = public_key_to_address(tx.sender_public_key)
        sender_account = self._get_account(sender_address, trie)

        logger.info(f"Processing transaction: type={tx.tx_type}, sender={sender_address.hex()}, nonce={tx.nonce}")

        if tx.nonce != sender_account['nonce']:
            logger.warning(f"Invalid nonce. Expected: {sender_account['nonce']}, Got: {tx.nonce}")
            return False
        
        sender_account['nonce'] += 1
        sender_balance = int(sender_account.get('balance', 0))
        tx_fee = int(tx.fee)

        try:
            if tx.tx_type == 'TRANSFER':
                amount = int(tx.data.get('amount', 0))
                recipient_address_hex = tx.data.get('recipient')
                
                if not recipient_address_hex or amount <= 0:
                    return False
                
                recipient_address = bytes.fromhex(recipient_address_hex)
                total_cost = amount + tx_fee
                
                if sender_balance < total_cost:
                    return False

                sender_balance -= total_cost
                sender_account['balance'] = sender_balance
                
                recipient_account = self._get_account(recipient_address, trie)
                recipient_balance = int(recipient_account.get('balance', 0))
                recipient_balance += amount
                recipient_account['balance'] = recipient_balance
                
                self._set_account(recipient_address, recipient_account, trie)

            elif tx.tx_type == 'SWAP':
                input_amount = int(tx.data.get('input_amount', 0))
                input_is_token = bool(tx.data.get('input_is_token', True))
                min_output = int(tx.data.get('min_output', 0))
                
                if input_amount <= 0:
                    return False
                
                pool = self._get_liquidity_pool_state(trie)
                output_amount = pool.get_swap_output(input_amount, input_is_token)
                
                if output_amount < min_output:
                    logger.warning(f"Slippage too high: {output_amount} < {min_output}")
                    return False
                
                if input_is_token:
                    total_cost = input_amount + tx_fee
                    if sender_balance < total_cost:
                        return False
                    
                    sender_balance -= total_cost
                    sender_account['balance'] = sender_balance
                    
                    pool.token_reserve += input_amount
                    pool.usd_reserve -= output_amount
                    
                    tokenomics = self._get_tokenomics_state(trie)
                    tokenomics.total_usd_out += Decimal(output_amount) / TOKEN_UNIT
                    self._set_tokenomics_state(tokenomics, trie)
                    
                else:
                    if sender_balance < tx_fee:
                        return False
                    
                    sender_balance -= tx_fee
                    sender_balance += output_amount
                    sender_account['balance'] = sender_balance
                    
                    pool.usd_reserve += input_amount
                    pool.token_reserve -= output_amount
                    
                    tokenomics = self._get_tokenomics_state(trie)
                    tokenomics.total_usd_in += Decimal(input_amount) / TOKEN_UNIT
                    self._set_tokenomics_state(tokenomics, trie)
                
                self._set_liquidity_pool_state(pool, trie)

            elif tx.tx_type == 'ADD_LIQUIDITY':
                token_amount = int(tx.data.get('token_amount', 0))
                usd_amount = int(tx.data.get('usd_amount', 0))
                
                if token_amount <= 0 or usd_amount <= 0:
                    return False
                
                pool = self._get_liquidity_pool_state(trie)
                
                if pool.lp_token_supply == 0:
                    lp_tokens = int((token_amount * usd_amount) ** 0.5)
                else:
                    lp_tokens = min(
                        (token_amount * pool.lp_token_supply) // pool.token_reserve,
                        (usd_amount * pool.lp_token_supply) // pool.usd_reserve
                    )
                
                total_cost = token_amount + tx_fee
                if sender_balance < total_cost:
                    return False
                
                sender_balance -= total_cost
                sender_account['balance'] = sender_balance
                
                pool.token_reserve += token_amount
                pool.usd_reserve += usd_amount
                pool.lp_token_supply += lp_tokens
                
                sender_account['lp_tokens'] = sender_account.get('lp_tokens', 0) + lp_tokens
                
                self._set_liquidity_pool_state(pool, trie)

            elif tx.tx_type == 'REMOVE_LIQUIDITY':
                lp_tokens = int(tx.data.get('lp_tokens', 0))
                
                if lp_tokens <= 0:
                    return False
                
                user_lp_tokens = sender_account.get('lp_tokens', 0)
                if user_lp_tokens < lp_tokens:
                    return False
                
                pool = self._get_liquidity_pool_state(trie)
                
                token_amount = (lp_tokens * pool.token_reserve) // pool.lp_token_supply
                usd_amount = (lp_tokens * pool.usd_reserve) // pool.lp_token_supply
                
                if sender_balance < tx_fee:
                    return False
                
                sender_balance -= tx_fee
                sender_balance += token_amount
                sender_account['balance'] = sender_balance
                sender_account['lp_tokens'] = user_lp_tokens - lp_tokens
                
                pool.token_reserve -= token_amount
                pool.usd_reserve -= usd_amount
                pool.lp_token_supply -= lp_tokens
                
                self._set_liquidity_pool_state(pool, trie)

            elif tx.tx_type == 'DISTRIBUTE_REWARDS':
                if sender_address != self.game_oracle_address:
                    logger.warning(f"Unauthorized DISTRIBUTE_REWARDS from {sender_address.hex()}")
                    return False
                
                rewards = tx.data.get('rewards', [])
                if not rewards or not isinstance(rewards, list):
                    return False
                
                treasury_account = self._get_account(TREASURY_ADDRESS, trie)
                treasury_balance = int(treasury_account.get('balance', 0))
                
                total_reward = sum(int(r.get('amount', 0)) for r in rewards)
                
                if treasury_balance < total_reward + tx_fee:
                    logger.warning(f"Insufficient treasury balance: {treasury_balance} < {total_reward}")
                    return False
                
                treasury_balance -= total_reward + tx_fee
                treasury_account['balance'] = treasury_balance
                self._set_account(TREASURY_ADDRESS, treasury_account, trie)
                
                for reward in rewards:
                    recipient_hex = reward.get('recipient')
                    amount = int(reward.get('amount', 0))
                    
                    if not recipient_hex or amount <= 0:
                        continue
                    
                    recipient_address = bytes.fromhex(recipient_hex)
                    recipient_account = self._get_account(recipient_address, trie)
                    recipient_balance = int(recipient_account.get('balance', 0))
                    recipient_account['balance'] = recipient_balance + amount
                    self._set_account(recipient_address, recipient_account, trie)
                
                logger.info(f"Distributed {total_reward} tokens to {len(rewards)} winners")

            elif tx.tx_type == 'STAKE':
                amount = int(tx.data.get('amount', 0))
                vrf_pub_key_hex = tx.data.get('vrf_pub_key')
                
                total_cost = amount + tx_fee
                if sender_balance < total_cost or amount < MIN_STAKE_AMOUNT or not vrf_pub_key_hex:
                    return False
                
                sender_balance -= total_cost
                sender_account['balance'] = sender_balance
                
                if 'vrf_pub_key' not in sender_account:
                    sender_account['vrf_pub_key'] = vrf_pub_key_hex
                
                validators = self._get_validator_set(trie)
                sender_hex = sender_address.hex()
                prev_stake = int(validators.get(sender_hex, 0))
                validators[sender_hex] = prev_stake + amount
                self._set_validator_set(validators, trie)

            elif tx.tx_type == 'UNSTAKE':
                amount = int(tx.data.get('amount', 0))
                if amount <= 0:
                    return False

                if sender_balance < tx_fee:
                    return False

                validators = self._get_validator_set(trie)
                sender_hex = sender_address.hex()
                prev_stake = int(validators.get(sender_hex, 0))
                
                if prev_stake < amount:
                    return False
                
                sender_balance -= tx_fee
                new_stake = prev_stake - amount
                sender_balance += amount
                sender_account['balance'] = sender_balance
                
                if new_stake <= 0:
                    if sender_hex in validators:
                        del validators[sender_hex]
                else:
                    validators[sender_hex] = new_stake
                
                self._set_validator_set(validators, trie)

            elif tx.tx_type == 'ATTEST':
                block_hash_hex = tx.data.get('block_hash')
                validators = self._get_validator_set(trie)
                if sender_address.hex() not in validators:
                    return False

                if sender_balance < tx_fee:
                    return False
                sender_balance -= tx_fee
                sender_account['balance'] = sender_balance

                attestations = self._get_attestations(trie)
                if block_hash_hex not in attestations:
                    attestations[block_hash_hex] = []
                
                if sender_address.hex() not in attestations[block_hash_hex]:
                    attestations[block_hash_hex].append(sender_address.hex())
                
                self._set_attestations(attestations, trie)
                self.latest_attestations[sender_address.hex()] = block_hash_hex

            elif tx.tx_type == 'SLASH':
                header1_dict = tx.data.get('header1')
                header2_dict = tx.data.get('header2')

                if not header1_dict or not header2_dict:
                    return False
                
                header1 = BlockHeader(**header1_dict)
                header2 = BlockHeader(**header2_dict)

                if header1.height != header2.height or \
                   header1.producer != header2.producer or \
                   header1.calculate_hash() == header2.calculate_hash():
                    return False
                
                offender_address = public_key_to_address(header1.producer)
                validators = self._get_validator_set(trie)
                offender_hex = offender_address.hex()
                
                if offender_hex in validators:
                    staked_amount = int(validators[offender_hex])
                    config = self._get_config()
                    slash_percentage = int(config.get('slash_percentage', SLASH_PERCENTAGE))
                    slashed_amount = (staked_amount * slash_percentage) // 100
                    
                    new_stake = staked_amount - slashed_amount
                    if new_stake <= 0:
                        del validators[offender_hex]
                    else:
                        validators[offender_hex] = new_stake
                    
                    self._set_validator_set(validators, trie)
                    
                    if sender_balance < tx_fee:
                        return False
                    sender_balance -= tx_fee
                    sender_balance += slashed_amount
                    sender_account['balance'] = sender_balance

            else:
                logger.warning(f"Unknown transaction type: {tx.tx_type}")
                return False
                
        except Exception as e:
            logger.error(f"Exception in _process_transaction for {tx.tx_type}: {e}", exc_info=True)
            return False

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