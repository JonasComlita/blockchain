"""
Validator node implementation with block production and attestation.
"""
import asyncio
import time
import logging
from typing import Optional
from crypto_v2.chain import Blockchain
from crypto_v2.core import Block, Transaction
from crypto_v2.poh import PoHRecorder
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address,
    generate_vrf_keypair,
    vrf_prove
)
from crypto_v2.consensus import LeaderScheduler
from crypto_v2.p2p import P2PNode, create_message, MSG_NEW_BLOCK
from crypto_v2.config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ValidatorNode:
    """
    A validator node that can produce blocks and attest to the chain.
    """
    
    def __init__(self, 
                 blockchain: Blockchain,
                 p2p_node: P2PNode,
                 validator_private_key,
                 validator_public_key,
                 vrf_private_key,
                 config: Config):
        self.blockchain = blockchain
        self.p2p_node = p2p_node
        self.validator_private_key = validator_private_key
        self.validator_public_key = validator_public_key
        self.validator_public_key_pem = serialize_public_key(validator_public_key)
        self.validator_address = public_key_to_address(self.validator_public_key_pem)
        self.vrf_private_key = vrf_private_key
        self.config = config
        
        self.is_running = False
        self.block_production_task = None
        self.attestation_task = None
        
        logger.info(f"Validator initialized: {self.validator_address.hex()}")
    
    def is_validator(self) -> bool:
        """Check if this node is currently a validator."""
        validators = self.blockchain._get_validator_set(self.blockchain.state_trie)
        return self.validator_address.hex() in validators
    
    def is_leader(self, seed: bytes) -> bool:
        """Check if this node is the leader for the given seed."""
        if not self.is_validator():
            return False
        
        validators = self.blockchain._get_validator_set(self.blockchain.state_trie)
        scheduler = LeaderScheduler(
            validators,
            lambda addr: self.blockchain._get_account(addr, self.blockchain.state_trie)
        )
        
        leader_address = scheduler.get_leader(seed)
        return leader_address == self.validator_address.hex()
    
    async def produce_block(self):
        """Attempt to produce a block if we are the leader."""
        try:
            latest_block = self.blockchain.get_latest_block()
            
            # Check if we are the leader for this slot
            if not self.is_leader(latest_block.hash):
                logger.debug("Not the leader for this slot")
                return
            
            logger.info(f"We are the leader! Producing block {latest_block.height + 1}")
            
            # Get transactions from mempool
            transactions = self.p2p_node.mempool.get_pending_transactions(
                max_txs=self.config.chain.max_txs_per_block
            )
            
            # Validate transactions have valid fees
            valid_txs = []
            for tx in transactions:
                if tx.fee >= self.config.mempool.min_fee:
                    valid_txs.append(tx)
            
            logger.info(f"Selected {len(valid_txs)} transactions for block")
            
            # Create PoH sequence
            if latest_block.poh_sequence:
                initial_hash = latest_block.poh_sequence[-1][0]
            else:
                initial_hash = latest_block.hash
            
            poh_recorder = PoHRecorder(initial_hash)
            for tx in valid_txs:
                poh_recorder.record(tx.id)
            poh_recorder.tick()
            
            # Calculate new state root by processing transactions
            from crypto_v2.trie import Trie
            temp_trie = Trie(self.blockchain.db, root_hash=latest_block.state_root)
            
            processed_txs = []
            for tx in valid_txs:
                if self.blockchain._process_transaction(tx, temp_trie):
                    processed_txs.append(tx)
                else:
                    logger.warning(f"Transaction {tx.id.hex()[:16]} failed processing")
            
            new_state_root = temp_trie.root_hash
            
            # Generate VRF proof
            vrf_proof, _ = vrf_prove(self.vrf_private_key, latest_block.hash)
            
            # Create block
            new_block = Block(
                parent_hash=latest_block.hash,
                state_root=new_state_root,
                transactions=processed_txs,
                poh_sequence=poh_recorder.sequence,
                height=latest_block.height + 1,
                producer=self.validator_public_key_pem,
                vrf_proof=vrf_proof,
                timestamp=time.time()
            )
            
            # Sign the block
            new_block.sign_block(self.validator_private_key)
            
            # Add block to our chain
            if self.blockchain.add_block(new_block):
                logger.info(f"Successfully produced block {new_block.height}: {new_block.hash.hex()[:16]}")
                
                # Remove processed transactions from mempool
                self.p2p_node.mempool.remove_transactions(processed_txs)
                
                # Broadcast block to network
                await self.p2p_node.broadcast(
                    create_message(MSG_NEW_BLOCK, new_block.to_dict())
                )
                
                return new_block
            else:
                logger.error("Failed to add our own block to chain!")
                
        except Exception as e:
            logger.error(f"Error producing block: {e}", exc_info=True)
    
    async def attest_to_head(self):
        """Create an attestation for the current head."""
        try:
            if not self.is_validator():
                logger.debug("Not a validator, skipping attestation")
                return
            
            head = self.blockchain.get_head()
            current_epoch = head.height // self.config.chain.epoch_length
            
            # Create and sign the attestation
            from crypto_v2.chain import Attestation
            attestation = Attestation(
                source_epoch=self.blockchain.finality_state.justified_epoch,
                target_epoch=current_epoch,
                target_hash=head.hash,
                validator_pubkey=self.validator_public_key_pem
            )
            attestation.sign(self.validator_private_key)
            
            # Create attestation transaction
            attest_tx = Transaction(
                sender_public_key=self.validator_public_key_pem,
                tx_type='ATTEST',
                data=attestation.to_dict(),
                nonce=self._get_next_nonce(),
                fee=0,  # Attestations are free
                chain_id=self.config.chain.chain_id
            )
            attest_tx.sign(self.validator_private_key)
            
            # Add to mempool (will be included in next block)
            success, error = self.p2p_node.mempool.add_transaction(attest_tx)
            if success:
                logger.debug(f"Attested to block {head.height}")
            else:
                logger.warning(f"Failed to create attestation: {error}")
                
        except Exception as e:
            logger.error(f"Error creating attestation: {e}")
    
    def _get_next_nonce(self) -> int:
        """Get the next nonce for our validator account."""
        account = self.blockchain._get_account(
            self.validator_address,
            self.blockchain.state_trie
        )
        
        # Check for pending transactions in mempool
        pending_nonces = self.p2p_node.mempool.get_pending_nonces(self.validator_address)
        if pending_nonces:
            return max(pending_nonces) + 1
        
        return account['nonce']
    
    async def block_production_loop(self):
        """Main block production loop."""
        logger.info("Starting block production loop")
        
        while self.is_running:
            try:
                await self.produce_block()
            except Exception as e:
                logger.error(f"Error in block production: {e}")
            
            # Wait for next slot
            await asyncio.sleep(self.config.chain.block_time)
    
    async def attestation_loop(self):
        """Main attestation loop."""
        logger.info("Starting attestation loop")
        
        # Attest more frequently than block production
        attestation_interval = self.config.chain.block_time / 2
        
        while self.is_running:
            try:
                await self.attest_to_head()
            except Exception as e:
                logger.error(f"Error in attestation: {e}")
            
            await asyncio.sleep(attestation_interval)
    
    async def start(self):
        """Start the validator node."""
        self.is_running = True
        
        # Start block production and attestation loops
        self.block_production_task = asyncio.create_task(self.block_production_loop())
        self.attestation_task = asyncio.create_task(self.attestation_loop())
        
        logger.info("Validator node started")
    
    async def stop(self):
        """Stop the validator node."""
        logger.info("Stopping validator node...")
        self.is_running = False
        
        if self.block_production_task:
            self.block_production_task.cancel()
        if self.attestation_task:
            self.attestation_task.cancel()
        
        logger.info("Validator node stopped")
    
    def get_status(self) -> dict:
        """Get validator status information."""
        is_validator = self.is_validator()
        stake = 0
        
        if is_validator:
            validators = self.blockchain._get_validator_set(self.blockchain.state_trie)
            stake = validators.get(self.validator_address.hex(), 0)
        
        return {
            'address': self.validator_address.hex(),
            'is_validator': is_validator,
            'stake': stake,
            'current_height': self.blockchain.get_latest_block().height,
            'mempool_size': len(self.p2p_node.mempool),
        }