"""
Pipelined Block Producer
"""
import time
import threading
from crypto_v2.core import Block
from crypto_v2.crypto import public_key_to_address

class BlockProducer(threading.Thread):
    def __init__(self, blockchain, mempool, poh_generator, key_pair):
        super().__init__()
        self.blockchain = blockchain
        self.mempool = mempool
        self.poh_generator = poh_generator
        self.key_pair = key_pair
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            time.sleep(1)  # Wait for a short time before trying to produce a block
            
            latest_block = self.blockchain.get_latest_block()
            leader = self.blockchain.leader_scheduler.get_leader(latest_block.hash)
            my_address = public_key_to_address(self.key_pair['pub_key_pem']).hex()

            if leader == my_address:
                # It's our turn to produce a block
                transactions = self.mempool.get_pending_transactions()
                
                # Record the transactions in the PoH sequence
                for tx in transactions:
                    self.poh_generator.record_event(tx.id)
                
                poh_sequence, _ = self.poh_generator.get_proof()
                
                # Create the new block
                new_block = Block(
                    parent_hash=latest_block.hash,
                    state_root=b'',  # This will be calculated by the blockchain
                    transactions=transactions,
                    poh_sequence=poh_sequence,
                    height=latest_block.height + 1,
                    producer_pubkey=self.key_pair['pub_key_pem'].hex(),
                    vrf_proof=b'',  # This should be the VRF proof
                    vrf_pub_key=b'',  # This should be the VRF public key
                    poh_initial=poh_sequence[0][0],
                )
                
                # Sign the block
                new_block.sign_block(self.key_pair['priv_key'])
                
                # Add the block to the blockchain
                if self.blockchain.add_block(new_block):
                    print(f"Produced block {new_block.height}")
                else:
                    print(f"Failed to produce block {new_block.height}")

    def stop(self):
        self.running = False
