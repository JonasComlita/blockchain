"""
Pipelined Block Producer
"""
import time
import threading
from crypto_v2.core import Block
from crypto_v2.crypto import public_key_to_address, vrf_prove, serialize_public_key

class BlockProducer(threading.Thread):
    def __init__(self, blockchain, mempool, poh_generator, key_pair):
        super().__init__()
        self.blockchain = blockchain
        self.mempool = mempool
        self.poh_generator = poh_generator
        
        # Normalize key_pair access
        if isinstance(key_pair, dict):
            self.private_key = key_pair.get('priv_key')
            self.public_key = key_pair.get('pub_key')
            self.vrf_priv_key = key_pair.get('vrf_priv_key')
            self.vrf_pub_key = key_pair.get('vrf_pub_key')
        else:
            raise ValueError("key_pair must be a dict with priv_key, pub_key, vrf_priv_key, vrf_pub_key")
        
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            time.sleep(1)
            
            latest_block = self.blockchain.get_latest_block()
            leader = self.blockchain.leader_scheduler.get_leader(latest_block.hash)
            
            pub_key_pem = serialize_public_key(self.public_key)
            my_address = public_key_to_address(pub_key_pem).hex()

            if leader == my_address:
                # Produce block
                transactions = self.mempool.get_pending_transactions()
                
                for tx in transactions:
                    self.poh_generator.record_event(tx.id)
                
                poh_sequence, _ = self.poh_generator.get_proof()
                
                # Generate VRF proof
                vrf_proof, _ = vrf_prove(self.vrf_priv_key, latest_block.hash)
                
                new_block = Block(
                    parent_hash=latest_block.hash,
                    state_root=b'',  # Will be calculated by blockchain
                    transactions=transactions,
                    poh_sequence=poh_sequence[1:],
                    poh_initial=poh_sequence[0][0],
                    height=latest_block.height + 1,
                    producer_pubkey=pub_key_pem,
                    vrf_proof=vrf_proof,
                    vrf_pub_key=bytes(self.vrf_pub_key),  # ← FIX: Convert to bytes
                )
                
                new_block.sign_block(self.private_key)
                
                if self.blockchain.add_block(new_block):
                    print(f"Produced block {new_block.height}")
                else:
                    print(f"Failed to produce block {new_block.height}")

    def stop(self):
        self.running = False
