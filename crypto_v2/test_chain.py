"""
Comprehensive tests for the improved blockchain implementation.
"""
import unittest
import shutil
import tempfile
import time
from crypto_v2.chain import Blockchain, ValidationError
from crypto_v2.core import Block, Transaction
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address,
    generate_vrf_keypair,
    vrf_prove,
    verify_signature
)
from crypto_v2.trie import Trie
from crypto_v2.poh import PoHRecorder
from crypto_v2.mempool import Mempool


class TestImprovedChain(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.bc = Blockchain(self.test_dir, chain_id=1)

        # Create validator Alice
        self.priv_key_alice, self.pub_key_alice = generate_key_pair()
        self.alice_pem = serialize_public_key(self.pub_key_alice)
        self.alice_addr = public_key_to_address(self.alice_pem)
        self.vrf_priv_alice, self.vrf_pub_alice = generate_vrf_keypair()
        
        # Setup genesis state with Alice as validator
        genesis_trie = self.bc.state_trie
        account = {
            'balance': 10000,
            'nonce': 0,
            'vrf_pub_key': self.vrf_pub_alice.encode().hex()
        }
        self.bc._set_account(self.alice_addr, account, genesis_trie)
        validators = {self.alice_addr.hex(): 1000}
        self.bc._set_validator_set(validators, genesis_trie)
        
        # Update genesis block
        genesis = self.bc.get_latest_block()
        genesis.state_root = genesis_trie.root_hash
        self.bc._store_block(genesis)
        self.bc.db.put(b'head', genesis.hash)
        self.bc.head_hash = genesis.hash
        self.bc.state_trie = genesis_trie

        # Create Bob for testing
        self.priv_key_bob, self.pub_key_bob = generate_key_pair()
        self.bob_pem = serialize_public_key(self.pub_key_bob)
        self.bob_addr = public_key_to_address(self.bob_pem)

    def tearDown(self):
        """Clean up test fixtures."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def _create_and_add_block(self, transactions: list[Transaction]) -> Block:
        """Helper to create and add a block."""
        latest_block = self.bc.get_latest_block()
        
        # Process transactions to get state root
        temp_trie = Trie(self.bc.db, root_hash=latest_block.state_root)
        for tx in transactions:
            self.bc._process_transaction(tx, temp_trie)
        
        # Create PoH sequence
        if latest_block.poh_sequence:
            initial_hash = latest_block.poh_sequence[-1][0]
        else:
            initial_hash = latest_block.hash
        
        poh_recorder = PoHRecorder(initial_hash)
        for tx in transactions:
            poh_recorder.record(tx.id)
        poh_recorder.tick()
        
        # Create VRF proof
        vrf_proof, _ = vrf_prove(self.vrf_priv_alice, latest_block.hash)
        
        # Create block
        block = Block(
            parent_hash=latest_block.hash,
            state_root=temp_trie.root_hash,
            transactions=transactions,
            poh_sequence=poh_recorder.sequence,
            height=latest_block.height + 1,
            producer=self.alice_pem,
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        
        # Sign block
        block.sign_block(self.priv_key_alice)
        
        # Add to chain
        success = self.bc.add_block(block)
        if success:
            self.bc.state_trie = Trie(self.bc.db, root_hash=block.state_root)
        
        return block if success else None

    def test_genesis_block(self):
        """Test genesis block creation."""
        genesis = self.bc.get_latest_block()
        self.assertEqual(genesis.height, 0)
        self.assertEqual(genesis.parent_hash, b'\x00' * 32)
        self.assertIsNotNone(genesis.state_root)

    def test_transaction_signature_verification(self):
        """Test that transaction signatures are verified."""
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 100},
            nonce=0,
            fee=1,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        # Valid signature
        self.assertTrue(tx.verify_signature())
        
        # Invalid signature (tamper with data)
        tx.data['amount'] = 200
        self.assertFalse(tx.verify_signature())

    def test_block_signature_verification(self):
        """Test that block signatures are verified."""
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 100},
            nonce=0,
            fee=1,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([tx])
        self.assertIsNotNone(block)
        self.assertTrue(block.verify_signature())

    def test_transaction_validation(self):
        """Test transaction validation."""
        # Invalid signature
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 100},
            nonce=0,
            fee=1,
            chain_id=1
        )
        is_valid, error = tx.validate_basic()
        self.assertFalse(is_valid)
        self.assertIn("signature", error.lower())
        
        # Valid transaction
        tx.sign(self.priv_key_alice)
        is_valid, error = tx.validate_basic()
        self.assertTrue(is_valid)

    def test_transfer_transaction(self):
        """Test basic transfer transaction."""
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 500},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([tx])
        self.assertIsNotNone(block)
        
        # Verify balances
        alice_account = self.bc._get_account(self.alice_addr, self.bc.state_trie)
        bob_account = self.bc._get_account(self.bob_addr, self.bc.state_trie)
        
        self.assertEqual(alice_account['balance'], 10000 - 500 - 10)
        self.assertEqual(alice_account['nonce'], 1)
        self.assertEqual(bob_account['balance'], 500)

    def test_nonce_enforcement(self):
        """Test that nonce is properly enforced."""
        # Try to use wrong nonce
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 100},
            nonce=5,  # Wrong nonce
            fee=1,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([tx])
        self.assertIsNone(block)  # Should fail

    def test_insufficient_balance(self):
        """Test that insufficient balance is rejected."""
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 20000},  # Too much
            nonce=0,
            fee=1,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([tx])
        self.assertIsNone(block)

    def test_chain_id_enforcement(self):
        """Test that chain ID is enforced."""
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 100},
            nonce=0,
            fee=1,
            chain_id=999  # Wrong chain ID
        )
        tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([tx])
        self.assertIsNone(block)

    def test_stake_and_unstake(self):
        """Test staking and unstaking."""
        # Stake
        stake_tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='STAKE',
            data={'amount': 500, 'vrf_pub_key': self.vrf_pub_alice.encode().hex()},
            nonce=0,
            fee=10,
            chain_id=1
        )
        stake_tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([stake_tx])
        self.assertIsNotNone(block)
        
        validators = self.bc._get_validator_set(self.bc.state_trie)
        self.assertEqual(validators[self.alice_addr.hex()], 1500)  # 1000 + 500
        
        alice_account = self.bc._get_account(self.alice_addr, self.bc.state_trie)
        self.assertEqual(alice_account['balance'], 10000 - 500 - 10)
        
        # Unstake
        unstake_tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='UNSTAKE',
            data={'amount': 300},
            nonce=1,
            fee=10,
            chain_id=1
        )
        unstake_tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([unstake_tx])
        self.assertIsNotNone(block)
        
        validators = self.bc._get_validator_set(self.bc.state_trie)
        self.assertEqual(validators[self.alice_addr.hex()], 1200)  # 1500 - 300
        
        alice_account = self.bc._get_account(self.alice_addr, self.bc.state_trie)
        self.assertEqual(alice_account['balance'], 10000 - 500 - 10 - 10 + 300)

    def test_mempool_functionality(self):
        """Test mempool operations."""
        mempool = Mempool(
            get_account_state=lambda addr: self.bc._get_account(addr, self.bc.state_trie)
        )
        
        # Add valid transaction
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 100},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        success, error = mempool.add_transaction(tx)
        self.assertTrue(success, error)
        self.assertEqual(len(mempool), 1)
        
        # Try to add duplicate
        success, error = mempool.add_transaction(tx)
        self.assertFalse(success)
        
        # Get pending transactions
        pending = mempool.get_pending_transactions()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].id, tx.id)
        
        # Remove transaction
        mempool.remove_transactions([tx])
        self.assertEqual(len(mempool), 0)

    def test_fee_prioritization(self):
        """Test that mempool prioritizes by fee."""
        mempool = Mempool(
            get_account_state=lambda addr: self.bc._get_account(addr, self.bc.state_trie)
        )
        
        # Add transactions with different fees
        for i, fee in enumerate([5, 20, 10, 15]):
            tx = Transaction(
                sender_public_key=self.alice_pem,
                tx_type='TRANSFER',
                data={'recipient': self.bob_addr, 'amount': 10},
                nonce=i,
                fee=fee,
                chain_id=1
            )
            tx.sign(self.priv_key_alice)
            mempool.add_transaction(tx)
        
        # Get transactions (should be sorted by fee)
        pending = mempool.get_pending_transactions()
        fees = [tx.fee for tx in pending]
        
        # Should be sorted descending by fee
        self.assertEqual(fees, sorted(fees, reverse=True))

    def test_block_size_limit(self):
        """Test that block size is limited."""
        # Create many transactions to exceed limit
        transactions = []
        for i in range(2000):  # More than MAX_TXS_PER_BLOCK
            tx = Transaction(
                sender_public_key=self.alice_pem,
                tx_type='TRANSFER',
                data={'recipient': self.bob_addr, 'amount': 1},
                nonce=i,
                fee=1,
                chain_id=1
            )
            tx.sign(self.priv_key_alice)
            transactions.append(tx)
        
        # Should fail due to size limit
        block = self._create_and_add_block(transactions)
        self.assertIsNone(block)

    def test_chain_validation(self):
        """Test full chain validation."""
        # Add some blocks
        for i in range(5):
            tx = Transaction(
                sender_public_key=self.alice_pem,
                tx_type='TRANSFER',
                data={'recipient': self.bob_addr, 'amount': 10},
                nonce=i,
                fee=1,
                chain_id=1
            )
            tx.sign(self.priv_key_alice)
            block = self._create_and_add_block([tx])
            self.assertIsNotNone(block)
        
        # Validate entire chain
        self.assertTrue(self.bc.validate_chain())

    def test_state_rollback_on_failure(self):
        """Test that state rolls back on failed block addition."""
        initial_balance = self.bc._get_account(
            self.alice_addr, 
            self.bc.state_trie
        )['balance']
        
        # Create invalid transaction (insufficient balance)
        tx = Transaction(
            sender_public_key=self.alice_pem,
            tx_type='TRANSFER',
            data={'recipient': self.bob_addr, 'amount': 999999},
            nonce=0,
            fee=1,
            chain_id=1
        )
        tx.sign(self.priv_key_alice)
        
        block = self._create_and_add_block([tx])
        self.assertIsNone(block)
        
        # Balance should be unchanged
        final_balance = self.bc._get_account(
            self.alice_addr,
            self.bc.state_trie
        )['balance']
        self.assertEqual(initial_balance, final_balance)


if __name__ == '__main__':
    unittest.main()