"""
Test PURCHASE transaction type.
Phase 3: Test token purchase with primary/secondary market logic.
"""
import unittest
import shutil
import tempfile
import time
from decimal import Decimal
from crypto_v2.chain import Blockchain, TREASURY_ADDRESS
from crypto_v2.core import Transaction
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address,
    generate_vrf_keypair,
    vrf_prove
)
from crypto_v2.trie import Trie
from crypto_v2.poh import PoHRecorder


class TestPurchaseTransaction(unittest.TestCase):
    def setUp(self):
        """Set up test blockchain with validator."""
        self.test_dir = tempfile.mkdtemp()
        self.bc = Blockchain(self.test_dir, chain_id=1)
        
        # Create validator (Alice) for block production
        self.priv_key_alice, self.pub_key_alice = generate_key_pair()
        self.alice_pem = serialize_public_key(self.pub_key_alice)
        self.alice_address = public_key_to_address(self.alice_pem)
        self.vrf_priv_alice, self.vrf_pub_alice = generate_vrf_keypair()
        
        # Setup genesis state with Alice as validator
        genesis_trie = self.bc.state_trie
        account = {
            'balance': '10000',
            'nonce': 0,
            'vrf_pub_key': self.vrf_pub_alice.encode().hex()
        }
        self.bc._set_account(self.alice_address, account, genesis_trie)
        validators = {self.alice_address.hex(): 1000}
        self.bc._set_validator_set(validators, genesis_trie)
        
        # Update genesis
        genesis = self.bc.get_latest_block()
        genesis.state_root = genesis_trie.root_hash
        self.bc._store_block(genesis)
        self.bc.db.put(b'head', genesis.hash)
        self.bc.head_hash = genesis.hash
        self.bc.state_trie = genesis_trie
        
        # Create buyer (Bob)
        self.priv_key_bob, self.pub_key_bob = generate_key_pair()
        self.bob_pem = serialize_public_key(self.pub_key_bob)
        self.bob_address = public_key_to_address(self.bob_pem)

    def tearDown(self):
        """Clean up."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def _create_and_add_block(self, transactions):
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
        from crypto_v2.core import Block
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
        
        return success

    def test_purchase_primary_market_first_buy(self):
        """Test first purchase mints tokens (primary market)."""
        # Bob buys tokens for $100
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={
                'usd_amount': '100',
                'payment_id': 'stripe_12345'
            },
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertTrue(success)
        
        # Check Bob's balance (should have 100 tokens at $1 each)
        bob_account = self.bc._get_account(self.bob_address, self.bc.state_trie)
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('100'))
        
        # Check tokenomics (100 tokens minted)
        stats = self.bc.get_tokenomics_stats()
        self.assertEqual(Decimal(stats['total_minted']), Decimal('100'))
        self.assertEqual(Decimal(stats['total_usd_in']), Decimal('100'))
        self.assertEqual(Decimal(stats['current_price']), Decimal('1.00'))

    def test_purchase_secondary_market_from_treasury(self):
        """Test purchase from treasury inventory (secondary market)."""
        # First, give treasury some tokens
        temp_trie = Trie(self.bc.db, root_hash=self.bc.state_trie.root_hash)
        self.bc.mint_tokens(TREASURY_ADDRESS, Decimal('100'), Decimal('100'), temp_trie)
        self.bc.state_trie = Trie(self.bc.db, root_hash=temp_trie.root_hash)
        
        # Update genesis to reflect this state
        genesis = self.bc.get_latest_block()
        genesis.state_root = self.bc.state_trie.root_hash
        self.bc._store_block(genesis)
        
        # Now Bob buys 50 tokens for $50
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={
                'usd_amount': '50',
                'payment_id': 'stripe_67890'
            },
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertTrue(success)
        
        # Check Bob got 50 tokens
        bob_account = self.bc._get_account(self.bob_address, self.bc.state_trie)
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('50'))
        
        # Check treasury now has 50 tokens (transferred, not minted new)
        treasury_account = self.bc._get_account(TREASURY_ADDRESS, self.bc.state_trie)
        self.assertEqual(Decimal(str(treasury_account['balance'])), Decimal('50'))
        
        # Check no new tokens minted (still 100 total)
        stats = self.bc.get_tokenomics_stats()
        self.assertEqual(Decimal(stats['total_minted']), Decimal('100'))
        # But USD increased by the purchase
        self.assertEqual(Decimal(stats['total_usd_in']), Decimal('150'))

    def test_purchase_mixed_market(self):
        """Test purchase that uses both treasury and minting."""
        # Give treasury 30 tokens
        temp_trie = Trie(self.bc.db, root_hash=self.bc.state_trie.root_hash)
        self.bc.mint_tokens(TREASURY_ADDRESS, Decimal('30'), Decimal('30'), temp_trie)
        self.bc.state_trie = Trie(self.bc.db, root_hash=temp_trie.root_hash)
        
        genesis = self.bc.get_latest_block()
        genesis.state_root = self.bc.state_trie.root_hash
        self.bc._store_block(genesis)
        
        # Bob tries to buy 50 tokens (treasury only has 30)
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={
                'usd_amount': '50',
                'payment_id': 'stripe_mixed'
            },
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertTrue(success)
        
        # Bob should have 50 tokens (30 from treasury + 20 minted)
        bob_account = self.bc._get_account(self.bob_address, self.bc.state_trie)
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('50'))
        
        # Treasury should be empty
        treasury_account = self.bc._get_account(TREASURY_ADDRESS, self.bc.state_trie)
        self.assertEqual(Decimal(str(treasury_account['balance'])), Decimal('0'))
        
        # Total minted should be 50 (30 initial + 20 new)
        stats = self.bc.get_tokenomics_stats()
        self.assertEqual(Decimal(stats['total_minted']), Decimal('50'))

    def test_purchase_updates_price_correctly(self):
        """Test that price updates correctly after purchase."""
        # First purchase: 100 tokens for $100 (price = $1.00)
        tx1 = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '100', 'payment_id': 'stripe_1'},
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx1.sign(self.priv_key_bob)
        
        self._create_and_add_block([tx1])
        
        stats = self.bc.get_tokenomics_stats()
        self.assertEqual(Decimal(stats['current_price']), Decimal('1.00'))
        
        # Second purchase: another $100 (price still $1.00)
        tx2 = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '100', 'payment_id': 'stripe_2'},
            nonce=1,
            fee=0,
            chain_id=1
        )
        tx2.sign(self.priv_key_bob)
        
        self._create_and_add_block([tx2])
        
        # Price should still be $1.00 (200 USD / 200 tokens)
        stats = self.bc.get_tokenomics_stats()
        self.assertEqual(Decimal(stats['current_price']), Decimal('1.00'))
        
        # Bob should have 200 tokens
        bob_account = self.bc._get_account(self.bob_address, self.bc.state_trie)
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('200'))

    def test_purchase_with_zero_usd_fails(self):
        """Test that purchase with $0 fails."""
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '0', 'payment_id': 'stripe_zero'},
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertFalse(success)

    def test_purchase_with_negative_usd_fails(self):
        """Test that purchase with negative USD fails."""
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '-100', 'payment_id': 'stripe_neg'},
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertFalse(success)

    def test_purchase_increments_nonce(self):
        """Test that PURCHASE transaction increments nonce."""
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '50', 'payment_id': 'stripe_nonce'},
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        self._create_and_add_block([tx])
        
        # Nonce should be incremented
        bob_account = self.bc._get_account(self.bob_address, self.bc.state_trie)
        self.assertEqual(bob_account['nonce'], 1)

    def test_multiple_purchases_same_block(self):
        """Test multiple purchase transactions in same block."""
        # Create two buyers
        priv_key_charlie, pub_key_charlie = generate_key_pair()
        charlie_pem = serialize_public_key(pub_key_charlie)
        charlie_address = public_key_to_address(charlie_pem)
        
        tx1 = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '100', 'payment_id': 'stripe_bob'},
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx1.sign(self.priv_key_bob)
        
        tx2 = Transaction(
            sender_public_key=charlie_pem,
            tx_type='PURCHASE',
            data={'usd_amount': '50', 'payment_id': 'stripe_charlie'},
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx2.sign(priv_key_charlie)
        
        success = self._create_and_add_block([tx1, tx2])
        self.assertTrue(success)
        
        # Check both got tokens
        bob_account = self.bc._get_account(self.bob_address, self.bc.state_trie)
        charlie_account = self.bc._get_account(charlie_address, self.bc.state_trie)
        
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('100'))
        self.assertEqual(Decimal(str(charlie_account['balance'])), Decimal('50'))
        
        # Total should be 150 tokens minted
        stats = self.bc.get_tokenomics_stats()
        self.assertEqual(Decimal(stats['total_minted']), Decimal('150'))


if __name__ == '__main__':
    unittest.main()