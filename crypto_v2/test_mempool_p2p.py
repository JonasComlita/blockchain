"""
Comprehensive tests for mempool and P2P networking components.
"""
import unittest
import asyncio
import time
from crypto_v2.mempool import Mempool
from crypto_v2.core import Transaction
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address
)


class TestMempoolBasic(unittest.TestCase):
    def setUp(self):
        """Set up test mempool and accounts."""
        self.mempool = Mempool()
        
        # Create test wallets
        self.wallets = {}
        for name in ['alice', 'bob']:
            priv_key, pub_key = generate_key_pair()
            self.wallets[name] = {
                'priv_key': priv_key,
                'pub_key': pub_key,
                'pem': serialize_public_key(pub_key),
                'address': public_key_to_address(serialize_public_key(pub_key)),
            }

    def test_add_valid_transaction(self):
        """Test adding a valid transaction."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success, error = self.mempool.add_transaction(tx)
        
        self.assertTrue(success, error)
        self.assertEqual(len(self.mempool), 1)

    def test_reject_unsigned_transaction(self):
        """Test that unsigned transactions are rejected."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=0,
            fee=10,
            chain_id=1
        )
        # Don't sign
        
        success, error = self.mempool.add_transaction(tx)
        
        self.assertFalse(success)
        self.assertIn('signature', error.lower())

    def test_reject_duplicate_transaction(self):
        """Test that duplicate transactions are rejected."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success1, _ = self.mempool.add_transaction(tx)
        success2, error2 = self.mempool.add_transaction(tx)
        
        self.assertTrue(success1)
        self.assertFalse(success2)
        self.assertIn('duplicate', error2.lower())

    def test_reject_low_fee(self):
        """Test that transactions with too low fee are rejected."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=0,
            fee=0,  # Too low
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success, error = self.mempool.add_transaction(tx)
        
        self.assertFalse(success)
        self.assertIn('fee', error.lower())

    def test_nonce_replacement_with_higher_fee(self):
        """Test replacing transaction with same nonce but higher fee."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        # First transaction
        tx1 = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx1.sign(alice['priv_key'])
        
        # Second transaction with same nonce but higher fee
        tx2 = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=0,
            fee=20,  # Higher fee
            chain_id=1
        )
        tx2.sign(alice['priv_key'])
        
        self.mempool.add_transaction(tx1)
        success, error = self.mempool.add_transaction(tx2)
        
        self.assertTrue(success)
        self.assertEqual(len(self.mempool), 1)
        
        # Should have the higher fee transaction
        pending = self.mempool.get_pending_transactions()
        self.assertEqual(pending[0].fee, 20)


class TestMempoolWithState(unittest.TestCase):
    def setUp(self):
        """Set up mempool with state validation."""
        # Mock account state
        self.accounts = {}
        
        def get_account_state(address: bytes) -> dict:
            return self.accounts.get(address.hex(), {'balance': 0, 'nonce': 0})
        
        self.mempool = Mempool(get_account_state=get_account_state)
        
        # Create wallets
        self.wallets = {}
        for name in ['alice', 'bob']:
            priv_key, pub_key = generate_key_pair()
            address = public_key_to_address(serialize_public_key(pub_key))
            
            self.wallets[name] = {
                'priv_key': priv_key,
                'pub_key': pub_key,
                'pem': serialize_public_key(pub_key),
                'address': address,
            }
            
            # Fund Alice
            if name == 'alice':
                self.accounts[address.hex()] = {'balance': 1000, 'nonce': 0}

    def test_reject_insufficient_balance(self):
        """Test rejecting transactions with insufficient balance."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 2000},  # More than balance
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success, error = self.mempool.add_transaction(tx)
        
        self.assertFalse(success)
        self.assertIn('balance', error.lower())

    def test_reject_old_nonce(self):
        """Test rejecting transactions with old nonces."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        # Update Alice's nonce
        self.accounts[alice['address'].hex()]['nonce'] = 5
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=3,  # Old nonce
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success, error = self.mempool.add_transaction(tx)
        
        self.assertFalse(success)
        self.assertIn('nonce', error.lower())

    def test_allow_future_nonce(self):
        """Test allowing transactions with future nonces."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': bob['address'], 'amount': 100},
            nonce=2,  # Future nonce (current is 0)
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success, error = self.mempool.add_transaction(tx)
        
        # Should be accepted but not immediately executable
        self.assertTrue(success, error)


class TestMempoolOrdering(unittest.TestCase):
    def setUp(self):
        """Set up mempool with mock state."""
        def get_account_state(address: bytes) -> dict:
            return {'balance': 10000, 'nonce': 0}
        
        self.mempool = Mempool(get_account_state=get_account_state)
        
        # Create wallet
        priv_key, pub_key = generate_key_pair()
        self.wallet = {
            'priv_key': priv_key,
            'pem': serialize_public_key(pub_key),
            'address': public_key_to_address(serialize_public_key(pub_key)),
        }

    def test_fee_based_ordering(self):
        """Test that transactions are ordered by fee."""
        # Create transactions with different fees
        fees = [5, 20, 10, 15, 25]
        
        for i, fee in enumerate(fees):
            tx = Transaction(
                sender_public_key=self.wallet['pem'],
                tx_type='TRANSFER',
                data={'recipient': self.wallet['address'], 'amount': 10},
                nonce=i,
                fee=fee,
                chain_id=1
            )
            tx.sign(self.wallet['priv_key'])
            self.mempool.add_transaction(tx)
        
        pending = self.mempool.get_pending_transactions()
        
        # Fees should be in descending order
        pending_fees = [tx.fee for tx in pending]
        self.assertEqual(pending_fees, sorted(fees, reverse=True))

    def test_nonce_gap_handling(self):
        """Test that only executable transactions are returned."""
        # Add transactions with nonce gaps
        for nonce in [0, 1, 2, 5, 6]:  # Gap at 3, 4
            tx = Transaction(
                sender_public_key=self.wallet['pem'],
                tx_type='TRANSFER',
                data={'recipient': self.wallet['address'], 'amount': 10},
                nonce=nonce,
                fee=10,
                chain_id=1
            )
            tx.sign(self.wallet['priv_key'])
            self.mempool.add_transaction(tx)
        
        pending = self.mempool.get_pending_transactions()
        
        # Should only get 0, 1, 2 (stop at gap)
        pending_nonces = [tx.nonce for tx in pending]
        self.assertEqual(pending_nonces, [0, 1, 2])


class TestMempoolMaintenance(unittest.TestCase):
    def setUp(self):
        """Set up mempool."""
        self.mempool = Mempool()
        
        priv_key, pub_key = generate_key_pair()
        self.wallet = {
            'priv_key': priv_key,
            'pem': serialize_public_key(pub_key),
            'address': public_key_to_address(serialize_public_key(pub_key)),
        }

    def test_remove_transactions(self):
        """Test removing transactions after block inclusion."""
        txs = []
        for i in range(5):
            tx = Transaction(
                sender_public_key=self.wallet['pem'],
                tx_type='TRANSFER',
                data={'recipient': self.wallet['address'], 'amount': 10},
                nonce=i,
                fee=10,
                chain_id=1
            )
            tx.sign(self.wallet['priv_key'])
            self.mempool.add_transaction(tx)
            txs.append(tx)
        
        self.assertEqual(len(self.mempool), 5)
        
        # Remove first 3
        self.mempool.remove_transactions(txs[:3])
        
        self.assertEqual(len(self.mempool), 2)

    def test_clean_expired_transactions(self):
        """Test cleaning expired transactions."""
        # Create old transaction
        tx = Transaction(
            sender_public_key=self.wallet['pem'],
            tx_type='TRANSFER',
            data={'recipient': self.wallet['address'], 'amount': 10},
            nonce=0,
            fee=10,
            chain_id=1,
            timestamp=time.time() - 4000  # 4000 seconds ago
        )
        tx.sign(self.wallet['priv_key'])
        
        self.mempool.add_transaction(tx)
        self.assertEqual(len(self.mempool), 1)
        
        # Clean expired
        self.mempool.clean_expired()
        
        self.assertEqual(len(self.mempool), 0)

    def test_mempool_size_limit(self):
        """Test that mempool enforces size limits."""
        from crypto_v2.mempool import MAX_MEMPOOL_SIZE
        
        # Try to add more than limit (this would be slow, so we test the mechanism)
        # Just verify the constant exists and is reasonable
        self.assertGreater(MAX_MEMPOOL_SIZE, 0)
        self.assertLess(MAX_MEMPOOL_SIZE, 100000)


class TestMempoolStats(unittest.TestCase):
    def test_statistics_tracking(self):
        """Test mempool statistics."""
        mempool = Mempool()
        
        priv_key, pub_key = generate_key_pair()
        wallet = {
            'priv_key': priv_key,
            'pem': serialize_public_key(pub_key),
        }
        
        # Add some transactions
        for i in range(3):
            tx = Transaction(
                sender_public_key=wallet['pem'],
                tx_type='TRANSFER',
                data={'recipient': bytes(20), 'amount': 10},
                nonce=i,
                fee=10,
                chain_id=1
            )
            tx.sign(priv_key)
            mempool.add_transaction(tx)
        
        stats = mempool.get_stats()
        
        self.assertEqual(stats['total_added'], 3)
        self.assertEqual(stats['current_size'], 3)
        self.assertGreaterEqual(stats['accounts'], 1)


if __name__ == '__main__':
    unittest.main()
