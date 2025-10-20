"""
Test token transfer operations.
Phase 2.5: Test transfer_tokens() helper method.
"""
import unittest
import shutil
import tempfile
from decimal import Decimal
from crypto_v2.chain import Blockchain
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address
from crypto_v2.trie import Trie


class TestTransferTokens(unittest.TestCase):
    def setUp(self):
        """Set up test blockchain with two users."""
        self.test_dir = tempfile.mkdtemp()
        self.bc = Blockchain(self.test_dir, chain_id=1)
        
        # Create Alice
        priv_key_alice, pub_key_alice = generate_key_pair()
        self.alice_pem = serialize_public_key(pub_key_alice)
        self.alice_address = public_key_to_address(self.alice_pem)
        
        # Create Bob
        priv_key_bob, pub_key_bob = generate_key_pair()
        self.bob_pem = serialize_public_key(pub_key_bob)
        self.bob_address = public_key_to_address(self.bob_pem)

    def tearDown(self):
        """Clean up."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def test_transfer_tokens_basic(self):
        """Test basic token transfer between accounts."""
        test_trie = Trie(self.bc.db)
        
        # Give Alice 100 tokens
        alice_account = {'balance': '100', 'nonce': 0}
        self.bc._set_account(self.alice_address, alice_account, test_trie)
        
        # Transfer 30 tokens to Bob
        success = self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('30'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Check balances
        alice_account = self.bc._get_account(self.alice_address, test_trie)
        bob_account = self.bc._get_account(self.bob_address, test_trie)
        
        self.assertEqual(Decimal(str(alice_account['balance'])), Decimal('70'))
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('30'))

    def test_transfer_insufficient_balance_fails(self):
        """Test that transfer with insufficient balance fails."""
        test_trie = Trie(self.bc.db)
        
        # Give Alice only 50 tokens
        alice_account = {'balance': '50', 'nonce': 0}
        self.bc._set_account(self.alice_address, alice_account, test_trie)
        
        # Try to transfer 100 tokens
        success = self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('100'),
            trie=test_trie
        )
        
        self.assertFalse(success)
        
        # Balances should be unchanged
        alice_account = self.bc._get_account(self.alice_address, test_trie)
        bob_account = self.bc._get_account(self.bob_address, test_trie)
        
        self.assertEqual(Decimal(str(alice_account['balance'])), Decimal('50'))
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('0'))

    def test_transfer_to_account_with_existing_balance(self):
        """Test transferring to account that already has balance."""
        test_trie = Trie(self.bc.db)
        
        # Give both accounts initial balances
        alice_account = {'balance': '100', 'nonce': 0}
        bob_account = {'balance': '25', 'nonce': 0}
        self.bc._set_account(self.alice_address, alice_account, test_trie)
        self.bc._set_account(self.bob_address, bob_account, test_trie)
        
        # Transfer 30 tokens
        success = self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('30'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Check balances
        alice_account = self.bc._get_account(self.alice_address, test_trie)
        bob_account = self.bc._get_account(self.bob_address, test_trie)
        
        self.assertEqual(Decimal(str(alice_account['balance'])), Decimal('70'))
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('55'))  # 25 + 30

    def test_transfer_exact_balance(self):
        """Test transferring exact balance (leave sender with 0)."""
        test_trie = Trie(self.bc.db)
        
        # Give Alice 100 tokens
        alice_account = {'balance': '100', 'nonce': 0}
        self.bc._set_account(self.alice_address, alice_account, test_trie)
        
        # Transfer all 100 tokens
        success = self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('100'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Check balances
        alice_account = self.bc._get_account(self.alice_address, test_trie)
        bob_account = self.bc._get_account(self.bob_address, test_trie)
        
        self.assertEqual(Decimal(str(alice_account['balance'])), Decimal('0'))
        self.assertEqual(Decimal(str(bob_account['balance'])), Decimal('100'))

    def test_transfer_preserves_other_fields(self):
        """Test that transfer doesn't overwrite other account fields."""
        test_trie = Trie(self.bc.db)
        
        # Give accounts with additional fields
        alice_account = {'balance': '100', 'nonce': 5, 'vrf_pub_key': 'alice_key'}
        bob_account = {'balance': '0', 'nonce': 3, 'is_treasury': True}
        self.bc._set_account(self.alice_address, alice_account, test_trie)
        self.bc._set_account(self.bob_address, bob_account, test_trie)
        
        # Transfer tokens
        self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('20'),
            trie=test_trie
        )
        
        # Check fields preserved
        alice_account = self.bc._get_account(self.alice_address, test_trie)
        bob_account = self.bc._get_account(self.bob_address, test_trie)
        
        self.assertEqual(alice_account['nonce'], 5)
        self.assertEqual(alice_account['vrf_pub_key'], 'alice_key')
        self.assertEqual(bob_account['nonce'], 3)
        self.assertEqual(bob_account['is_treasury'], True)

    def test_transfer_does_not_affect_tokenomics(self):
        """Test that transfers don't change minted/burned totals."""
        test_trie = Trie(self.bc.db)
        
        # Give Alice tokens
        alice_account = {'balance': '100', 'nonce': 0}
        self.bc._set_account(self.alice_address, alice_account, test_trie)
        
        # Get initial tokenomics state
        initial_state = self.bc._get_tokenomics_state(test_trie)
        initial_minted = initial_state.total_minted
        initial_burned = initial_state.total_burned
        
        # Transfer tokens
        self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('30'),
            trie=test_trie
        )
        
        # Check tokenomics unchanged
        final_state = self.bc._get_tokenomics_state(test_trie)
        self.assertEqual(final_state.total_minted, initial_minted)
        self.assertEqual(final_state.total_burned, initial_burned)

    def test_transfer_from_empty_account_fails(self):
        """Test that transfer from account with 0 balance fails."""
        test_trie = Trie(self.bc.db)
        
        # Alice has default balance of 0
        success = self.bc.transfer_tokens(
            from_address=self.alice_address,
            to_address=self.bob_address,
            amount=Decimal('10'),
            trie=test_trie
        )
        
        self.assertFalse(success)


if __name__ == '__main__':
    unittest.main()