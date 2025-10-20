"""
Test token minting and burning operations.
Phase 2: Test mint_tokens() and burn_tokens() methods.
"""
import unittest
import shutil
import tempfile
from decimal import Decimal
from crypto_v2.chain import Blockchain
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address
from crypto_v2.trie import Trie


class TestMintBurn(unittest.TestCase):
    def setUp(self):
        """Set up test blockchain."""
        self.test_dir = tempfile.mkdtemp()
        self.bc = Blockchain(self.test_dir, chain_id=1)
        
        # Create test user
        self.priv_key, self.pub_key = generate_key_pair()
        self.pub_key_pem = serialize_public_key(self.pub_key)
        self.user_address = public_key_to_address(self.pub_key_pem)

    def tearDown(self):
        """Clean up."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def test_mint_tokens_to_new_account(self):
        """Test minting tokens to an account with no balance."""
        test_trie = Trie(self.bc.db)
        
        # Mint 100 tokens
        success = self.bc.mint_tokens(
            to_address=self.user_address,
            amount=Decimal('100'),
            usd_amount=Decimal('100'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Check account balance
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(Decimal(str(account['balance'])), Decimal('100'))

    def test_mint_tokens_to_existing_account(self):
        """Test minting tokens to an account that already has balance."""
        test_trie = Trie(self.bc.db)
        
        # Set initial balance
        account = {'balance': '50', 'nonce': 0}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Mint 100 more tokens
        success = self.bc.mint_tokens(
            to_address=self.user_address,
            amount=Decimal('100'),
            usd_amount=Decimal('100'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Check balance is now 150
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(Decimal(str(account['balance'])), Decimal('150'))

    def test_mint_updates_tokenomics_state(self):
        """Test that minting updates total_minted and total_usd_in."""
        test_trie = Trie(self.bc.db)
        
        # Initial state
        initial_state = self.bc._get_tokenomics_state(test_trie)
        self.assertEqual(initial_state.total_minted, Decimal('0'))
        self.assertEqual(initial_state.total_usd_in, Decimal('0'))
        
        # Mint tokens
        self.bc.mint_tokens(
            to_address=self.user_address,
            amount=Decimal('100'),
            usd_amount=Decimal('100'),
            trie=test_trie
        )
        
        # Check tokenomics state updated
        new_state = self.bc._get_tokenomics_state(test_trie)
        self.assertEqual(new_state.total_minted, Decimal('100'))
        self.assertEqual(new_state.total_usd_in, Decimal('100'))

    def test_mint_multiple_times(self):
        """Test multiple minting operations accumulate correctly."""
        test_trie = Trie(self.bc.db)
        
        # Mint 3 times
        self.bc.mint_tokens(self.user_address, Decimal('100'), Decimal('100'), test_trie)
        self.bc.mint_tokens(self.user_address, Decimal('50'), Decimal('50'), test_trie)
        self.bc.mint_tokens(self.user_address, Decimal('25'), Decimal('25'), test_trie)
        
        # Check account balance
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(Decimal(str(account['balance'])), Decimal('175'))
        
        # Check tokenomics state
        state = self.bc._get_tokenomics_state(test_trie)
        self.assertEqual(state.total_minted, Decimal('175'))
        self.assertEqual(state.total_usd_in, Decimal('175'))

    def test_burn_tokens_from_account(self):
        """Test burning tokens from an account."""
        test_trie = Trie(self.bc.db)
        
        # Give user 100 tokens
        account = {'balance': '100', 'nonce': 0}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Burn 30 tokens
        success = self.bc.burn_tokens(
            from_address=self.user_address,
            amount=Decimal('30'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Check balance is now 70
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(Decimal(str(account['balance'])), Decimal('70'))

    def test_burn_updates_tokenomics_state(self):
        """Test that burning updates total_burned."""
        test_trie = Trie(self.bc.db)
        
        # Give user tokens
        account = {'balance': '100', 'nonce': 0}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Burn tokens
        self.bc.burn_tokens(
            from_address=self.user_address,
            amount=Decimal('30'),
            trie=test_trie
        )
        
        # Check tokenomics state
        state = self.bc._get_tokenomics_state(test_trie)
        self.assertEqual(state.total_burned, Decimal('30'))

    def test_burn_insufficient_balance_fails(self):
        """Test that burning more than balance fails."""
        test_trie = Trie(self.bc.db)
        
        # Give user only 50 tokens
        account = {'balance': '50', 'nonce': 0}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Try to burn 100 tokens
        success = self.bc.burn_tokens(
            from_address=self.user_address,
            amount=Decimal('100'),
            trie=test_trie
        )
        
        self.assertFalse(success)
        
        # Balance should be unchanged
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(Decimal(str(account['balance'])), Decimal('50'))

    def test_burn_exact_balance(self):
        """Test burning exactly the account balance."""
        test_trie = Trie(self.bc.db)
        
        # Give user 100 tokens
        account = {'balance': '100', 'nonce': 0}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Burn all 100 tokens
        success = self.bc.burn_tokens(
            from_address=self.user_address,
            amount=Decimal('100'),
            trie=test_trie
        )
        
        self.assertTrue(success)
        
        # Balance should be 0
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(Decimal(str(account['balance'])), Decimal('0'))

    def test_mint_and_burn_cycle(self):
        """Test complete mint and burn cycle affects price correctly."""
        test_trie = Trie(self.bc.db)
        
        # Mint 100 tokens for $100
        self.bc.mint_tokens(self.user_address, Decimal('100'), Decimal('100'), test_trie)
        
        state = self.bc._get_tokenomics_state(test_trie)
        self.assertEqual(state.current_price, Decimal('1.00'))
        
        # Burn 50 tokens (supply decreases, price should increase)
        self.bc.burn_tokens(self.user_address, Decimal('50'), test_trie)
        
        state = self.bc._get_tokenomics_state(test_trie)
        # Price = $100 / (100 - 50) = $100 / 50 = $2.00
        self.assertEqual(state.current_price, Decimal('2.00'))
        self.assertEqual(state.circulating_supply, Decimal('50'))

    def test_burn_from_empty_account_fails(self):
        """Test that burning from account with 0 balance fails."""
        test_trie = Trie(self.bc.db)
        
        # Account has default balance of 0
        success = self.bc.burn_tokens(
            from_address=self.user_address,
            amount=Decimal('10'),
            trie=test_trie
        )
        
        self.assertFalse(success)

    def test_mint_preserves_other_account_fields(self):
        """Test that minting doesn't overwrite nonce or other fields."""
        test_trie = Trie(self.bc.db)
        
        # Set account with nonce
        account = {'balance': '10', 'nonce': 5, 'vrf_pub_key': 'test_key'}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Mint tokens
        self.bc.mint_tokens(self.user_address, Decimal('20'), Decimal('20'), test_trie)
        
        # Check other fields preserved
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(account['nonce'], 5)
        self.assertEqual(account['vrf_pub_key'], 'test_key')
        self.assertEqual(Decimal(str(account['balance'])), Decimal('30'))

    def test_burn_preserves_other_account_fields(self):
        """Test that burning doesn't overwrite nonce or other fields."""
        test_trie = Trie(self.bc.db)
        
        # Set account with nonce
        account = {'balance': '100', 'nonce': 3, 'vrf_pub_key': 'test_key'}
        self.bc._set_account(self.user_address, account, test_trie)
        
        # Burn tokens
        self.bc.burn_tokens(self.user_address, Decimal('20'), test_trie)
        
        # Check other fields preserved
        account = self.bc._get_account(self.user_address, test_trie)
        self.assertEqual(account['nonce'], 3)
        self.assertEqual(account['vrf_pub_key'], 'test_key')
        self.assertEqual(Decimal(str(account['balance'])), Decimal('80'))


if __name__ == '__main__':
    unittest.main()