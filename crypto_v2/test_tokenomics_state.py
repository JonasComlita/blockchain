"""
Test tokenomics state storage in blockchain.
Phase 1: Just test storing/retrieving tokenomics data in the trie.
"""
import unittest
import shutil
import tempfile
from decimal import Decimal
from crypto_v2.chain import Blockchain, TOKEN_UNIT
from crypto_v2.trie import Trie
from crypto_v2.tokenomics_state import TokenomicsState


class TestTokenomicsState(unittest.TestCase):
    def setUp(self):
        """Set up test blockchain."""
        self.test_dir = tempfile.mkdtemp()
        self.bc = Blockchain(self.test_dir, chain_id=1)

    def tearDown(self):
        """Clean up."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def test_tokenomics_state_initialization(self):
        """Test that tokenomics state initializes with zeros."""
        state = self.bc._get_tokenomics_state(self.bc.state_trie)
        
        self.assertEqual(state.total_minted, 0)
        self.assertEqual(state.total_burned, 0)
        self.assertEqual(state.total_usd_in, Decimal('0'))
        self.assertEqual(state.total_usd_out, Decimal('0'))

    def test_tokenomics_state_storage(self):
        """Test storing and retrieving tokenomics state."""
        test_trie = Trie(self.bc.db)
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_burned = 10 * TOKEN_UNIT
        state.total_usd_in = Decimal('100')
        state.total_usd_out = Decimal('0')
        
        self.bc._set_tokenomics_state(state, test_trie)
        retrieved = self.bc._get_tokenomics_state(test_trie)
        
        self.assertEqual(retrieved.total_minted, 100 * TOKEN_UNIT)
        self.assertEqual(retrieved.total_burned, 10 * TOKEN_UNIT)
        self.assertEqual(retrieved.total_usd_in, Decimal('100'))
        self.assertEqual(retrieved.total_usd_out, Decimal('0'))

    def test_circulating_supply_calculation(self):
        """Test circulating supply calculation."""
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_burned = 30 * TOKEN_UNIT
        self.assertEqual(state.circulating_supply, 70 * TOKEN_UNIT)

    def test_net_treasury_usd_calculation(self):
        """Test net treasury USD calculation."""
        state = TokenomicsState()
        state.total_usd_in = Decimal('1000')
        state.total_usd_out = Decimal('250')
        self.assertEqual(state.net_treasury_usd, Decimal('750'))

    def test_price_calculation_initial(self):
        """Test price calculation with no minting."""
        state = TokenomicsState()
        self.assertEqual(state.current_price, Decimal('1.00'))

    def test_price_calculation_after_minting(self):
        """Test price calculation after initial mint."""
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_usd_in = Decimal('100')
        self.assertEqual(state.current_price, Decimal('1.00'))

    def test_price_calculation_with_burn(self):
        """Test that burning increases price."""
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_burned = 20 * TOKEN_UNIT
        state.total_usd_in = Decimal('100')
        self.assertEqual(state.current_price, Decimal('1.25'))

    def test_price_calculation_with_redemption(self):
        """Test that redemptions lower price."""
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_usd_in = Decimal('100')
        state.total_usd_out = Decimal('50')
        self.assertEqual(state.current_price, Decimal('0.50'))

    def test_price_floor(self):
        """Test that price has a floor of $0.01."""
        state = TokenomicsState()
        state.total_minted = 1000 * TOKEN_UNIT
        state.total_usd_in = Decimal('1')
        self.assertEqual(state.current_price, Decimal('0.01'))

    def test_reserve_ratio_calculation(self):
        """Test reserve ratio calculation."""
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_usd_in = Decimal('100')
        self.assertEqual(state.reserve_ratio, Decimal('1.0'))

    def test_reserve_ratio_after_redemption(self):
        """Test reserve ratio decreases after redemption."""
        state = TokenomicsState()
        state.total_minted = 100 * TOKEN_UNIT
        state.total_usd_in = Decimal('100')
        state.total_usd_out = Decimal('40')
        self.assertEqual(state.reserve_ratio, Decimal('1.0'))

    def test_tokenomics_persistence(self):
        """Test that tokenomics state persists across trie instances."""
        trie1 = Trie(self.bc.db)
        state = TokenomicsState()
        state.total_minted = 500 * TOKEN_UNIT
        state.total_usd_in = Decimal('500')
        self.bc._set_tokenomics_state(state, trie1)
        
        root_hash = trie1.root_hash
        
        trie2 = Trie(self.bc.db, root_hash=root_hash)
        retrieved = self.bc._get_tokenomics_state(trie2)
        
        self.assertEqual(retrieved.total_minted, 500 * TOKEN_UNIT)
        self.assertEqual(retrieved.total_usd_in, Decimal('500'))


if __name__ == '__main__':
    unittest.main()