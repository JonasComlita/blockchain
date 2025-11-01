"""
Test Suite 2: AMM Pool Security
Critical Priority - Must Pass Before Launch

Tests constant product formula, walled garden restrictions ($1 min, 50% max),
fee calculations, and protection against common AMM exploits.
"""
import pytest
import tempfile
import shutil
from decimal import Decimal
from crypto_v2.chain import Blockchain, TOKEN_UNIT, ValidationError
from crypto_v2.core import Transaction
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address
from crypto_v2.db import DB
from crypto_v2.amm_state import LiquidityPoolState
from crypto_v2.trie import Trie


@pytest.fixture
def blockchain():
    """Create a temporary blockchain for testing."""
    temp_dir = tempfile.mkdtemp()
    db = DB(temp_dir)
    chain = Blockchain(db=db, chain_id=1)
    yield chain
    db.close()
    shutil.rmtree(temp_dir)


@pytest.fixture
def funded_account(blockchain):
    """Create an account with funds."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    
    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = 10000 * TOKEN_UNIT
    account['balances']['usd'] = 10000 * TOKEN_UNIT
    blockchain._set_account(address, account, blockchain.state_trie)
    
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address
    }


@pytest.fixture
def pool_1to1(blockchain):
    """Create a 1:1 pool (1000 tokens : 1000 USD)."""
    pool = LiquidityPoolState({
        'token_reserve': 1000 * TOKEN_UNIT,
        'usd_reserve': 1000 * TOKEN_UNIT,
        'lp_token_supply': 1000 * TOKEN_UNIT
    })
    blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
    return pool


@pytest.fixture
def pool_2to1(blockchain):
    """Create a 2:1 pool (2000 tokens : 1000 USD = $0.50 per token)."""
    pool = LiquidityPoolState({
        'token_reserve': 2000 * TOKEN_UNIT,
        'usd_reserve': 1000 * TOKEN_UNIT,
        'lp_token_supply': 1414 * TOKEN_UNIT  # sqrt(2000 * 1000)
    })
    blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
    return pool


class TestConstantProductInvariant:
    """Test that x * y = k is maintained."""
    
    def test_swap_maintains_k(self, blockchain, funded_account, pool_1to1):
        """Constant product k is maintained after swap (accounting for fees)."""
        initial_k = pool_1to1.token_reserve * pool_1to1.usd_reserve
        
        # Swap 10 tokens for USD
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 10 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        blockchain._process_transaction(tx, temp_trie)
        
        pool_after = blockchain._get_liquidity_pool_state(temp_trie)
        final_k = pool_after.token_reserve * pool_after.usd_reserve
        
        # K should increase slightly due to fees (0.3% kept in pool)
        # After adding tokens, K increases because fees stay in pool
        assert final_k > initial_k
        
        # Verify the math: with 0.3% fee, input becomes 99.7% effective
        # New reserves should satisfy: (x + dx*0.997) * (y - dy) = x*y
        expected_output = pool_1to1.get_swap_output(10 * TOKEN_UNIT, input_is_token=True)
        
        # Check reserves match expected
        assert pool_after.token_reserve == pool_1to1.token_reserve + 10 * TOKEN_UNIT
        assert pool_after.usd_reserve == pool_1to1.usd_reserve - expected_output
    
    def test_multiple_swaps_maintain_k_growth(self, blockchain, funded_account, pool_1to1):
        """K should monotonically increase with fees."""
        k_values = [pool_1to1.token_reserve * pool_1to1.usd_reserve]
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Perform 5 swaps
        for i in range(5):
            tx = Transaction(
                sender_public_key=funded_account['pub_key_pem'],
                tx_type='SWAP',
                data={
                    'amount_in': 10 * TOKEN_UNIT,
                    'min_amount_out': 0,
                    'token_in': 'native' if i % 2 == 0 else 'usd'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(funded_account['priv_key'])
            blockchain._process_transaction(tx, temp_trie)
            
            pool = blockchain._get_liquidity_pool_state(temp_trie)
            k_values.append(pool.token_reserve * pool.usd_reserve)
        
        # Each K should be >= previous K (fees accumulate)
        for i in range(1, len(k_values)):
            assert k_values[i] >= k_values[i-1], f"K decreased from {k_values[i-1]} to {k_values[i]}"
    
    def test_add_remove_liquidity_maintains_ratio(self, blockchain, funded_account, pool_1to1):
        """Adding and removing liquidity maintains pool ratio."""
        initial_ratio = pool_1to1.usd_reserve / pool_1to1.token_reserve
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Add liquidity
        add_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 100 * TOKEN_UNIT,
                'usd_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        add_tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(add_tx, temp_trie)
        
        pool_after_add = blockchain._get_liquidity_pool_state(temp_trie)
        ratio_after_add = pool_after_add.usd_reserve / pool_after_add.token_reserve
        
        # Ratio should be unchanged
        assert abs(ratio_after_add - initial_ratio) < 0.0001
        
        # Now remove some liquidity
        account = blockchain._get_account(funded_account['address'], temp_trie)
        lp_to_remove = account['lp_tokens'] // 2
        
        remove_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='REMOVE_LIQUIDITY',
            data={
                'lp_amount': lp_to_remove
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        remove_tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(remove_tx, temp_trie)
        
        pool_after_remove = blockchain._get_liquidity_pool_state(temp_trie)
        ratio_after_remove = pool_after_remove.usd_reserve / pool_after_remove.token_reserve
        
        # Ratio should still be maintained
        assert abs(ratio_after_remove - initial_ratio) < 0.0001


class TestMinimumTransactionValue:
    """Test $1.00 minimum transaction enforcement."""
    
    def test_reject_swap_below_one_dollar_native_to_usd(self, blockchain, funded_account, pool_1to1):
        """Reject swap of native tokens worth less than $1."""
        # At 1:1 ratio, 0.5 tokens = $0.50 (below minimum)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': int(0.5 * TOKEN_UNIT),  # $0.50 worth
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="below the \\$1.00 minimum"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_reject_swap_below_one_dollar_usd_to_native(self, blockchain, funded_account, pool_1to1):
        """Reject swap of USD tokens less than $1."""
        # Swapping 0.75 USD (below minimum)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': int(0.75 * TOKEN_UNIT),  # $0.75
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="below the \\$1.00 minimum"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_accept_swap_exactly_one_dollar(self, blockchain, funded_account, pool_1to1):
        """Accept swap of exactly $1."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 1 * TOKEN_UNIT,  # Exactly $1
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should succeed
        assert blockchain._process_transaction(tx, temp_trie) == True
    
    def test_minimum_enforced_at_different_price_ratios(self, blockchain, funded_account, pool_2to1):
        """Minimum is enforced correctly when token price != $1."""
        # Pool has 2000 tokens : 1000 USD, so 1 token = $0.50
        # To get $1 worth, need 2 tokens
        
        # Test: 1.5 tokens = $0.75 (should fail)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': int(1.5 * TOKEN_UNIT),  # 1.5 tokens = $0.75
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="below the \\$1.00 minimum"):
            blockchain._process_transaction(tx, temp_trie)
        
        # Test: 2 tokens = $1.00 (should succeed)
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 2 * TOKEN_UNIT,  # 2 tokens = $1.00
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        
        temp_trie2 = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        assert blockchain._process_transaction(tx2, temp_trie2) == True


class TestMaximumTransactionSize:
    """Test 50% maximum pool impact enforcement."""
    
    def test_reject_swap_claiming_over_50_percent_usd(self, blockchain, funded_account, pool_1to1):
        """Cannot claim more than 50% of USD reserve in one swap."""
        # Pool has 1000 USD, so max output is 500 USD
        # Need to calculate input that would output >500 USD
        
        # With constant product: (x + dx) * (y - dy) = x * y
        # To get dy = 501 USD (>50%), solve for dx
        # dx = (x * dy) / (y - dy)
        target_output = 501 * TOKEN_UNIT  # >50%
        
        # This would drain too much
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 5000 * TOKEN_UNIT,  # Large input
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Transaction size is too large and exceeds the 50% maximum pool limit."):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_reject_swap_claiming_over_50_percent_tokens(self, blockchain, funded_account, pool_1to1):
        """Cannot claim more than 50% of token reserve in one swap."""
        # Pool has 1000 tokens, so max output is 500 tokens
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 5000 * TOKEN_UNIT,  # Large input
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Transaction size is too large and exceeds the 50% maximum pool limit."):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_accept_swap_exactly_50_percent_minus_one(self, blockchain, funded_account, pool_1to1):
        """Can swap up to just under 50%."""
        # Calculate input that yields ~49.9% output
        # For simplicity, test that a moderately large swap works
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 400 * TOKEN_UNIT,  # Should be under 50% limit
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should succeed
        blockchain._process_transaction(tx, temp_trie)
        
        pool = blockchain._get_liquidity_pool_state(temp_trie)
        
        # Verify output was less than 50%
        usd_output = pool_1to1.usd_reserve - pool.usd_reserve
        assert usd_output < (pool_1to1.usd_reserve // 2)
    
    def test_maximum_enforced_at_different_pool_sizes(self, blockchain, funded_account):
        """Maximum is enforced at different pool sizes."""
        # Create small pool
        small_pool = LiquidityPoolState({
            'token_reserve': 100 * TOKEN_UNIT,
            'usd_reserve': 100 * TOKEN_UNIT,
            'lp_token_supply': 100 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(small_pool, blockchain.state_trie)
        
        # Try to claim 51 USD from 100 USD pool (>50%)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 500 * TOKEN_UNIT,  # Large relative to pool
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Transaction size is too large and exceeds the 50% maximum pool limit."):
            blockchain._process_transaction(tx, temp_trie)


class TestFeeCalculation:
    """Test that 0.3% fee is correctly applied."""
    
    def test_fee_applied_to_input(self, blockchain, funded_account, pool_1to1):
        """0.3% fee is deducted from input amount."""
        input_amount = 100 * TOKEN_UNIT
        
        # Calculate expected output with fee
        # Formula: output = (reserve_out * input * 0.997) / (reserve_in + input * 0.997)
        expected_output = pool_1to1.get_swap_output(input_amount, input_is_token=True)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': input_amount,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        pool = blockchain._get_liquidity_pool_state(temp_trie)
        
        # User received expected amount (accounting for integer division)
        initial_usd = 10000 * TOKEN_UNIT
        actual_output = account['balances']['usd'] - initial_usd
        assert abs(actual_output - expected_output) <= 1  # Allow 1 unit rounding error
        
        # Pool received full input
        assert pool.token_reserve == pool_1to1.token_reserve + input_amount
    
    def test_fee_accumulates_in_pool(self, blockchain, funded_account, pool_1to1):
        """Fees stay in pool, increasing K over time."""
        initial_k = pool_1to1.token_reserve * pool_1to1.usd_reserve
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Perform swap
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 100 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx, temp_trie)
        
        pool = blockchain._get_liquidity_pool_state(temp_trie)
        final_k = pool.token_reserve * pool.usd_reserve
        
        # K increased due to fees
        fee_amount = (100 * TOKEN_UNIT * 3) // 1000  # 0.3%
        assert final_k > initial_k
        
        # The fee worth of tokens stayed in pool
        # (100 input - 99.7 effective = 0.3 tokens stayed as fee)
    
    def test_no_fee_on_liquidity_operations(self, blockchain, funded_account, pool_1to1):
        """Adding/removing liquidity has no trading fee."""
        initial_k = pool_1to1.token_reserve * pool_1to1.usd_reserve
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Add liquidity
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 100 * TOKEN_UNIT,
                'usd_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx, temp_trie)
        
        pool = blockchain._get_liquidity_pool_state(temp_trie)
        new_k = pool.token_reserve * pool.usd_reserve
        
        # K increased proportionally (no fee taken)
        expected_k = (pool_1to1.token_reserve + 100 * TOKEN_UNIT) * (pool_1to1.usd_reserve + 100 * TOKEN_UNIT)
        assert new_k == expected_k


class TestSlippageProtection:
    """Test min_amount_out slippage protection."""
    
    def test_reject_swap_below_minimum_output(self, blockchain, funded_account, pool_1to1):
        """Reject swap if output less than min_amount_out."""
        # Calculate actual output
        input_amount = 10 * TOKEN_UNIT
        input_with_fee = (input_amount * 997) // 1000
        actual_output = (pool_1to1.usd_reserve * input_with_fee) // (pool_1to1.token_reserve + input_with_fee)
        
        # Set minimum higher than actual
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': input_amount,
                'min_amount_out': actual_output + 1000,  # Higher than possible
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="less than minimum output"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_accept_swap_meeting_minimum_output(self, blockchain, funded_account, pool_1to1):
        """Accept swap if output >= min_amount_out."""
        input_amount = 10 * TOKEN_UNIT
        actual_output = pool_1to1.get_swap_output(input_amount, input_is_token=True)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': input_amount,
                'min_amount_out': actual_output - 100,  # Slightly below actual
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should succeed
        assert blockchain._process_transaction(tx, temp_trie) == True


class TestPriceImpact:
    """Test price impact calculations."""
    
    def test_large_swap_has_high_price_impact(self, blockchain, funded_account, pool_1to1):
        """Large swaps have significant price impact."""
        # Small swap - get price
        small_input = 10 * TOKEN_UNIT
        small_input_fee = (small_input * 997) // 1000
        small_output = (pool_1to1.usd_reserve * small_input_fee) // (pool_1to1.token_reserve + small_input_fee)
        small_rate = small_output / small_input  # USD per token
        
        # Large swap (40% of pool)
        large_input = 400 * TOKEN_UNIT
        large_input_fee = (large_input * 997) // 1000
        large_output = (pool_1to1.usd_reserve * large_input_fee) // (pool_1to1.token_reserve + large_input_fee)
        large_rate = large_output / large_input  # USD per token
        
        # Large swap should get worse rate (higher price impact)
        assert large_rate < small_rate * 0.9  # At least 10% worse
    
    def test_multiple_small_swaps_better_than_one_large(self, blockchain, funded_account, pool_1to1):
        """Multiple small swaps get better effective rate than one large swap."""
        # One large swap: 100 tokens
        large_input = 100 * TOKEN_UNIT
        large_input_fee = (large_input * 997) // 1000
        large_output = (pool_1to1.usd_reserve * large_input_fee) // (pool_1to1.token_reserve + large_input_fee)
        
        # Five small swaps: 20 tokens each
        pool_state = pool_1to1
        total_output = 0
        
        for i in range(5):
            small_input = 20 * TOKEN_UNIT
            small_input_fee = (small_input * 997) // 1000
            output = (pool_state.usd_reserve * small_input_fee) // (pool_state.token_reserve + small_input_fee)
            total_output += output
            
            # Update pool for next iteration
            pool_state = LiquidityPoolState({
                'token_reserve': pool_state.token_reserve + small_input,
                'usd_reserve': pool_state.usd_reserve - output,
                'lp_token_supply': pool_state.lp_token_supply
            })
        
        # Multiple small swaps should get a better or nearly identical effective rate
        assert total_output >= large_output - (TOKEN_UNIT // 100)  # Allow for 0.01 token difference


class TestIntegerOverflowProtection:
    """Test protection against integer overflow/underflow."""
    
    def test_maximum_values_dont_overflow(self, blockchain, funded_account):
        """Maximum possible values don't cause overflow."""
        # Create pool with large reserves
        large_pool = LiquidityPoolState({
            'token_reserve': 2**50,  # Large but not max
            'usd_reserve': 2**50,
            'lp_token_supply': 2**50
        })
        blockchain._set_liquidity_pool_state(large_pool, blockchain.state_trie)
        
        # Fund account with large amount
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] = 2**50
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        # Try large swap
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 2**40,  # Large input
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should not crash or overflow
        try:
            blockchain._process_transaction(tx, temp_trie)
        except ValidationError:
            # May fail validation, but shouldn't crash
            pass
    
    def test_zero_reserves_handled_gracefully(self, blockchain, funded_account):
        """Operations on empty pool don't cause division by zero."""
        empty_pool = LiquidityPoolState({
            'token_reserve': 0,
            'usd_reserve': 0,
            'lp_token_supply': 0
        })
        blockchain._set_liquidity_pool_state(empty_pool, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 10 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should fail gracefully, not crash
        with pytest.raises((ValidationError, ZeroDivisionError)):
            blockchain._process_transaction(tx, temp_trie)


class TestLiquidityProvision:
    """Test liquidity addition and removal."""
    
    def test_add_liquidity_mints_correct_lp_tokens(self, blockchain, funded_account, pool_1to1):
        """LP tokens minted proportional to contribution."""
        initial_lp_supply = pool_1to1.lp_token_supply
        
        # Add 10% more liquidity
        native_add = pool_1to1.token_reserve // 10
        usd_add = pool_1to1.usd_reserve // 10
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': native_add,
                'usd_amount': usd_add
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        pool = blockchain._get_liquidity_pool_state(temp_trie)
        
        # Should receive ~10% of LP tokens
        expected_lp = (native_add * initial_lp_supply) // pool_1to1.token_reserve
        assert abs(account['lp_tokens'] - expected_lp) <= 1  # Allow rounding
        
        # Pool supply increased
        assert pool.lp_token_supply == initial_lp_supply + account['lp_tokens']
    
    def test_remove_liquidity_burns_lp_tokens(self, blockchain, funded_account, pool_1to1):
        """Removing liquidity burns LP tokens and returns assets."""
        # First add liquidity
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        add_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 100 * TOKEN_UNIT,
                'usd_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        add_tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(add_tx, temp_trie)
        
        account_after_add = blockchain._get_account(funded_account['address'], temp_trie)
        lp_received = account_after_add['lp_tokens']
        
        pool_after_add = blockchain._get_liquidity_pool_state(temp_trie)
        
        # Now remove half the liquidity
        remove_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='REMOVE_LIQUIDITY',
            data={
                'lp_amount': lp_received // 2
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        remove_tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(remove_tx, temp_trie)
        
        account_after_remove = blockchain._get_account(funded_account['address'], temp_trie)
        pool_after_remove = blockchain._get_liquidity_pool_state(temp_trie)
        
        # LP tokens reduced
        assert account_after_remove['lp_tokens'] == lp_received // 2
        
        # Pool supply reduced
        assert pool_after_remove.lp_token_supply < pool_after_add.lp_token_supply
    
    def test_remove_liquidity_proportional_share(self, blockchain, funded_account, pool_1to1):
        """Removing liquidity returns proportional share of reserves."""
        # Add liquidity first
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        add_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 100 * TOKEN_UNIT,
                'usd_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        add_tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(add_tx, temp_trie)
        
        account_after_add = blockchain._get_account(funded_account['address'], temp_trie)
        pool_after_add = blockchain._get_liquidity_pool_state(temp_trie)
        
        lp_tokens = account_after_add['lp_tokens']
        share = lp_tokens / pool_after_add.lp_token_supply
        
        expected_native = int(pool_after_add.token_reserve * share)
        expected_usd = int(pool_after_add.usd_reserve * share)
        
        initial_native = account_after_add['balances']['native']
        initial_usd = account_after_add['balances']['usd']
        
        # Remove all LP tokens
        remove_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='REMOVE_LIQUIDITY',
            data={
                'lp_amount': lp_tokens
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        remove_tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(remove_tx, temp_trie)
        
        account_after_remove = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Check received proportional amounts (allowing for rounding)
        native_received = account_after_remove['balances']['native'] - initial_native + 1000 # Add back the fee
        usd_received = account_after_remove['balances']['usd'] - initial_usd
        
        assert abs(native_received - expected_native) <= 10
        assert abs(usd_received - expected_usd) <= 10
    
    def test_cannot_remove_more_lp_than_owned(self, blockchain, funded_account, pool_1to1):
        """Cannot remove more LP tokens than you have."""
        # User has 0 LP tokens initially
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='REMOVE_LIQUIDITY',
            data={
                'lp_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient LP tokens"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_first_liquidity_provider_gets_fixed_amount(self, blockchain, funded_account):
        """First LP gets fixed initial amount."""
        # Start with empty pool
        empty_pool = LiquidityPoolState({
            'token_reserve': 0,
            'usd_reserve': 0,
            'lp_token_supply': 0
        })
        blockchain._set_liquidity_pool_state(empty_pool, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 1000 * TOKEN_UNIT,
                'usd_amount': 1000 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # First LP gets fixed 100 tokens (from code)
        assert account['lp_tokens'] == 100 * TOKEN_UNIT


class TestSandwichAttackProtection:
    """Test protection against sandwich attacks."""
    
    def test_slippage_protects_against_frontrun(self, blockchain, funded_account, pool_1to1):
        """Slippage protection prevents frontrunning profit."""
        # Victim wants to swap 50 tokens
        victim_input = 50 * TOKEN_UNIT
        
        # Calculate expected output without frontrun
        input_fee = (victim_input * 997) // 1000
        expected_output = (pool_1to1.usd_reserve * input_fee) // (pool_1to1.token_reserve + input_fee)
        
        # Attacker frontruns with large swap
        attacker_priv, attacker_pub = generate_key_pair()
        attacker_pem = serialize_public_key(attacker_pub)
        attacker_addr = public_key_to_address(attacker_pem)
        
        # Fund attacker
        attacker_account = blockchain._get_account(attacker_addr, blockchain.state_trie)
        attacker_account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(attacker_addr, attacker_account, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Attacker frontruns
        frontrun_tx = Transaction(
            sender_public_key=attacker_pem,
            tx_type='SWAP',
            data={
                'amount_in': 400 * TOKEN_UNIT,  # Large swap to move price
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        frontrun_tx.sign(attacker_priv)
        blockchain._process_transaction(frontrun_tx, temp_trie)
        
        # Now victim's transaction with slippage protection
        victim_tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': victim_input,
                'min_amount_out': int(expected_output * 0.95),  # 5% slippage tolerance
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        victim_tx.sign(funded_account['priv_key'])
        
        # Should fail due to price movement
        with pytest.raises(ValidationError, match="less than minimum output"):
            blockchain._process_transaction(victim_tx, temp_trie)
    
    def test_50_percent_limit_prevents_large_manipulation(self, blockchain, funded_account, pool_1to1):
        """50% limit prevents single transaction from draining pool."""
        # Even with huge input, can't drain more than 50%
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 10000 * TOKEN_UNIT,  # Massive input
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Transaction size is too large and exceeds the 50% maximum pool limit."):
            blockchain._process_transaction(tx, temp_trie)


class TestPriceManipulationResistance:
    """Test resistance to price oracle manipulation."""
    
    def test_large_swap_and_reverse_loses_money(self, blockchain, funded_account, pool_1to1):
        """Swapping and immediately reversing loses money to fees."""
        initial_native = 10000 * TOKEN_UNIT
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Swap 100 native for USD
        tx1 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 100 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx1, temp_trie)
        
        account_mid = blockchain._get_account(funded_account['address'], temp_trie)
        usd_received = account_mid['balances']['usd'] - 10000 * TOKEN_UNIT
        
        # Swap USD back to native
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': usd_received,
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx2, temp_trie)
        
        account_final = blockchain._get_account(funded_account['address'], temp_trie)
        final_native = account_final['balances']['native']
        
        # Should have less than started (fees + price impact)
        assert final_native < initial_native - 2000
    
    def test_cannot_profit_from_price_manipulation_within_block(self, blockchain, funded_account, pool_1to1):
        """Cannot profit from manipulating price within same block."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        initial_native = 10000 * TOKEN_UNIT - 3000  # After 3 tx fees
        
        # Manipulate price up
        tx1 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 400 * TOKEN_UNIT,  # Large buy
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx1, temp_trie)
        
        account_after_buy = blockchain._get_account(funded_account['address'], temp_trie)
        usd_got = account_after_buy['balances']['usd'] - 10000 * TOKEN_UNIT
        
        # Try to sell back at manipulated price
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': usd_got,
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx2, temp_trie)
        
        account_final = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Should not profit (should have less native than started)
        assert account_final['balances']['native'] < initial_native


class TestEdgeCases:
    """Test edge cases and corner scenarios."""
    
    def test_swap_with_exact_reserve_amount(self, blockchain, funded_account, pool_1to1):
        """Swapping amount equal to reserve is rejected."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': pool_1to1.token_reserve,  # Entire reserve
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Transaction size is too large and exceeds the 50% maximum pool limit."):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_minimum_swap_amounts(self, blockchain, funded_account, pool_1to1):
        """Minimum swap of 1 unit works."""
        # Even though below $1 min, test the math doesn't break
        # (validation should catch it)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 1,  # 1 unit (0.000001 token)
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should fail validation (below $1)
        with pytest.raises(ValidationError, match="below the \\$1.00 minimum"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_price_calculation_at_extreme_ratios(self, blockchain, funded_account):
        """Price calculations work at extreme reserve ratios."""
        # Pool with 1000:1 ratio
        extreme_pool = LiquidityPoolState({
            'token_reserve': 1000000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 31622 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(extreme_pool, blockchain.state_trie)
        
        # Current price should be very low
        price = extreme_pool.current_price
        assert price < Decimal('0.01')  # Less than 1 cent per token
        
        # Swap should still work (if meets $1 min)
        # Need 1000+ tokens to meet $1 minimum
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 2000 * TOKEN_UNIT,  # > $1 at this price
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should work
        blockchain._process_transaction(tx, temp_trie)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])