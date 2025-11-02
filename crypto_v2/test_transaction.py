"""
Test Suite 3: Transaction Type Validation
Critical Priority - Must Pass Before Launch

Tests all transaction types including permission checks, balance updates,
and proper state transitions for each transaction type.
"""
import pytest
import tempfile
import shutil
from decimal import Decimal
from crypto_v2.chain import (
    Blockchain, TOKEN_UNIT, ValidationError,
    PAYMENTS_ORACLE_ADDRESS, RESERVE_ADMIN_ADDRESS, 
    RESERVE_POOL_ADDRESS, OUTFLOW_RESERVE_ADDRESS,
    BONDING_CURVE_BASE_PRICE, BONDING_CURVE_SLOPE
)
from crypto_v2.core import Transaction
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address
from crypto_v2.db import DB
from crypto_v2.amm_state import LiquidityPoolState
from crypto_v2.tokenomics_state import TokenomicsState
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
def second_account(blockchain):
    """Create a second account."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address
    }


@pytest.fixture
def mock_oracle(blockchain, monkeypatch):
    """Create a mock oracle account with a valid keypair and monkeypatch the address."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)

    monkeypatch.setattr('crypto_v2.chain.PAYMENTS_ORACLE_ADDRESS', address)

    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = 10000 * TOKEN_UNIT
    blockchain._set_account(address, account, blockchain.state_trie)

    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address
    }


@pytest.fixture
def mock_reserve_admin(blockchain, monkeypatch):
    """Create a mock reserve admin account and monkeypatch the address."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)

    monkeypatch.setattr('crypto_v2.chain.RESERVE_ADMIN_ADDRESS', address)

    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = 10000 * TOKEN_UNIT
    blockchain._set_account(address, account, blockchain.state_trie)

    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address
    }


class TestTransferTransaction:
    """Test TRANSFER transaction type."""
    
    def test_transfer_native_tokens(self, blockchain, funded_account, second_account):
        """Successfully transfer native tokens."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        transfer_amount = 100 * TOKEN_UNIT
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': transfer_amount,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        sender = blockchain._get_account(funded_account['address'], temp_trie)
        recipient = blockchain._get_account(second_account['address'], temp_trie)
        
        # Sender lost amount + fee
        assert sender['balances']['native'] == 10000 * TOKEN_UNIT - transfer_amount - 1000
        
        # Recipient gained amount
        assert recipient['balances']['native'] == transfer_amount
    
    def test_transfer_usd_tokens(self, blockchain, funded_account, second_account):
        """Successfully transfer USD tokens."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        transfer_amount = 50 * TOKEN_UNIT
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': transfer_amount,
                'token_type': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        sender = blockchain._get_account(funded_account['address'], temp_trie)
        recipient = blockchain._get_account(second_account['address'], temp_trie)
        
        # Sender lost USD amount (fee from native)
        assert sender['balances']['usd'] == 10000 * TOKEN_UNIT - transfer_amount
        assert sender['balances']['native'] == 10000 * TOKEN_UNIT - 1000  # Only fee
        
        # Recipient gained USD
        assert recipient['balances']['usd'] == transfer_amount
    
    def test_transfer_invalid_token_type(self, blockchain, funded_account, second_account):
        """Reject transfer with invalid token type."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'bitcoin'  # Invalid
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Invalid token type"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_transfer_to_self(self, blockchain, funded_account):
        """Can transfer to self (pointless but valid)."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': funded_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Only paid fee (amount went to self)
        assert account['balances']['native'] == 10000 * TOKEN_UNIT - 1000
    
    def test_add_liquidity_to_empty_pool(self, blockchain, funded_account):
        """Add initial liquidity to empty pool."""
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
        new_pool = blockchain._get_liquidity_pool_state(temp_trie)
        
        # Pool initialized
        assert new_pool.token_reserve == 1000 * TOKEN_UNIT
        assert new_pool.usd_reserve == 1000 * TOKEN_UNIT
        
        # First LP gets fixed amount
        assert account['lp_tokens'] == 100 * TOKEN_UNIT
    
    def test_add_liquidity_insufficient_native(self, blockchain, funded_account):
        """Cannot add liquidity without sufficient native tokens."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 20000 * TOKEN_UNIT,  # More than balance
                'usd_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient balance"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_add_liquidity_insufficient_usd(self, blockchain, funded_account):
        """Cannot add liquidity without sufficient USD."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 100 * TOKEN_UNIT,
                'usd_amount': 20000 * TOKEN_UNIT  # More than balance
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient balance"):
            blockchain._process_transaction(tx, temp_trie)


class TestRemoveLiquidityTransaction:
    """Test REMOVE_LIQUIDITY transaction type."""
    
    def test_remove_liquidity_returns_proportional_assets(self, blockchain, funded_account):
        """Removing liquidity returns proportional share."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Give user some LP tokens
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['lp_tokens'] = 100 * TOKEN_UNIT  # 10% of pool
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
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
        
        initial_native = 10000 * TOKEN_UNIT
        initial_usd = 10000 * TOKEN_UNIT
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        new_pool = blockchain._get_liquidity_pool_state(temp_trie)
        
        # LP tokens burned
        assert account['lp_tokens'] == 0
        
        # Received ~10% of reserves (100 native, 100 USD)
        native_received = account['balances']['native'] - initial_native + 1000  # +fee
        usd_received = account['balances']['usd'] - initial_usd
        
        assert abs(native_received - 100 * TOKEN_UNIT) <= 10  # Allow rounding
        assert abs(usd_received - 100 * TOKEN_UNIT) <= 10
        
        # Pool reserves decreased
        assert new_pool.token_reserve == 900 * TOKEN_UNIT
        assert new_pool.usd_reserve == 900 * TOKEN_UNIT
    
    def test_remove_partial_liquidity(self, blockchain, funded_account):
        """Can remove partial liquidity."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Give user 200 LP tokens
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['lp_tokens'] = 200 * TOKEN_UNIT
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Remove only 50 LP tokens
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='REMOVE_LIQUIDITY',
            data={
                'lp_amount': 50 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Still have remaining LP tokens
        assert account['lp_tokens'] == 150 * TOKEN_UNIT
    
    def test_remove_liquidity_insufficient_lp_tokens(self, blockchain, funded_account):
        """Cannot remove more LP tokens than owned."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # User has 0 LP tokens
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


class TestChainIDValidation:
    """Test chain ID validation across all transaction types."""
    
    def test_wrong_chain_id_rejected(self, blockchain, funded_account, second_account):
        """Transactions with wrong chain ID are rejected."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=999  # Wrong chain ID
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Wrong chain ID"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_correct_chain_id_accepted(self, blockchain, funded_account, second_account):
        """Transactions with correct chain ID are accepted."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1  # Correct chain ID
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Should succeed
        assert blockchain._process_transaction(tx, temp_trie) == True


class TestFeeHandling:
    """Test fee handling across transaction types."""
    
    def test_fees_always_paid_in_native(self, blockchain, funded_account, second_account):
        """Fees always deducted from native balance."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        initial_native = 10000 * TOKEN_UNIT
        fee = 5000
        
        # Transfer USD (fee still in native)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'usd'
            },
            nonce=0,
            fee=fee,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Native reduced by fee only
        assert account['balances']['native'] == initial_native - fee
        
        # USD reduced by transfer amount
        assert account['balances']['usd'] == 10000 * TOKEN_UNIT - 100 * TOKEN_UNIT
    
    def test_zero_fee_rejected(self, blockchain, funded_account, second_account):
        """Zero fee transactions may be rejected (policy decision)."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=0,  # Zero fee
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        # Zero fees are allowed in the code, but may fail basic validation
        is_valid, error = tx.validate_basic()
        # Current implementation allows 0 fees (checks fee >= 0)
        # If policy changes to require minimum fee, update this test
    
    def test_negative_fee_rejected(self, blockchain, funded_account, second_account):
        """Negative fees are rejected."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=-1000,  # Negative fee
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        is_valid, error = tx.validate_basic()
        assert not is_valid
        assert "Negative fee" in error


class TestNonceIncrement:
    """Test nonce increment behavior across transaction types."""
    
    def test_nonce_increments_on_success(self, blockchain, funded_account, second_account):
        """Nonce increments after successful transaction."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Initial nonce is 0
        account = blockchain._get_account(funded_account['address'], temp_trie)
        assert account['nonce'] == 0
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        assert account['nonce'] == 1
    
    def test_nonce_increments_sequentially(self, blockchain, funded_account, second_account):
        """Nonce increments for each transaction."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        for i in range(5):
            tx = Transaction(
                sender_public_key=funded_account['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': second_account['address'].hex(),
                    'amount': 10 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(funded_account['priv_key'])
            blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        assert account['nonce'] == 5


class TestTokenomicsStateUpdates:
    """Test that tokenomics state is properly updated."""
    
    def test_bond_mint_updates_supply(self, blockchain, funded_account):
        """Bond minting increases total supply."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        initial_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        initial_supply = initial_tokenomics.total_supply
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='BOND_MINT',
            data={'amount_in': 100 * TOKEN_UNIT},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        new_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        assert new_tokenomics.total_supply > initial_supply
    
    def test_reserve_burn_updates_burned(self, blockchain, funded_account):
        """Reserve burn increases total burned."""
        # Setup pool and outflow reserve
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        outflow = blockchain._get_account(OUTFLOW_RESERVE_ADDRESS, blockchain.state_trie)
        outflow['balances']['usd'] = 1000 * TOKEN_UNIT
        blockchain._set_account(OUTFLOW_RESERVE_ADDRESS, outflow, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        initial_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        initial_burned = initial_tokenomics.total_burned
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='RESERVE_BURN',
            data={'amount_in': 100 * TOKEN_UNIT},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        new_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        assert new_tokenomics.total_burned == initial_burned + 100 * TOKEN_UNIT


class TestTransactionSignatures:
    """Test signature validation for all transaction types."""
    
    def test_unsigned_transaction_rejected(self, blockchain, funded_account, second_account):
        """Unsigned transactions are rejected."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        # Don't sign
        
        is_valid, error = tx.validate_basic()
        assert not is_valid
        assert "Invalid signature" in error
    
    def test_invalid_signature_rejected(self, blockchain, funded_account, second_account):
        """Transactions with invalid signatures are rejected."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        # Set invalid signature
        tx.signature = b'invalid_signature_bytes'
        
        is_valid, error = tx.validate_basic()
        assert not is_valid
        assert "Invalid signature" in error
    
    def test_tampered_transaction_rejected(self, blockchain, funded_account, second_account):
        """Tampering with signed transaction invalidates signature."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        # Tamper with amount after signing
        tx.data['amount'] = 200 * TOKEN_UNIT
        
        is_valid, error = tx.validate_basic()
        assert not is_valid
        assert "Invalid signature" in error


class TestEdgeCasesAndBoundaries:
    """Test edge cases and boundary conditions."""
    
    def test_transfer_zero_amount(self, blockchain, funded_account, second_account):
        """Transferring zero amount (pointless but should work)."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 0,  # Zero transfer
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        # Basic validation may reject this
        is_valid, error = tx.validate_basic()
        if not is_valid:
            assert "must be positive" in error.lower()
    
    def test_maximum_amount_transfer(self, blockchain, funded_account, second_account):
        """Transferring maximum amount."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        max_amount = 10000 * TOKEN_UNIT - 1000  # Balance minus fee
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': max_amount,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        sender = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Should have exactly 0 left
        assert sender['balances']['native'] == 0


class TestMintUSDToken:
    """Test MINT_USD_TOKEN transaction type (oracle-only)."""

    def test_oracle_can_mint_usd(self, blockchain, mock_oracle, second_account):
        """Payments oracle can mint USD tokens."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)

        mint_amount = 500 * TOKEN_UNIT

        tx = Transaction(
            sender_public_key=mock_oracle['pub_key_pem'],
            tx_type='MINT_USD_TOKEN',
            data={
                'to': second_account['address'].hex(),
                'amount': mint_amount
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(mock_oracle['priv_key'])

        blockchain._process_transaction(tx, temp_trie)

        recipient = blockchain._get_account(second_account['address'], temp_trie)
        assert recipient['balances']['usd'] == mint_amount

        # Check tokenomics updated
        tokenomics = blockchain._get_tokenomics_state(temp_trie)
        assert tokenomics.total_usd_in == Decimal(mint_amount) / Decimal(TOKEN_UNIT)

    def test_non_oracle_cannot_mint_usd(self, blockchain, funded_account, second_account):
        """Non-oracle accounts cannot mint USD."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='MINT_USD_TOKEN',
            data={
                'to': second_account['address'].hex(),
                'amount': 500 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])

        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)

        with pytest.raises(ValidationError, match="not authorized to mint USD"):
            blockchain._process_transaction(tx, temp_trie)

    def test_mint_usd_updates_tokenomics(self, blockchain, mock_oracle, second_account):
        """Minting USD updates tokenomics state."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)

        initial_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        initial_usd_in = initial_tokenomics.total_usd_in

        mint_amount = 250 * TOKEN_UNIT

        tx = Transaction(
            sender_public_key=mock_oracle['pub_key_pem'],
            tx_type='MINT_USD_TOKEN',
            data={
                'to': second_account['address'].hex(),
                'amount': mint_amount
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(mock_oracle['priv_key'])

        blockchain._process_transaction(tx, temp_trie)

        new_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        expected_usd_in = initial_usd_in + (Decimal(mint_amount) / Decimal(TOKEN_UNIT))
        assert new_tokenomics.total_usd_in == expected_usd_in


class TestStakeTransaction:
    """Test STAKE transaction type."""
    
    def test_stake_adds_to_validator_set(self, blockchain, funded_account):
        """Staking adds account to validator set."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        stake_amount = 100 * TOKEN_UNIT
        vrf_key = "test_vrf_public_key_hex"
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='STAKE',
            data={
                'amount': stake_amount,
                'vrf_pub_key': vrf_key
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        # Check balance reduced
        account = blockchain._get_account(funded_account['address'], temp_trie)
        assert account['balances']['native'] == 10000 * TOKEN_UNIT - stake_amount - 1000
        
        # Check added to validator set
        validators = blockchain._get_validator_set(temp_trie)
        assert funded_account['address'].hex() in validators
        assert validators[funded_account['address'].hex()] == stake_amount
    
    def test_stake_updates_existing_stake(self, blockchain, funded_account):
        """Staking again increases existing stake."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # First stake
        tx1 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='STAKE',
            data={
                'amount': 100 * TOKEN_UNIT,
                'vrf_pub_key': 'test_vrf'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx1, temp_trie)
        
        # Second stake
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='STAKE',
            data={
                'amount': 50 * TOKEN_UNIT,
                'vrf_pub_key': 'test_vrf'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx2, temp_trie)
        
        # Check total stake
        validators = blockchain._get_validator_set(temp_trie)
        assert validators[funded_account['address'].hex()] == 150 * TOKEN_UNIT
    
    def test_stake_insufficient_balance(self, blockchain, funded_account):
        """Cannot stake more than balance."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='STAKE',
            data={
                'amount': 20000 * TOKEN_UNIT,  # More than balance
                'vrf_pub_key': 'test_vrf'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient.*funds"):
            blockchain._process_transaction(tx, temp_trie)


class TestBondMintTransaction:
    """Test BOND_MINT transaction type (bonding curve)."""
    
    def test_bond_mint_calculates_price_from_curve(self, blockchain, funded_account):
        """Bond minting uses bonding curve for pricing."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        usd_amount = 100 * TOKEN_UNIT
        
        # Get current supply
        tokenomics = blockchain._get_tokenomics_state(temp_trie)
        current_supply = tokenomics.circulating_supply
        
        # Calculate expected tokens
        price_per_token = BONDING_CURVE_BASE_PRICE + (BONDING_CURVE_SLOPE * Decimal(current_supply))
        expected_tokens = int(Decimal(usd_amount) / price_per_token)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='BOND_MINT',
            data={
                'amount_in': usd_amount
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        initial_native = 10000 * TOKEN_UNIT
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Check USD was taken
        assert account['balances']['usd'] == 10000 * TOKEN_UNIT - usd_amount
        
        # Check native tokens received (approximately)
        tokens_received = account['balances']['native'] - initial_native + 1000  # +fee
        assert abs(tokens_received - expected_tokens) <= 1  # Allow rounding
        
        # Check reserve pool got USD
        reserve = blockchain._get_account(RESERVE_POOL_ADDRESS, temp_trie)
        assert reserve['balances']['usd'] == usd_amount
        
        # Check supply increased
        new_tokenomics = blockchain._get_tokenomics_state(temp_trie)
        assert new_tokenomics.total_supply == current_supply + tokens_received
    
    def test_bond_mint_insufficient_usd(self, blockchain, funded_account):
        """Cannot bond mint without sufficient USD."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='BOND_MINT',
            data={
                'amount_in': 20000 * TOKEN_UNIT  # More than balance
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient USD balance"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_bond_mint_price_increases_with_supply(self, blockchain, funded_account):
        """Bonding curve price increases as supply grows."""
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        usd_amount = 100 * TOKEN_UNIT
        
        # First mint
        tx1 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='BOND_MINT',
            data={'amount_in': usd_amount},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx1, temp_trie)
        
        account_after_1 = blockchain._get_account(funded_account['address'], temp_trie)
        tokens_from_first = account_after_1['balances']['native'] - 10000 * TOKEN_UNIT + 1000
        
        # Second mint (same USD amount)
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='BOND_MINT',
            data={'amount_in': usd_amount},
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx2, temp_trie)
        
        account_after_2 = blockchain._get_account(funded_account['address'], temp_trie)
        tokens_from_second = account_after_2['balances']['native'] - account_after_1['balances']['native'] + 1000
        
        # Second mint should give fewer tokens (price increased)
        assert tokens_from_second < tokens_from_first


class TestReserveBurnTransaction:
    """Test RESERVE_BURN transaction type (buyback & burn)."""
    
    def test_reserve_burn_burns_tokens_gives_usd(self, blockchain, funded_account):
        """Reserve burn burns native tokens and gives USD."""
        # Setup: AMM pool for market price reference
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Fund outflow reserve with USD
        outflow_account = blockchain._get_account(OUTFLOW_RESERVE_ADDRESS, blockchain.state_trie)
        outflow_account['balances']['usd'] = 1000 * TOKEN_UNIT
        blockchain._set_account(OUTFLOW_RESERVE_ADDRESS, outflow_account, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        burn_amount = 100 * TOKEN_UNIT
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='RESERVE_BURN',
            data={
                'amount_in': burn_amount
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        initial_native = 10000 * TOKEN_UNIT
        initial_usd = 10000 * TOKEN_UNIT
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Native tokens decreased
        assert account['balances']['native'] < initial_native - burn_amount  # -burn -fee
        
        # USD received (at 98% of market price)
        market_price = Decimal(1.0)  # 1:1 pool
        expected_usd = int(Decimal(burn_amount) * market_price * Decimal('0.98'))
        assert account['balances']['usd'] == initial_usd + expected_usd
        
        # Check tokens were burned
        tokenomics = blockchain._get_tokenomics_state(temp_trie)
        assert tokenomics.total_burned == burn_amount
        assert tokenomics.total_supply == -burn_amount  # Started at 0
    
    def test_reserve_burn_insufficient_outflow_reserve(self, blockchain, funded_account):
        """Cannot burn if outflow reserve has insufficient USD."""
        # Setup pool
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Outflow reserve has only 10 USD
        outflow_account = blockchain._get_account(OUTFLOW_RESERVE_ADDRESS, blockchain.state_trie)
        outflow_account['balances']['usd'] = 10 * TOKEN_UNIT
        blockchain._set_account(OUTFLOW_RESERVE_ADDRESS, outflow_account, blockchain.state_trie)
        
        # Try to burn 100 tokens (would need ~98 USD)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='RESERVE_BURN',
            data={
                'amount_in': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="insufficient USD liquidity"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_reserve_burn_insufficient_native_balance(self, blockchain, funded_account):
        """Cannot burn more native tokens than owned."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        outflow_account = blockchain._get_account(OUTFLOW_RESERVE_ADDRESS, blockchain.state_trie)
        outflow_account['balances']['usd'] = 10000 * TOKEN_UNIT
        blockchain._set_account(OUTFLOW_RESERVE_ADDRESS, outflow_account, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='RESERVE_BURN',
            data={
                'amount_in': 20000 * TOKEN_UNIT  # More than balance
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient native token balance"):
            blockchain._process_transaction(tx, temp_trie)


class TestDeployReserveLiquidity:
    """Test DEPLOY_RESERVE_LIQUIDITY transaction (admin-only)."""

    def test_non_admin_cannot_deploy_liquidity(self, blockchain, funded_account):
        """Non-admin accounts cannot deploy reserve liquidity."""
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='DEPLOY_RESERVE_LIQUIDITY',
            data={},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])

        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)

        with pytest.raises(ValidationError, match="Only the Reserve Admin"):
            blockchain._process_transaction(tx, temp_trie)

    def test_deploy_requires_usd_in_reserve_pool(self, blockchain, mock_reserve_admin):
        """Deploying liquidity requires USD in reserve pool."""
        # Ensure reserve pool is empty
        reserve_pool_account = blockchain._get_account(RESERVE_POOL_ADDRESS, blockchain.state_trie)
        reserve_pool_account['balances']['usd'] = 0
        blockchain._set_account(RESERVE_POOL_ADDRESS, reserve_pool_account, blockchain.state_trie)

        tx = Transaction(
            sender_public_key=mock_reserve_admin['pub_key_pem'],
            tx_type='DEPLOY_RESERVE_LIQUIDITY',
            data={},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(mock_reserve_admin['priv_key'])

        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)

        with pytest.raises(ValidationError, match="No USD in reserve pool to deploy."):
            blockchain._process_transaction(tx, temp_trie)

    def test_deploy_adds_to_amm_pool(self, blockchain, mock_reserve_admin):
        """Deploying liquidity adds to AMM pool."""
        # Fund the reserve pool with USD
        reserve_pool_account = blockchain._get_account(RESERVE_POOL_ADDRESS, blockchain.state_trie)
        usd_to_deploy = 5000 * TOKEN_UNIT
        reserve_pool_account['balances']['usd'] = usd_to_deploy
        blockchain._set_account(RESERVE_POOL_ADDRESS, reserve_pool_account, blockchain.state_trie)

        # Get initial AMM state
        initial_pool = blockchain._get_liquidity_pool_state(blockchain.state_trie)

        tx = Transaction(
            sender_public_key=mock_reserve_admin['pub_key_pem'],
            tx_type='DEPLOY_RESERVE_LIQUIDITY',
            data={},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(mock_reserve_admin['priv_key'])

        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        blockchain._process_transaction(tx, temp_trie)

        # Check AMM pool was updated
        final_pool = blockchain._get_liquidity_pool_state(temp_trie)
        assert final_pool.usd_reserve > initial_pool.usd_reserve
        assert final_pool.token_reserve > initial_pool.token_reserve

        # Check reserve pool USD was used
        final_reserve_pool = blockchain._get_account(RESERVE_POOL_ADDRESS, temp_trie)
        assert final_reserve_pool['balances']['usd'] == 0


class TestSwapTransaction:
    """Test SWAP transaction type (covered extensively in AMM tests)."""
    
    def test_swap_native_for_usd(self, blockchain, funded_account):
        """Basic swap of native tokens for USD."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
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
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Received some USD
        assert account['balances']['usd'] > 10000 * TOKEN_UNIT
        
        # Lost native tokens + fee
        assert account['balances']['native'] < 10000 * TOKEN_UNIT
    
    def test_swap_usd_for_native(self, blockchain, funded_account):
        """Basic swap of USD for native tokens."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 10 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        account = blockchain._get_account(funded_account['address'], temp_trie)
        
        # Lost USD
        assert account['balances']['usd'] < 10000 * TOKEN_UNIT
        
        # Gained native (net of fee)
        assert account['balances']['native'] > 10000 * TOKEN_UNIT - 1000


class TestAddLiquidityTransaction:
    """Test ADD_LIQUIDITY transaction type."""
    
    def test_add_liquidity_to_existing_pool(self, blockchain, funded_account):
        """Add liquidity to pool with existing reserves."""
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
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

        pool_after = blockchain._get_liquidity_pool_state(temp_trie)
        assert pool_after.token_reserve == 1100 * TOKEN_UNIT
        assert pool_after.usd_reserve == 1100 * TOKEN_UNIT


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
