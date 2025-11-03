"""
Test Suite 1: State Transition Validation
Critical Priority - Must Pass Before Launch

Tests core state integrity including double-spends, nonce enforcement,
balance underflows, and state root verification.
"""
import pytest
import tempfile
import shutil
from decimal import Decimal
from crypto_v2.chain import Blockchain, TOKEN_UNIT, ValidationError
from crypto_v2.core import Transaction, Block
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address
from crypto_v2.db import DB
from crypto_v2.poh import PoHRecorder
from crypto_v2.trie import BLANK_ROOT
import time


@pytest.fixture
def blockchain():
    """Create a temporary blockchain for testing."""
    temp_dir = tempfile.mkdtemp()
    db = DB(temp_dir)
    
    # Manually create and store a genesis block
    genesis = Block(
        parent_hash=b'\x00' * 32,
        state_root=BLANK_ROOT,
        transactions=[],
        poh_sequence=[],
        poh_initial=b'\x00' * 32,
        height=0,
        producer_pubkey=b'genesis',
        vrf_proof=b'genesis',
        vrf_pub_key=b'genesis',
        timestamp=0,
        signature=b'genesis_signature'
    )
    
    # Store the block and set it as head
    import msgpack
    block_data = msgpack.packb(genesis.to_dict(), use_bin_type=True)
    db.put(genesis.hash, block_data)
    db.put(b'height:0', genesis.hash)
    db.put(b'head', genesis.hash)

    chain = Blockchain(db=db, chain_id=1)
    yield chain
    db.close()
    shutil.rmtree(temp_dir)


@pytest.fixture
def funded_account(blockchain):
    """Create an account with initial funds."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    
    # Fund the account with both native and USD tokens
    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = (1000 * TOKEN_UNIT) + 5000 # Add extra for fees
    account['balances']['usd'] = 1000 * TOKEN_UNIT
    blockchain._set_account(address, account, blockchain.state_trie)
    
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address
    }


@pytest.fixture
def second_account(blockchain):
    """Create a second account for transfer tests."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address
    }


class TestDoubleSpendPrevention:
    """Test that double-spend attempts are prevented."""
    
    def test_same_nonce_duplicate_transaction(self, blockchain, funded_account, second_account):
        """Cannot include two transactions with same nonce in same block."""
        # Create two transactions with same nonce
        tx1 = Transaction(
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
        tx1.sign(funded_account['priv_key'])
        
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 200 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,  # Same nonce!
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        
        # Try to process both in same block
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # First should succeed
        assert blockchain._process_transaction(tx1, temp_trie) == True
        
        # Second should fail (nonce already used)
        with pytest.raises(ValidationError, match="Invalid nonce"):
            blockchain._process_transaction(tx2, temp_trie)
    
    def test_parallel_spend_same_funds(self, blockchain, funded_account, second_account):
        """Cannot spend same tokens in parallel transactions."""
        # Fund account with exactly 100 tokens
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] = 100 * TOKEN_UNIT + 2000  # Just enough for 2 fees
        account['nonce'] = 0
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        # Try to send 100 tokens twice with different nonces
        tx1 = Transaction(
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
        tx1.sign(funded_account['priv_key'])
        
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=1,  # Different nonce
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # First should succeed
        assert blockchain._process_transaction(tx1, temp_trie) == True
        
        # Second should fail (insufficient balance)
        with pytest.raises(ValidationError, match="Insufficient.*funds"):
            blockchain._process_transaction(tx2, temp_trie)
    
    def test_double_spend_across_blocks(self, blockchain, funded_account, second_account):
        """Cannot reuse nonce across blocks."""
        # Create and process first transaction in block 1
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] += 5000 # Ensure enough for fee
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)

        tx1 = Transaction(
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
        tx1.sign(funded_account['priv_key'])
        
        # Create block with tx1
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        blockchain._process_transaction(tx1, temp_trie)
        
        block1 = Block(
            parent_hash=latest.hash,
            state_root=temp_trie.root_hash,
            transactions=[tx1],
            poh_sequence=poh.sequence[1:],
            poh_initial=poh.sequence[0][0],
            height=latest.height + 1,
            producer_pubkey=funded_account['pub_key_pem'],
            vrf_proof=b'test',
            vrf_pub_key=b'test',
            timestamp=time.time(),
            signature=b'test'
        )
        
        # Add block
        blockchain.add_block(block1)
        blockchain.state_trie = Trie(blockchain.db, root_hash=block1.state_root)
        
        # Try to create another transaction with same nonce
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 50 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,  # Same nonce as tx1
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        
        # Should fail - nonce already used
        temp_trie2 = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        with pytest.raises(ValidationError, match="Invalid nonce"):
            blockchain._process_transaction(tx2, temp_trie2)


class TestNonceEnforcement:
    """Test nonce ordering and validation."""
    
    def test_skipped_nonce_rejected(self, blockchain, funded_account, second_account):
        """Cannot skip nonces."""
        # Try to use nonce 5 when current nonce is 0
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=5,  # Skipped nonces 0-4
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Invalid nonce"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_old_nonce_rejected(self, blockchain, funded_account, second_account):
        """Cannot reuse old nonces."""
        # Set account nonce to 5
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['nonce'] = 5
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        # Try to use nonce 3 (old)
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=3,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Invalid nonce"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_sequential_nonces_accepted(self, blockchain, funded_account, second_account):
        """Sequential nonces work correctly."""
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Process 5 transactions with sequential nonces
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
            
            assert blockchain._process_transaction(tx, temp_trie) == True
        
        # Verify final nonce is 5
        account = blockchain._get_account(funded_account['address'], temp_trie)
        assert account['nonce'] == 5


class TestBalanceUnderflow:
    """Test that balance underflows are prevented."""
    
    def test_insufficient_native_balance_transfer(self, blockchain, funded_account, second_account):
        """Cannot transfer more native tokens than available."""
        # Set balance to 100 tokens
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] = 100 * TOKEN_UNIT
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        # Try to transfer 200 tokens
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 200 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient.*funds"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_insufficient_usd_balance_transfer(self, blockchain, funded_account, second_account):
        """Cannot transfer more USD tokens than available."""
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['usd'] = 50 * TOKEN_UNIT
        account['balances']['native'] = 1000 * TOKEN_UNIT  # Have enough for fee
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient.*funds"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_insufficient_balance_for_fee(self, blockchain, funded_account, second_account):
        """Cannot pay fee without sufficient balance."""
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] = 500  # Less than fee
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 1,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,  # More than balance
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient native funds for fee"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_insufficient_for_stake(self, blockchain, funded_account):
        """Cannot stake more than available."""
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] = 100 * TOKEN_UNIT
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='STAKE',
            data={
                'amount': 200 * TOKEN_UNIT,
                'vrf_pub_key': 'test_vrf_key'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient.*funds"):
            blockchain._process_transaction(tx, temp_trie)
    
    def test_insufficient_for_swap(self, blockchain, funded_account):
        """Cannot swap more tokens than available."""
        # Setup AMM pool
        from crypto_v2.amm_state import LiquidityPoolState
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 100 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Give account only 10 tokens
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        account['balances']['native'] = 10 * TOKEN_UNIT
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        # Try to swap 100 tokens
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
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        with pytest.raises(ValidationError, match="Insufficient.*balance"):
            blockchain._process_transaction(tx, temp_trie)


class TestStateRootVerification:
    """Test that state roots are correctly calculated and verified."""
    
    def test_state_root_matches_after_transaction(self, blockchain, funded_account, second_account):
        """State root changes after transaction."""
        from crypto_v2.trie import Trie
        
        initial_root = blockchain.state_trie.root_hash
        
        temp_trie = Trie(blockchain.db, root_hash=initial_root)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        # State root should have changed
        assert temp_trie.root_hash != initial_root
    
    def test_deterministic_state_root(self, blockchain, funded_account, second_account):
        """Same operations produce same state root."""
        from crypto_v2.trie import Trie
        
        # Process transaction in first trie
        trie1 = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, trie1)
        root1 = trie1.root_hash
        
        # Process same transaction in second trie
        trie2 = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        blockchain._process_transaction(tx, trie2)
        root2 = trie2.root_hash
        
        # Roots should match
        assert root1 == root2
    
    def test_state_root_different_for_different_operations(self, blockchain, funded_account, second_account):
        """Different operations produce different roots."""
        from crypto_v2.trie import Trie
        
        # First transaction
        trie1 = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        tx1 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx1, trie1)
        root1 = trie1.root_hash
        
        # Different transaction (different amount)
        trie2 = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        tx2 = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 20 * TOKEN_UNIT,  # Different amount
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_account['priv_key'])
        blockchain._process_transaction(tx2, trie2)
        root2 = trie2.root_hash
        
        # Roots should be different
        assert root1 != root2


class TestBalanceIsolation:
    """Test that native and USD balances are properly isolated."""
    
    def test_native_transfer_doesnt_affect_usd(self, blockchain, funded_account, second_account):
        """Transferring native tokens doesn't affect USD balance."""
        # Set initial balances
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        initial_usd = 500 * TOKEN_UNIT
        account['balances']['usd'] = initial_usd
        account['balances']['native'] = 1000 * TOKEN_UNIT
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
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
        
        # Check USD balance unchanged
        final_account = blockchain._get_account(funded_account['address'], temp_trie)
        assert final_account['balances']['usd'] == initial_usd
    
    def test_usd_transfer_doesnt_affect_native(self, blockchain, funded_account, second_account):
        """Transferring USD tokens doesn't affect native balance (except fee)."""
        account = blockchain._get_account(funded_account['address'], blockchain.state_trie)
        initial_native = 1000 * TOKEN_UNIT
        account['balances']['native'] = initial_native
        account['balances']['usd'] = 500 * TOKEN_UNIT
        blockchain._set_account(funded_account['address'], account, blockchain.state_trie)
        
        from crypto_v2.trie import Trie
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        tx = Transaction(
            sender_public_key=funded_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': second_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        # Check native balance only decreased by fee
        final_account = blockchain._get_account(funded_account['address'], temp_trie)
        assert final_account['balances']['native'] == initial_native - 1000


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])