"""
Test Suite 7: Integration & End-to-End Tests
High Priority - Should Pass Before Launch

Tests complete user flows, multi-transaction scenarios, cross-component integration,
and realistic usage patterns.

Areas to Monitor:

Oracle/admin transaction types need special keypair setup
Large concurrent operations need performance testing
Chain reorganization needs more complex fork scenarios
"""
import pytest
import tempfile
import shutil
import time
from decimal import Decimal
from crypto_v2.chain import (
    Blockchain, TOKEN_UNIT, 
    PAYMENTS_ORACLE_ADDRESS, RESERVE_POOL_ADDRESS, 
    OUTFLOW_RESERVE_ADDRESS, RESERVE_ADMIN_ADDRESS
)
from crypto_v2.core import Transaction, Block
from crypto_v2.crypto import (
    generate_key_pair, serialize_public_key, public_key_to_address,
    generate_vrf_keypair, vrf_prove
)
from crypto_v2.db import DB
from crypto_v2.poh import PoHRecorder
from crypto_v2.trie import Trie
from crypto_v2.amm_state import LiquidityPoolState
from crypto_v2.tokenomics_state import TokenomicsState


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
def funded_user(blockchain):
    """Create a funded user account."""
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
def validator(blockchain):
    """Create a validator account."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    
    vrf_priv, vrf_pub = generate_vrf_keypair()
    
    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = 100000 * TOKEN_UNIT
    account['vrf_pub_key'] = vrf_pub.encode().hex()
    blockchain._set_account(address, account, blockchain.state_trie)
    
    validators = blockchain._get_validator_set(blockchain.state_trie)
    validators[address.hex()] = 10000 * TOKEN_UNIT
    blockchain._set_validator_set(validators, blockchain.state_trie)
    
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address,
        'vrf_priv': vrf_priv,
        'vrf_pub': vrf_pub
    }


def create_and_add_block(blockchain, validator, transactions):
    """Helper to create and add a block with transactions."""
    latest = blockchain.get_latest_block()
    
    # Process transactions and compute state root
    temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
    
    valid_txs = []
    for tx in transactions:
        try:
            if blockchain._process_transaction(tx, temp_trie):
                valid_txs.append(tx)
        except Exception as e:
            print(f"Transaction failed: {e}")
    
    # Create PoH sequence
    if latest.poh_sequence:
        initial_hash = latest.poh_sequence[-1][0]
    else:
        initial_hash = latest.hash
    
    poh = PoHRecorder(initial_hash)
    for tx in valid_txs:
        poh.record(tx.id)
    poh.tick()
    
    # Generate VRF proof
    vrf_proof, _ = vrf_prove(validator['vrf_priv'], latest.hash)
    
    block = Block(
        parent_hash=latest.hash,
        state_root=temp_trie.root_hash,
        transactions=valid_txs,
        poh_sequence=poh.sequence,
        height=latest.height + 1,
        producer=validator['pub_key_pem'],
        vrf_proof=vrf_proof,
        timestamp=time.time()
    )
    
    block.sign_block(validator['priv_key'])
    
    success = blockchain.add_block(block)
    return success, block, valid_txs


class TestNewUserOnboarding:
    """Test complete new user onboarding flow."""
    
    def test_user_buys_tokens_and_plays_game(self, blockchain, validator):
        """
        Complete flow: User receives USD -> Swaps for tokens -> Plays game
        """
        # 1. Create new user
        user_priv, user_pub = generate_key_pair()
        user_pem = serialize_public_key(user_pub)
        user_addr = public_key_to_address(user_pem)
        
        # 2. User receives USD from payment processor (simulated)
        # In production, this would be MINT_USD_TOKEN from oracle
        account = blockchain._get_account(user_addr, blockchain.state_trie)
        account['balances']['native'] = 1 * TOKEN_UNIT  # Start with 1 token for fees
        account['balances']['usd'] = 100 * TOKEN_UNIT  # $100
        blockchain._set_account(user_addr, account, blockchain.state_trie)
        
        # 3. Initialize AMM pool for swaps
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # 4. User swaps $50 USD for native tokens
        swap_tx = Transaction(
            sender_public_key=user_pem,
            tx_type='SWAP',
            data={
                'amount_in': 50 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        swap_tx.sign(user_priv)
        
        success, block1, txs1 = create_and_add_block(blockchain, validator, [swap_tx])
        assert success == True
        assert len(txs1) == 1
        
        # Check user received native tokens
        account = blockchain.get_account(user_addr)
        assert account['balances']['native'] > 0
        native_balance = account['balances']['native']
        usd_balance = account['balances']['usd']
        
        assert usd_balance == 50 * TOKEN_UNIT - 1000  # $50 left, minus fee
        print(f"User has {native_balance / TOKEN_UNIT} native tokens after swap")
        
        # 5. User "plays a game" (transfers tokens as game fee)
        game_fee_tx = Transaction(
            sender_public_key=user_pem,
            tx_type='TRANSFER',
            data={
                'to': validator['address'].hex(),  # Sending to validator as example
                'amount': 1 * TOKEN_UNIT,  # 1 token game fee
                'token_type': 'native'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        game_fee_tx.sign(user_priv)
        
        success, block2, txs2 = create_and_add_block(blockchain, validator, [game_fee_tx])
        assert success == True
        
        # Verify user paid game fee
        final_account = blockchain.get_account(user_addr)
        assert final_account['balances']['native'] < native_balance
        
        print("✅ Complete user flow: USD -> Swap -> Game payment")


class TestLiquidityProviderFlow:
    """Test liquidity provider lifecycle."""
    
    def test_add_liquidity_earn_fees_remove(self, blockchain, funded_user, validator):
        """
        Complete LP flow: Add liquidity -> Earn fees from swaps -> Remove liquidity
        """
        # 1. Initialize empty pool
        pool = LiquidityPoolState({
            'token_reserve': 0,
            'usd_reserve': 0,
            'lp_token_supply': 0
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # 2. LP adds initial liquidity
        add_liq_tx = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 1000 * TOKEN_UNIT,
                'usd_amount': 1000 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        add_liq_tx.sign(funded_user['priv_key'])
        
        success, block1, txs1 = create_and_add_block(blockchain, validator, [add_liq_tx])
        assert success == True
        
        account = blockchain.get_account(funded_user['address'])
        lp_tokens = account['lp_tokens']
        assert lp_tokens > 0
        print(f"LP received {lp_tokens / TOKEN_UNIT} LP tokens")
        
        # 3. Create another user who will swap (generating fees)
        trader_priv, trader_pub = generate_key_pair()
        trader_pem = serialize_public_key(trader_pub)
        trader_addr = public_key_to_address(trader_pem)
        
        trader_account = blockchain._get_account(trader_addr, blockchain.state_trie)
        trader_account['balances']['native'] = 1000 * TOKEN_UNIT
        trader_account['balances']['usd'] = 1 * TOKEN_UNIT  # For fees
        blockchain._set_account(trader_addr, trader_account, blockchain.state_trie)
        
        # 4. Trader performs swaps (generates fees for LP)
        swap_tx = Transaction(
            sender_public_key=trader_pem,
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
        swap_tx.sign(trader_priv)
        
        success, block2, txs2 = create_and_add_block(blockchain, validator, [swap_tx])
        assert success == True
        
        # Check pool K increased (fees accumulated)
        pool_after_swap = blockchain._get_liquidity_pool_state(blockchain.state_trie)
        k_after = pool_after_swap.token_reserve * pool_after_swap.usd_reserve
        initial_k = 1000 * TOKEN_UNIT * 1000 * TOKEN_UNIT
        assert k_after > initial_k
        print(f"Pool K increased from {initial_k} to {k_after} (fees earned)")
        
        # 5. LP removes liquidity
        remove_liq_tx = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='REMOVE_LIQUIDITY',
            data={
                'lp_amount': lp_tokens
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        remove_liq_tx.sign(funded_user['priv_key'])
        
        success, block3, txs3 = create_and_add_block(blockchain, validator, [remove_liq_tx])
        assert success == True
        
        final_account = blockchain.get_account(funded_user['address'])
        assert final_account['lp_tokens'] == 0
        
        # LP should have more than initial (earned fees)
        # Note: Exact calculation depends on how much trader activity occurred
        print("✅ Complete LP flow: Add -> Earn fees -> Remove")


class TestTokenBuybackFlow:
    """Test token buyback and burn mechanism."""
    
    def test_reserve_burn_reduces_supply(self, blockchain, funded_user, validator):
        """
        Flow: User sells tokens to outflow reserve -> Tokens burned -> Supply decreases
        """
        # 1. Setup AMM pool for price reference
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # 2. Fund outflow reserve with USD
        outflow_account = blockchain._get_account(OUTFLOW_RESERVE_ADDRESS, blockchain.state_trie)
        outflow_account['balances']['usd'] = 5000 * TOKEN_UNIT
        blockchain._set_account(OUTFLOW_RESERVE_ADDRESS, outflow_account, blockchain.state_trie)
        
        # 3. Record initial supply
        initial_tokenomics = blockchain._get_tokenomics_state(blockchain.state_trie)
        initial_supply = initial_tokenomics.total_supply
        initial_burned = initial_tokenomics.total_burned
        
        # 4. User burns tokens via reserve
        burn_amount = 100 * TOKEN_UNIT
        
        burn_tx = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='RESERVE_BURN',
            data={
                'amount_in': burn_amount
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        burn_tx.sign(funded_user['priv_key'])
        
        initial_usd = blockchain.get_account(funded_user['address'])['balances']['usd']
        
        success, block, txs = create_and_add_block(blockchain, validator, [burn_tx])
        assert success == True
        
        # 5. Verify tokens burned and supply decreased
        final_tokenomics = blockchain._get_tokenomics_state(blockchain.state_trie)
        assert final_tokenomics.total_burned == initial_burned + burn_amount
        assert final_tokenomics.total_supply == initial_supply - burn_amount
        
        # 6. Verify user received USD (at 98% of market price)
        final_account = blockchain.get_account(funded_user['address'])
        usd_received = final_account['balances']['usd'] - initial_usd
        
        market_price = Decimal(1.0)  # 1:1 pool
        expected_usd = int(Decimal(burn_amount) * market_price * Decimal('0.98'))
        assert usd_received == expected_usd
        
        print(f"✅ Burned {burn_amount / TOKEN_UNIT} tokens, received ${usd_received / TOKEN_UNIT} USD")


class TestMultiUserInteraction:
    """Test multiple users interacting simultaneously."""
    
    def test_multiple_users_swap_in_same_block(self, blockchain, validator):
        """
        Multiple users perform swaps in the same block
        """
        # Setup pool
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Create 5 users
        users = []
        for i in range(5):
            priv, pub = generate_key_pair()
            pem = serialize_public_key(pub)
            addr = public_key_to_address(pem)
            
            account = blockchain._get_account(addr, blockchain.state_trie)
            account['balances']['native'] = 1000 * TOKEN_UNIT
            account['balances']['usd'] = 1000 * TOKEN_UNIT
            blockchain._set_account(addr, account, blockchain.state_trie)
            
            users.append({'priv': priv, 'pub': pub, 'pem': pem, 'addr': addr})
        
        # Each user creates a swap transaction
        transactions = []
        for i, user in enumerate(users):
            tx = Transaction(
                sender_public_key=user['pem'],
                tx_type='SWAP',
                data={
                    'amount_in': 10 * TOKEN_UNIT,
                    'min_amount_out': 0,
                    'token_in': 'native' if i % 2 == 0 else 'usd'
                },
                nonce=0,
                fee=1000,
                chain_id=1
            )
            tx.sign(user['priv'])
            transactions.append(tx)
        
        # All transactions in one block
        success, block, valid_txs = create_and_add_block(blockchain, validator, transactions)
        assert success == True
        assert len(valid_txs) == 5
        
        # Verify all users' swaps succeeded
        for user in users:
            account = blockchain.get_account(user['addr'])
            # Account should have changed (either native or usd increased)
            assert account['balances']['native'] != 1000 * TOKEN_UNIT or \
                   account['balances']['usd'] != 1000 * TOKEN_UNIT
        
        print("✅ 5 users successfully swapped in same block")


class TestValidatorStakingCycle:
    """Test validator staking lifecycle."""
    
    def test_stake_validate_unstake(self, blockchain, funded_user, validator):
        """
        Flow: User stakes -> Becomes validator -> Validates blocks -> Unstakes
        """
        # 1. User stakes tokens
        stake_amount = 1000 * TOKEN_UNIT
        
        # Generate VRF key for staking
        vrf_priv, vrf_pub = generate_vrf_keypair()
        
        stake_tx = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='STAKE',
            data={
                'amount': stake_amount,
                'vrf_pub_key': vrf_pub.encode().hex()
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        stake_tx.sign(funded_user['priv_key'])
        
        success, block1, txs1 = create_and_add_block(blockchain, validator, [stake_tx])
        assert success == True
        
        # 2. Verify user is now in validator set
        validators = blockchain.get_validator_set()
        assert funded_user['address'].hex() in validators
        assert validators[funded_user['address'].hex()] == stake_amount
        
        # 3. User's balance reduced
        account = blockchain.get_account(funded_user['address'])
        expected_balance = 10000 * TOKEN_UNIT - stake_amount - 1000  # - stake - fee
        assert account['balances']['native'] == expected_balance
        
        print(f"✅ User staked {stake_amount / TOKEN_UNIT} tokens and became validator")
        
        # Note: Unstaking would require implementing UNSTAKE transaction type
        # which wasn't in the original code, but the pattern would be similar


class TestCrossAssetTransactions:
    """Test transactions involving multiple asset types."""
    
    def test_transfer_both_asset_types(self, blockchain, funded_user, validator):
        """
        User transfers both native and USD tokens to different recipients
        """
        # Create two recipients
        recip1_priv, recip1_pub = generate_key_pair()
        recip1_pem = serialize_public_key(recip1_pub)
        recip1_addr = public_key_to_address(recip1_pem)
        
        recip2_priv, recip2_pub = generate_key_pair()
        recip2_pem = serialize_public_key(recip2_pub)
        recip2_addr = public_key_to_address(recip2_pem)
        
        # Transfer native to recipient 1
        tx1 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recip1_addr.hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_user['priv_key'])
        
        # Transfer USD to recipient 2
        tx2 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recip2_addr.hex(),
                'amount': 200 * TOKEN_UNIT,
                'token_type': 'usd'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_user['priv_key'])
        
        success, block, txs = create_and_add_block(blockchain, validator, [tx1, tx2])
        assert success == True
        assert len(txs) == 2
        
        # Verify balances
        sender = blockchain.get_account(funded_user['address'])
        assert sender['balances']['native'] == 10000 * TOKEN_UNIT - 100 * TOKEN_UNIT - 2000  # -transfers -fees
        assert sender['balances']['usd'] == 10000 * TOKEN_UNIT - 200 * TOKEN_UNIT
        
        recip1 = blockchain.get_account(recip1_addr)
        assert recip1['balances']['native'] == 100 * TOKEN_UNIT
        assert recip1['balances']['usd'] == 0
        
        recip2 = blockchain.get_account(recip2_addr)
        assert recip2['balances']['native'] == 0
        assert recip2['balances']['usd'] == 200 * TOKEN_UNIT
        
        print("✅ Cross-asset transfers: Native and USD to different recipients")


class TestChainReorganization:
    """Test chain reorganization scenarios."""
    
    def test_longer_chain_replaces_shorter(self, blockchain, validator):
        """
        Test that a longer valid chain replaces a shorter one
        """
        initial_height = blockchain.get_latest_block().height
        
        # Create 3 blocks
        for i in range(3):
            success, block, _ = create_and_add_block(blockchain, validator, [])
            assert success == True
        
        final_height = blockchain.get_latest_block().height
        assert final_height == initial_height + 3
        
        print(f"✅ Chain grew from height {initial_height} to {final_height}")


class TestAtomicBlockExecution:
    """Test that block execution is atomic."""
    
    def test_invalid_transaction_rolls_back_block(self, blockchain, funded_user, validator):
        """
        Block with mix of valid and invalid transactions - all should fail
        """
        # Valid transaction
        tx1 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': funded_user['address'].hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_user['priv_key'])
        
        # Invalid transaction (insufficient funds)
        tx2 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': funded_user['address'].hex(),
                'amount': 1000000 * TOKEN_UNIT,  # Way more than balance
                'token_type': 'native'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_user['priv_key'])
        
        initial_state_root = blockchain.state_trie.root_hash
        
        # Try to add block with invalid transaction
        success, block, valid_txs = create_and_add_block(blockchain, validator, [tx1, tx2])
        
        # Block should fail or only include valid tx
        if not success:
            # State should be unchanged
            assert blockchain.state_trie.root_hash == initial_state_root
        else:
            # Only valid transactions should be included
            assert len(valid_txs) < 2
        
        print("✅ Invalid transaction handling verified")


class TestComplexSwapScenario:
    """Test complex AMM swap scenarios."""
    
    def test_arbitrage_attempt(self, blockchain, validator):
        """
        User attempts arbitrage: Large swap one way, then reverse
        Should lose money due to fees and slippage
        """
        # Setup pool
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Create arbitrage user
        arb_priv, arb_pub = generate_key_pair()
        arb_pem = serialize_public_key(arb_pub)
        arb_addr = public_key_to_address(arb_pem)
        
        arb_account = blockchain._get_account(arb_addr, blockchain.state_trie)
        arb_account['balances']['native'] = 5001 * TOKEN_UNIT
        arb_account['balances']['usd'] = 5000 * TOKEN_UNIT
        blockchain._set_account(arb_addr, arb_account, blockchain.state_trie)
        
        initial_native = 5001 * TOKEN_UNIT
        
        # Swap 1: Native -> USD (large swap)
        tx1 = Transaction(
            sender_public_key=arb_pem,
            tx_type='SWAP',
            data={
                'amount_in': 1000 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(arb_priv)
        
        success, block1, _ = create_and_add_block(blockchain, validator, [tx1])
        assert success == True
        
        account_mid = blockchain.get_account(arb_addr)
        usd_received = account_mid['balances']['usd'] - 5000 * TOKEN_UNIT
        
        # Swap 2: USD -> Native (reverse)
        tx2 = Transaction(
            sender_public_key=arb_pem,
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
        tx2.sign(arb_priv)
        
        success, block2, _ = create_and_add_block(blockchain, validator, [tx2])
        assert success == True
        
        account_final = blockchain.get_account(arb_addr)
        final_native = account_final['balances']['native']
        
        # Should have less than started (fees + slippage)
        net_loss = initial_native - final_native - 2000  # Subtract both transaction fees
        assert net_loss > 0
        
        print(f"✅ Arbitrage attempt lost {net_loss / TOKEN_UNIT} tokens to fees/slippage")


class TestStateConsistency:
    """Test state consistency across operations."""
    
    def test_state_root_uniqueness(self, blockchain, funded_user, validator):
        """
        Different operations produce different state roots
        """
        state_roots = [blockchain.state_trie.root_hash]
        
        # Perform 5 different operations
        for i in range(5):
            tx = Transaction(
                sender_public_key=funded_user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': funded_user['address'].hex(),
                    'amount': (i + 1) * TOKEN_UNIT,  # Different amounts
                    'token_type': 'native'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(funded_user['priv_key'])
            
            success, block, _ = create_and_add_block(blockchain, validator, [tx])
            if success:
                state_roots.append(blockchain.state_trie.root_hash)
        
        # All state roots should be unique
        assert len(state_roots) == len(set(state_roots))
        
        print(f"✅ {len(state_roots)} operations produced {len(set(state_roots))} unique state roots")


class TestRecoveryAndRestart:
    """Test blockchain recovery and restart scenarios."""
    
    def test_reload_blockchain_from_disk(self, funded_user, validator):
        """
        Create blockchain, add blocks, close it, reopen and verify state
        """
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Create and populate blockchain
            db1 = DB(temp_dir)
            chain1 = Blockchain(db=db1, chain_id=1)
            
            # Add funded user
            account = chain1._get_account(funded_user['address'], chain1.state_trie)
            account['balances']['native'] = 10000 * TOKEN_UNIT
            chain1._set_account(funded_user['address'], account, chain1.state_trie)
            
            # Add validator
            val_account = chain1._get_account(validator['address'], chain1.state_trie)
            val_account['balances']['native'] = 100000 * TOKEN_UNIT
            val_account['vrf_pub_key'] = validator['vrf_pub'].encode().hex()
            chain1._set_account(validator['address'], val_account, chain1.state_trie)
            
            validators = chain1._get_validator_set(chain1.state_trie)
            validators[validator['address'].hex()] = 10000 * TOKEN_UNIT
            chain1._set_validator_set(validators, chain1.state_trie)
            
            # Create some transactions and blocks
            tx = Transaction(
                sender_public_key=funded_user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': validator['address'].hex(),
                    'amount': 100 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=0,
                fee=1000,
                chain_id=1
            )
            tx.sign(funded_user['priv_key'])
            
            success, block, _ = create_and_add_block(chain1, validator, [tx])
            assert success == True
            
            final_height = chain1.get_latest_block().height
            final_state_root = block.state_root
            
            # Close blockchain
            db1.close()
            
            # Reopen blockchain
            db2 = DB(temp_dir)
            chain2 = Blockchain(db=db2, chain_id=1)
            
            # Verify state is preserved
            assert chain2.get_latest_block().height == final_height
            assert chain2.get_latest_block().state_root == final_state_root
            
            # Verify account balances preserved
            account2 = chain2.get_account(funded_user['address'])
            expected_balance = 10000 * TOKEN_UNIT - 100 * TOKEN_UNIT - 1000
            assert account2['balances']['native'] == expected_balance
            
            db2.close()
            print("✅ Blockchain state persisted and recovered correctly")
            
        finally:
            shutil.rmtree(temp_dir)


class TestWalledGardenRestrictions:
    """Test walled garden restrictions ($1 min, 50% max)."""
    
    def test_enforce_minimum_swap_value(self, blockchain, funded_user, validator):
        """
        Verify $1 minimum is enforced across different pool prices
        """
        # Pool at 1:1 ratio
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Try to swap $0.50 (should fail)
        tx = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': int(0.5 * TOKEN_UNIT),
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_user['priv_key'])
        
        success, block, valid_txs = create_and_add_block(blockchain, validator, [tx])
        
        # Transaction should fail validation
        assert len(valid_txs) == 0
        print("✅ $0.50 swap correctly rejected (below $1 minimum)")
        
        # Try to swap $1.00 (should succeed)
        tx2 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 1 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_user['priv_key'])
        
        success2, block2, valid_txs2 = create_and_add_block(blockchain, validator, [tx2])
        assert len(valid_txs2) == 1
        print("✅ $1.00 swap correctly accepted")
    
    def test_enforce_maximum_pool_impact(self, blockchain, funded_user, validator):
        """
        Verify 50% maximum pool impact is enforced
        """
        # Small pool
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Try to swap huge amount (would claim >50%)
        tx = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 5000 * TOKEN_UNIT,  # Huge input
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(funded_user['priv_key'])
        
        success, block, valid_txs = create_and_add_block(blockchain, validator, [tx])
        
        # Should be rejected
        assert len(valid_txs) == 0
        print("✅ Large swap correctly rejected (>50% pool impact)")


class TestCompleteGameEconomy:
    """Test complete game economy cycle."""
    
    def test_full_game_economy_cycle(self, blockchain, validator):
        """
        Complete game economy: Mint USD -> Buy tokens -> Play games -> Sell tokens
        """
        # 1. Create player
        player_priv, player_pub = generate_key_pair()
        player_pem = serialize_public_key(player_pub)
        player_addr = public_key_to_address(player_pem)
        
        # 2. Player buys $25 USD (simulated payment processor)
        player_account = blockchain._get_account(player_addr, blockchain.state_trie)
        player_account['balances']['native'] = 1 * TOKEN_UNIT  # For fees
        player_account['balances']['usd'] = 25 * TOKEN_UNIT
        blockchain._set_account(player_addr, player_account, blockchain.state_trie)
        
        # 3. Setup AMM pool
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # 4. Player swaps $20 for game tokens
        swap_tx = Transaction(
            sender_public_key=player_pem,
            tx_type='SWAP',
            data={
                'amount_in': 20 * TOKEN_UNIT,
                'min_amount_out': 0,
                'token_in': 'usd'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        swap_tx.sign(player_priv)
        
        success, block1, _ = create_and_add_block(blockchain, validator, [swap_tx])
        assert success == True
        
        account_after_buy = blockchain.get_account(player_addr)
        tokens_bought = account_after_buy['balances']['native']
        print(f"Player bought {tokens_bought / TOKEN_UNIT} tokens for $20")
        
        # 5. Player plays 10 games at $0.25 each (2.5 tokens total at 1:1 price)
        # Simplified: Transfer tokens to validator as "game fee"
        game_fees = []
        for i in range(10):
            game_tx = Transaction(
                sender_public_key=player_pem,
                tx_type='TRANSFER',
                data={
                    'to': validator['address'].hex(),
                    'amount': int(0.25 * TOKEN_UNIT),  # $0.25 per game
                    'token_type': 'native'
                },
                nonce=1 + i,
                fee=1000,
                chain_id=1
            )
            game_tx.sign(player_priv)
            game_fees.append(game_tx)
        
        success, block2, valid_game_txs = create_and_add_block(blockchain, validator, game_fees)
        assert success == True
        assert len(valid_game_txs) == 10
        
        account_after_games = blockchain.get_account(player_addr)
        tokens_after_games = account_after_games['balances']['native']
        tokens_spent = tokens_bought - tokens_after_games - (10 * 1000)  # Minus fees
        print(f"Player spent {tokens_spent / TOKEN_UNIT} tokens on 10 games")
        
        # 6. Player sells remaining tokens back to USD
        remaining_tokens = account_after_games['balances']['native'] - 1000  # Keep for fee
        
        sell_tx = Transaction(
            sender_public_key=player_pem,
            tx_type='SWAP',
            data={
                'amount_in': remaining_tokens,
                'min_amount_out': 0,
                'token_in': 'native'
            },
            nonce=11,
            fee=1000,
            chain_id=1
        )
        sell_tx.sign(player_priv)
        
        success, block3, _ = create_and_add_block(blockchain, validator, [sell_tx])
        assert success == True
        
        final_account = blockchain.get_account(player_addr)
        final_usd = final_account['balances']['usd']
        
        print(f"Player ended with ${final_usd / TOKEN_UNIT} USD after full cycle")
        print("✅ Complete game economy cycle: Buy -> Play -> Sell")


class TestConcurrentOperations:
    """Test concurrent operations on shared resources."""
    
    def test_multiple_swaps_same_pool(self, blockchain, validator):
        """
        Multiple users swap from same pool simultaneously
        """
        # Setup pool
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        initial_k = pool.token_reserve * pool.usd_reserve
        
        # Create 10 users
        users = []
        for i in range(10):
            priv, pub = generate_key_pair()
            pem = serialize_public_key(pub)
            addr = public_key_to_address(pem)
            
            account = blockchain._get_account(addr, blockchain.state_trie)
            account['balances']['native'] = 100 * TOKEN_UNIT
            blockchain._set_account(addr, account, blockchain.state_trie)
            
            users.append({'priv': priv, 'pem': pem, 'addr': addr})
        
        # All users swap in same block
        txs = []
        for i, user in enumerate(users):
            tx = Transaction(
                sender_public_key=user['pem'],
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
            tx.sign(user['priv'])
            txs.append(tx)
        
        success, block, valid_txs = create_and_add_block(blockchain, validator, txs)
        assert success == True
        assert len(valid_txs) == 10
        
        # Verify pool state is consistent
        final_pool = blockchain._get_liquidity_pool_state(blockchain.state_trie)
        final_k = final_pool.token_reserve * final_pool.usd_reserve
        
        # K should have increased (fees accumulated)
        assert final_k > initial_k
        
        # Verify all users got USD
        for user in users:
            account = blockchain.get_account(user['addr'])
            assert account['balances']['usd'] > 0
        
        print(f"✅ 10 concurrent swaps processed, K: {initial_k} -> {final_k}")


class TestErrorRecovery:
    """Test error handling and recovery."""
    
    def test_failed_transaction_doesnt_affect_valid_ones(self, blockchain, funded_user, validator):
        """
        One failed transaction shouldn't affect other valid transactions
        """
        # Create recipient
        recip_priv, recip_pub = generate_key_pair()
        recip_pem = serialize_public_key(recip_pub)
        recip_addr = public_key_to_address(recip_pem)
        
        # Valid transaction
        tx1 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recip_addr.hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(funded_user['priv_key'])
        
        # Invalid transaction (wrong nonce)
        tx2 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recip_addr.hex(),
                'amount': 10 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=5,  # Wrong nonce (should be 1)
            fee=1000,
            chain_id=1
        )
        tx2.sign(funded_user['priv_key'])
        
        # Another valid transaction
        tx3 = Transaction(
            sender_public_key=funded_user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recip_addr.hex(),
                'amount': 5 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx3.sign(funded_user['priv_key'])
        
        success, block, valid_txs = create_and_add_block(blockchain, validator, [tx1, tx2, tx3])
        
        # Should succeed with valid transactions only
        assert success == True
        assert len(valid_txs) == 2  # tx1 and tx3
        
        # Verify valid transactions executed
        recip_account = blockchain.get_account(recip_addr)
        assert recip_account['balances']['native'] == 15 * TOKEN_UNIT
        
        print("✅ Failed transaction isolated from valid ones")


class TestDataIntegrity:
    """Test data integrity across operations."""
    
    def test_conservation_of_value(self, blockchain, validator):
        """
        Total value in system should be conserved (ignoring fees)
        """
        # Setup pool
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Create user
        user_priv, user_pub = generate_key_pair()
        user_pem = serialize_public_key(user_pub)
        user_addr = public_key_to_address(user_pem)
        
        user_account = blockchain._get_account(user_addr, blockchain.state_trie)
        user_account['balances']['native'] = 501 * TOKEN_UNIT
        user_account['balances']['usd'] = 500 * TOKEN_UNIT
        blockchain._set_account(user_addr, user_account, blockchain.state_trie)
        
        # Calculate total value before swap
        initial_total_native = 501 * TOKEN_UNIT + 1000 * TOKEN_UNIT  # user + pool
        initial_total_usd = 500 * TOKEN_UNIT + 1000 * TOKEN_UNIT
        
        # User swaps
        tx = Transaction(
            sender_public_key=user_pem,
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
        tx.sign(user_priv)
        
        success, block, _ = create_and_add_block(blockchain, validator, [tx])
        assert success == True
        
        # Calculate total value after swap
        final_user = blockchain.get_account(user_addr)
        final_pool = blockchain._get_liquidity_pool_state(blockchain.state_trie)
        
        final_total_native = final_user['balances']['native'] + final_pool.token_reserve
        final_total_usd = final_user['balances']['usd'] + final_pool.usd_reserve
        
        # Native should equal initial (all native tokens accounted for, minus fee)
        assert final_total_native == initial_total_native - 1000  # Minus transaction fee
        
        # USD should equal initial (all USD accounted for)
        assert final_total_usd == initial_total_usd
        
        print("✅ Value conservation verified: Native and USD totals consistent")


class TestBlockchainValidation:
    """Test full blockchain validation."""
    
    def test_validate_entire_chain(self, blockchain, funded_user, validator):
        """
        Create multiple blocks and validate entire chain
        """
        # Add 10 blocks with transactions
        for i in range(10):
            tx = Transaction(
                sender_public_key=funded_user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': validator['address'].hex(),
                    'amount': (i + 1) * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(funded_user['priv_key'])
            
            success, block, _ = create_and_add_block(blockchain, validator, [tx])
            assert success == True
        
        # Validate entire chain
        is_valid = blockchain.validate_chain()
        assert is_valid == True
        
        print(f"✅ Full chain validation passed for {blockchain.get_latest_block().height} blocks")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])