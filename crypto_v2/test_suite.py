"""
═══════════════════════════════════════════════════════════════════════════
                    COMPREHENSIVE TEST SUITE
              Unit, Integration, Security, and Stress Tests
═══════════════════════════════════════════════════════════════════════════

Run tests:
    python3 -m pytest test_suite.py -v
    python3 -m pytest test_suite.py -v -k "test_security"  # Only security tests
    python3 -m pytest test_suite.py --cov=crypto_v2 --cov-report=html

Coverage target: 80%+
"""

import pytest
import time
import os
import tempfile
import shutil
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import blockchain modules
from crypto_v2.core import Transaction, Block, BlockHeader
from crypto_v2.chain import Blockchain, TOKEN_UNIT, ValidationError
from crypto_v2.crypto import (
    generate_key_pair, 
    serialize_public_key, 
    public_key_to_address,
    generate_hash,
    sign,
    verify_signature,
    generate_vrf_keypair
)
from crypto_v2.db import DB
from crypto_v2.trie import Trie, BLANK_ROOT
from crypto_v2.mempool import Mempool
from crypto_v2.tokenomics_state import TokenomicsState
from crypto_v2.amm_state import LiquidityPoolState


# ==============================================================================
# TEST FIXTURES
# ==============================================================================

@pytest.fixture
def temp_db_path():
    """Create temporary database for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def db(temp_db_path):
    """Create a test database."""
    db = DB(temp_db_path)
    yield db
    db.close()


@pytest.fixture
def test_keys():
    """Generate test keypairs."""
    alice_priv, alice_pub = generate_key_pair()
    bob_priv, bob_pub = generate_key_pair()
    
    return {
        'alice': {
            'private': alice_priv,
            'public': alice_pub,
            'public_pem': serialize_public_key(alice_pub),
            'address': public_key_to_address(serialize_public_key(alice_pub))
        },
        'bob': {
            'private': bob_priv,
            'public': bob_pub,
            'public_pem': serialize_public_key(bob_pub),
            'address': public_key_to_address(serialize_public_key(bob_pub))
        }
    }


@pytest.fixture
def blockchain(temp_db_path, test_keys):
    """Create a test blockchain with genesis block."""
    from crypto_v2.chain import (
        VALIDATOR_SET_ADDRESS, 
        TOKENOMICS_ADDRESS,
        TREASURY_ADDRESS
    )
    
    db = DB(temp_db_path)
    trie = Trie(db, root_hash=BLANK_ROOT)
    
    # Initialize validator
    alice_addr = test_keys['alice']['address']
    validators = {alice_addr.hex(): 1000 * TOKEN_UNIT}
    
    import msgpack
    trie.set(VALIDATOR_SET_ADDRESS, msgpack.packb(validators, use_bin_type=True))
    
    # Initialize treasury
    treasury_account = {
        'balances': {'native': 84_000_000 * TOKEN_UNIT, 'usd': 0},
        'nonce': 0,
        'lp_tokens': 0
    }
    trie.set(b"ACCOUNT:" + TREASURY_ADDRESS, msgpack.packb(treasury_account))
    
    # Initialize tokenomics
    tokenomics = TokenomicsState({
        'total_supply': 100_000_000 * TOKEN_UNIT,
        'total_minted': 100_000_000 * TOKEN_UNIT,
        'total_burned': 0,
        'total_usd_in': 0,
        'total_usd_out': 0,
    })
    trie.set(TOKENOMICS_ADDRESS, msgpack.packb(tokenomics.to_dict(), use_bin_type=True))
    
    # Create genesis block
    vrf_sk, vrf_pk = generate_vrf_keypair()
    
    genesis_block = Block(
        parent_hash=b'\x00' * 32,
        state_root=trie.root_hash,
        transactions=[],
        poh_sequence=[(b'\x00' * 32, None)],
        height=0,
        producer_pubkey=test_keys['alice']['public_pem'],
        vrf_proof=b'\x00' * 64,
        vrf_pub_key=bytes(vrf_pk),
        poh_initial=b'\x00' * 32,
        timestamp=time.time(),
        attestations=[]
    )
    
    genesis_block.sign_block(test_keys['alice']['private'])
    
    # Store genesis
    block_data = msgpack.packb(genesis_block.to_dict(), use_bin_type=True)
    db.put(b'block:' + genesis_block.hash, block_data)
    db.put(b'height:0', genesis_block.hash)
    db.put(b'head', genesis_block.hash)
    
    # Create blockchain
    chain = Blockchain(db=db)
    
    yield chain
    
    db.close()


# ==============================================================================
# UNIT TESTS - CRYPTOGRAPHY
# ==============================================================================

class TestCryptography:
    """Test cryptographic functions."""
    
    def test_key_generation(self):
        """Test key pair generation."""
        priv, pub = generate_key_pair()
        assert priv is not None
        assert pub is not None
        
    def test_signature_creation_and_verification(self, test_keys):
        """Test signing and verification."""
        data = b"test message"
        signature = sign(test_keys['alice']['private'], data)
        
        assert signature is not None
        assert len(signature) > 0
        
        # Verify with correct key
        assert verify_signature(
            test_keys['alice']['public_pem'],
            signature,
            data
        )
        
        # Verify fails with wrong key
        assert not verify_signature(
            test_keys['bob']['public_pem'],
            signature,
            data
        )
        
    def test_address_derivation(self, test_keys):
        """Test address derivation from public key."""
        address = public_key_to_address(test_keys['alice']['public_pem'])
        
        assert len(address) == 20
        assert isinstance(address, bytes)
        
        # Same key should produce same address
        address2 = public_key_to_address(test_keys['alice']['public_pem'])
        assert address == address2
        
    def test_hash_generation(self):
        """Test hash generation."""
        data = b"test data"
        hash1 = generate_hash(data)
        hash2 = generate_hash(data)
        
        assert len(hash1) == 32
        assert hash1 == hash2
        
        # Different data produces different hash
        hash3 = generate_hash(b"different data")
        assert hash1 != hash3


# ==============================================================================
# UNIT TESTS - TRANSACTIONS
# ==============================================================================

class TestTransactions:
    """Test transaction creation and validation."""
    
    def test_transaction_creation(self, test_keys):
        """Test creating a transaction."""
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={
                'to': test_keys['bob']['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1,
            gas_limit=1_000_000
        )
        
        assert tx.tx_type == 'TRANSFER'
        assert tx.nonce == 0
        assert tx.fee == 1000
        assert tx.gas_limit == 1_000_000
        
    def test_transaction_signing(self, test_keys):
        """Test transaction signing."""
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        
        tx.sign(test_keys['alice']['private'])
        
        assert tx.signature is not None
        assert tx.verify_signature()
        
    def test_transaction_validation(self, test_keys):
        """Test transaction validation."""
        # Valid transaction
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        is_valid, error = tx.validate_basic()
        assert is_valid
        assert error == ""
        
        # Invalid transaction (negative fee)
        tx_bad = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=-100,  # Invalid
            chain_id=1
        )
        tx_bad.sign(test_keys['alice']['private'])
        
        is_valid, error = tx_bad.validate_basic()
        assert not is_valid
        assert "Negative fee" in error


# ==============================================================================
# UNIT TESTS - BLOCKCHAIN STATE
# ==============================================================================

class TestBlockchainState:
    """Test blockchain state management."""
    
    def test_account_creation(self, blockchain, test_keys):
        """Test creating and retrieving accounts."""
        address = test_keys['alice']['address']
        
        # Fund account
        account = blockchain._get_account(address, blockchain.state_trie)
        account['balances']['native'] = 1000 * TOKEN_UNIT
        blockchain._set_account(address, account, blockchain.state_trie)
        
        # Retrieve and verify
        retrieved = blockchain._get_account(address, blockchain.state_trie)
        assert retrieved['balances']['native'] == 1000 * TOKEN_UNIT
        assert retrieved['nonce'] == 0
        
    def test_validator_set(self, blockchain, test_keys):
        """Test validator set management."""
        validators = blockchain._get_validator_set(blockchain.state_trie)
        
        assert test_keys['alice']['address'].hex() in validators
        assert validators[test_keys['alice']['address'].hex()] == 1000 * TOKEN_UNIT
        
    def test_tokenomics_state(self, blockchain):
        """Test tokenomics state."""
        state = blockchain._get_tokenomics_state(blockchain.state_trie)
        
        assert state.total_supply == 100_000_000 * TOKEN_UNIT
        assert state.total_minted == 100_000_000 * TOKEN_UNIT
        assert state.total_burned == 0


# ==============================================================================
# INTEGRATION TESTS - TRANSACTIONS
# ==============================================================================

class TestTransactionProcessing:
    """Test transaction processing end-to-end."""
    
    def test_transfer_native_tokens(self, blockchain, test_keys):
        """Test transferring native tokens."""
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Create transfer
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={
                'to': test_keys['bob']['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        # Process transaction
        blockchain._process_transaction(tx, blockchain.state_trie)
        
        # Verify balances
        alice_after = blockchain._get_account(alice_addr, blockchain.state_trie)
        bob_after = blockchain._get_account(test_keys['bob']['address'], blockchain.state_trie)
        
        assert alice_after['balances']['native'] == (10000 - 100) * TOKEN_UNIT - 1000
        assert bob_after['balances']['native'] == 100 * TOKEN_UNIT
        assert alice_after['nonce'] == 1
        
    def test_stake_tokens(self, blockchain, test_keys):
        """Test staking tokens."""
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Stake
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='STAKE',
            data={'amount': 500 * TOKEN_UNIT},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        blockchain._process_transaction(tx, blockchain.state_trie)
        
        # Verify stake
        validators = blockchain._get_validator_set(blockchain.state_trie)
        assert validators[alice_addr.hex()] == 1500 * TOKEN_UNIT  # 1000 initial + 500 staked
        
        # Verify balance deducted
        alice_after = blockchain._get_account(alice_addr, blockchain.state_trie)
        assert alice_after['balances']['native'] == (10000 - 500) * TOKEN_UNIT - 1000


# ==============================================================================
# INTEGRATION TESTS - AMM & SWAPS
# ==============================================================================

class TestAMM:
    """Test AMM functionality."""
    
    def test_add_liquidity(self, blockchain, test_keys):
        """Test adding liquidity to AMM pool."""
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 1000 * TOKEN_UNIT
        alice_account['balances']['usd'] = 1000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Add liquidity
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='ADD_LIQUIDITY',
            data={
                'native_amount': 100 * TOKEN_UNIT,
                'usd_amount': 100 * TOKEN_UNIT
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        blockchain._process_transaction(tx, blockchain.state_trie)
        
        # Verify pool
        pool = blockchain._get_liquidity_pool_state(blockchain.state_trie)
        assert pool.token_reserve == 100 * TOKEN_UNIT
        assert pool.usd_reserve == 100 * TOKEN_UNIT
        
        # Verify LP tokens (geometric mean minus locked liquidity)
        import math
        expected_lp = int(math.sqrt(100 * TOKEN_UNIT * 100 * TOKEN_UNIT)) - 1000
        alice_after = blockchain._get_account(alice_addr, blockchain.state_trie)
        assert alice_after['lp_tokens'] == expected_lp
        
    def test_swap_tokens(self, blockchain, test_keys):
        """Test swapping tokens via AMM."""
        # Setup pool first
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 2000 * TOKEN_UNIT
        alice_account['balances']['usd'] = 2000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Add liquidity
        tx1 = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='ADD_LIQUIDITY',
            data={'native_amount': 1000 * TOKEN_UNIT, 'usd_amount': 1000 * TOKEN_UNIT},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(test_keys['alice']['private'])
        blockchain._process_transaction(tx1, blockchain.state_trie)
        
        # Perform swap
        tx2 = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 10 * TOKEN_UNIT,
                'token_in': 'native',
                'min_amount_out': 0
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(test_keys['alice']['private'])
        blockchain._process_transaction(tx2, blockchain.state_trie)
        
        # Verify swap occurred
        alice_after = blockchain._get_account(alice_addr, blockchain.state_trie)
        assert alice_after['balances']['usd'] > 1000 * TOKEN_UNIT  # Received USD


# ==============================================================================
# SECURITY TESTS
# ==============================================================================

class TestSecurity:
    """Security-focused tests."""
    
    def test_replay_attack_prevention(self, blockchain, test_keys):
        """Test that transactions can't be replayed."""
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Create and process transaction
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100 * TOKEN_UNIT, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        blockchain._process_transaction(tx, blockchain.state_trie)
        
        # Try to replay (should fail with nonce error)
        with pytest.raises(ValidationError, match="Invalid nonce"):
            blockchain._process_transaction(tx, blockchain.state_trie)
            
    def test_signature_tampering(self, blockchain, test_keys):
        """Test that tampered transactions are rejected."""
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        # Tamper with amount after signing
        tx.data['amount'] = 10000 * TOKEN_UNIT
        
        # Should fail signature verification
        assert not tx.verify_signature()
        
    def test_insufficient_balance(self, blockchain, test_keys):
        """Test that transactions with insufficient balance fail."""
        alice_addr = test_keys['alice']['address']
        
        # Don't fund Alice
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100 * TOKEN_UNIT, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        with pytest.raises(ValidationError, match="Insufficient"):
            blockchain._process_transaction(tx, blockchain.state_trie)
            
    def test_double_spending(self, blockchain, test_keys):
        """Test that double spending is prevented."""
        # Fund Alice with exactly 100 tokens
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 100 * TOKEN_UNIT + 2000  # +2000 for fees
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Create two transactions spending the same funds
        tx1 = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100 * TOKEN_UNIT, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(test_keys['alice']['private'])
        
        tx2 = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100 * TOKEN_UNIT, 'token_type': 'native'},
            nonce=0,  # Same nonce
            fee=1000,
            chain_id=1
        )
        tx2.sign(test_keys['alice']['private'])
        
        # First should succeed
        blockchain._process_transaction(tx1, blockchain.state_trie)
        
        # Second should fail (nonce already used)
        with pytest.raises(ValidationError, match="Invalid nonce"):
            blockchain._process_transaction(tx2, blockchain.state_trie)
            
    def test_price_manipulation_protection(self, blockchain, test_keys):
        """Test TWAP protection against price manipulation."""
        # Setup large pool
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 100000 * TOKEN_UNIT
        alice_account['balances']['usd'] = 100000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Add liquidity
        tx1 = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='ADD_LIQUIDITY',
            data={'native_amount': 10000 * TOKEN_UNIT, 'usd_amount': 10000 * TOKEN_UNIT},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(test_keys['alice']['private'])
        blockchain._process_transaction(tx1, blockchain.state_trie)
        
        # Try to manipulate price with large swap (should be blocked by 50% limit)
        tx2 = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='SWAP',
            data={
                'amount_in': 6000 * TOKEN_UNIT,  # >50% of pool
                'token_in': 'native',
                'min_amount_out': 0
            },
            nonce=1,
            fee=1000,
            chain_id=1
        )
        tx2.sign(test_keys['alice']['private'])
        
        with pytest.raises(ValidationError, match="50%"):
            blockchain._process_transaction(tx2, blockchain.state_trie)


# ==============================================================================
# STRESS TESTS
# ==============================================================================

class TestStress:
    """Stress and performance tests."""
    
    def test_high_transaction_volume(self, blockchain, test_keys):
        """Test processing many transactions."""
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 1_000_000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Process 100 transactions
        num_txs = 100
        start_time = time.time()
        
        for i in range(num_txs):
            tx = Transaction(
                sender_public_key=test_keys['alice']['public_pem'],
                tx_type='TRANSFER',
                data={'to': test_keys['bob']['address'].hex(), 'amount': 1 * TOKEN_UNIT, 'token_type': 'native'},
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(test_keys['alice']['private'])
            blockchain._process_transaction(tx, blockchain.state_trie)
        
        elapsed = time.time() - start_time
        tps = num_txs / elapsed
        
        print(f"\nProcessed {num_txs} transactions in {elapsed:.2f}s ({tps:.2f} TPS)")
        assert tps > 10  # Should process at least 10 TPS
        
    def test_concurrent_transactions(self, blockchain, test_keys):
        """Test concurrent transaction processing."""
        # Fund multiple accounts
        accounts = []
        for i in range(10):
            priv, pub = generate_key_pair()
            pub_pem = serialize_public_key(pub)
            addr = public_key_to_address(pub_pem)
            
            account = blockchain._get_account(addr, blockchain.state_trie)
            account['balances']['native'] = 10000 * TOKEN_UNIT
            blockchain._set_account(addr, account, blockchain.state_trie)
            
            accounts.append({
                'private': priv,
                'public_pem': pub_pem,
                'address': addr
            })
        
        # Process transactions concurrently
        def process_tx(account_info, nonce):
            tx = Transaction(
                sender_public_key=account_info['public_pem'],
                tx_type='TRANSFER',
                data={'to': test_keys['bob']['address'].hex(), 'amount': 1 * TOKEN_UNIT, 'token_type': 'native'},
                nonce=nonce,
                fee=1000,
                chain_id=1
            )
            tx.sign(account_info['private'])
            blockchain._process_transaction(tx, blockchain.state_trie)
            return True
        
        # Note: This test shows the pattern, but true concurrency requires
        # proper locking in the blockchain implementation
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for account in accounts[:5]:
                future = executor.submit(process_tx, account, 0)
                futures.append(future)
            
            results = [f.result() for f in as_completed(futures)]
            assert all(results)


# ==============================================================================
# MEMPOOL TESTS
# ==============================================================================

class TestMempool:
    """Test mempool functionality."""
    
    def test_mempool_add_transaction(self, blockchain, test_keys):
        """Test adding transactions to mempool."""
        mempool = Mempool(
            get_account_state=lambda addr: blockchain._get_account(addr, blockchain.state_trie)
        )
        
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Create transaction
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100 * TOKEN_UNIT, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        success, error = mempool.add_transaction(tx)
        assert success
        assert error == ""
        assert mempool.size() == 1
        
    def test_mempool_duplicate_rejection(self, blockchain, test_keys):
        """Test that duplicate transactions are rejected."""
        mempool = Mempool()
        
        tx = Transaction(
            sender_public_key=test_keys['alice']['public_pem'],
            tx_type='TRANSFER',
            data={'to': test_keys['bob']['address'].hex(), 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(test_keys['alice']['private'])
        
        # Add once
        success1, _ = mempool.add_transaction(tx)
        assert success1
        
        # Try to add again
        success2, error2 = mempool.add_transaction(tx)
        assert not success2
        assert "Duplicate" in error2
        
    def test_mempool_fee_prioritization(self, blockchain, test_keys):
        """Test that transactions are prioritized by fee."""
        mempool = Mempool(
            get_account_state=lambda addr: blockchain._get_account(addr, blockchain.state_trie)
        )
        
        # Fund Alice
        alice_addr = test_keys['alice']['address']
        alice_account = blockchain._get_account(alice_addr, blockchain.state_trie)
        alice_account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(alice_addr, alice_account, blockchain.state_trie)
        
        # Add transactions with different fees
        for i, fee in enumerate([100, 1000, 500]):
            tx = Transaction(
                sender_public_key=test_keys['alice']['public_pem'],
                tx_type='TRANSFER',
                data={'to': test_keys['bob']['address'].hex(), 'amount': 1 * TOKEN_UNIT, 'token_type': 'native'},
                nonce=i,
                fee=fee,
                chain_id=1
            )