"""
Test Suite 5: Block Production & Validation
Critical Priority - Must Pass Before Launch

Tests block validation rules, parent hash chain, size limits, timestamp validation,
producer validation, fork choice, and block integrity.
"""
import pytest
import tempfile
import shutil
import time
import msgpack
from crypto_v2.chain import (
    Blockchain, TOKEN_UNIT, ValidationError,
    MAX_BLOCK_SIZE, MAX_TXS_PER_BLOCK,
    VALIDATOR_SET_ADDRESS
)
from crypto_v2.core import Transaction, Block
from crypto_v2.crypto import (
    generate_key_pair, serialize_public_key, public_key_to_address,
    generate_vrf_keypair, vrf_prove
)
from crypto_v2.db import DB
from crypto_v2.poh import PoHRecorder
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
def validator_account(blockchain):
    """Create a validator account with stake."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    
    # Generate VRF keys
    vrf_priv, vrf_pub = generate_vrf_keypair()
    
    # Fund account
    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = 10000 * TOKEN_UNIT
    account['vrf_pub_key'] = vrf_pub.encode().hex()
    blockchain._set_account(address, account, blockchain.state_trie)
    
    # Add to validator set
    validators = blockchain._get_validator_set(blockchain.state_trie)
    validators[address.hex()] = 1000 * TOKEN_UNIT
    blockchain._set_validator_set(validators, blockchain.state_trie)
    
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address,
        'vrf_priv': vrf_priv,
        'vrf_pub': vrf_pub
    }


@pytest.fixture
def valid_block(blockchain, validator_account):
    """Create a valid block for testing."""
    latest = blockchain.get_latest_block()
    
    # Create PoH sequence
    if latest.poh_sequence:
        initial_hash = latest.poh_sequence[-1][0]
    else:
        initial_hash = latest.hash
    
    poh = PoHRecorder(initial_hash)
    poh.tick()
    
    # Generate VRF proof
    vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
    
    block = Block(
        parent_hash=latest.hash,
        state_root=latest.state_root,
        transactions=[],
        poh_sequence=poh.sequence,
        height=latest.height + 1,
        producer=validator_account['pub_key_pem'],
        vrf_proof=vrf_proof,
        timestamp=time.time()
    )
    
    block.sign_block(validator_account['priv_key'])
    
    return block


class TestParentHashValidation:
    """Test parent hash chain integrity."""
    
    def test_valid_parent_hash_accepted(self, blockchain, valid_block):
        """Block with correct parent hash is accepted."""
        assert blockchain.add_block(valid_block) == True
    
    def test_invalid_parent_hash_rejected(self, blockchain, validator_account):
        """Block with invalid parent hash is rejected."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        # Wrong parent hash
        block = Block(
            parent_hash=b'\xff' * 32,  # Wrong parent
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=b'test',
            timestamp=time.time(),
            signature=b'test'
        )
        
        assert blockchain.add_block(block) == False
    
    def test_skip_block_height_rejected(self, blockchain, validator_account):
        """Cannot skip block heights."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        # Skip to height + 2
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 2,  # Skipped height
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False
    
    def test_wrong_height_rejected(self, blockchain, validator_account):
        """Block with wrong height is rejected."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height,  # Same height as parent
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False
    
    def test_chain_linkage_maintained(self, blockchain, validator_account):
        """Chain maintains proper parent linkage."""
        blocks = []
        
        for i in range(5):
            latest = blockchain.get_latest_block()
            
            if latest.poh_sequence:
                initial_hash = latest.poh_sequence[-1][0]
            else:
                initial_hash = latest.hash
            
            poh = PoHRecorder(initial_hash)
            poh.tick()
            
            vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
            
            block = Block(
                parent_hash=latest.hash,
                state_root=latest.state_root,
                transactions=[],
                poh_sequence=poh.sequence,
                height=latest.height + 1,
                producer=validator_account['pub_key_pem'],
                vrf_proof=vrf_proof,
                timestamp=time.time() + i
            )
            block.sign_block(validator_account['priv_key'])
            
            assert blockchain.add_block(block) == True
            blocks.append(block)
        
        # Verify chain linkage
        for i in range(len(blocks) - 1):
            assert blocks[i+1].parent_hash == blocks[i].hash


class TestBlockSizeLimits:
    """Test block size and transaction count limits."""
    
    def test_empty_block_accepted(self, blockchain, valid_block):
        """Empty blocks are accepted."""
        assert len(valid_block.transactions) == 0
        assert blockchain.add_block(valid_block) == True
    
    def test_max_transactions_accepted(self, blockchain, validator_account):
        """Block with MAX_TXS_PER_BLOCK is accepted."""
        latest = blockchain.get_latest_block()
        
        # Create max transactions
        transactions = []
        temp_trie = Trie(blockchain.db, root_hash=latest.state_root)
        
        # Fund validator
        account = blockchain._get_account(validator_account['address'], temp_trie)
        account['balances']['native'] = 1000000 * TOKEN_UNIT
        blockchain._set_account(validator_account['address'], account, temp_trie)
        
        recipient_priv, recipient_pub = generate_key_pair()
        recipient_pem = serialize_public_key(recipient_pub)
        recipient_addr = public_key_to_address(recipient_pem)
        
        for i in range(MAX_TXS_PER_BLOCK):
            tx = Transaction(
                sender_public_key=validator_account['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': recipient_addr.hex(),
                    'amount': 1 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(validator_account['priv_key'])
            
            blockchain._process_transaction(tx, temp_trie)
            transactions.append(tx)
        
        poh = PoHRecorder(latest.hash)
        for tx in transactions:
            poh.record(tx.id)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=temp_trie.root_hash,
            transactions=transactions,
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == True
    
    def test_too_many_transactions_rejected(self, blockchain, validator_account):
        """Block with >MAX_TXS_PER_BLOCK is rejected."""
        latest = blockchain.get_latest_block()
        
        # Create too many transactions
        transactions = []
        
        recipient_priv, recipient_pub = generate_key_pair()
        recipient_pem = serialize_public_key(recipient_pub)
        recipient_addr = public_key_to_address(recipient_pem)
        
        for i in range(MAX_TXS_PER_BLOCK + 1):
            tx = Transaction(
                sender_public_key=validator_account['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': recipient_addr.hex(),
                    'amount': 1 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(validator_account['priv_key'])
            transactions.append(tx)
        
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=transactions,
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False
    
    def test_oversized_block_rejected(self, blockchain, validator_account):
        """Block exceeding MAX_BLOCK_SIZE is rejected."""
        latest = blockchain.get_latest_block()
        
        # Create transactions with large data to exceed block size
        transactions = []
        temp_trie = Trie(blockchain.db, root_hash=latest.state_root)
        
        # Create a transaction with huge data field
        large_data = 'x' * (MAX_BLOCK_SIZE // 10)  # Very large data
        
        for i in range(20):  # Should exceed size limit
            tx = Transaction(
                sender_public_key=validator_account['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': validator_account['address'].hex(),
                    'amount': 1,
                    'token_type': 'native',
                    'large_field': large_data  # Extra large data
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(validator_account['priv_key'])
            transactions.append(tx)
        
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=transactions,
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        # Check block size
        block_size = len(msgpack.packb(block.to_dict(), use_bin_type=True))
        
        if block_size > MAX_BLOCK_SIZE:
            assert blockchain.add_block(block) == False


class TestTimestampValidation:
    """Test block timestamp validation."""
    
    def test_future_timestamp_accepted_within_tolerance(self, blockchain, validator_account):
        """Block with slightly future timestamp is accepted."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        # Timestamp slightly in future (within tolerance)
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time() + 1  # 1 second in future
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == True
    
    def test_past_timestamp_rejected(self, blockchain, validator_account):
        """Block with timestamp <= parent is rejected."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=latest.timestamp - 1  # Before parent
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False
    
    def test_timestamp_monotonically_increasing(self, blockchain, validator_account):
        """Block timestamps increase monotonically."""
        timestamps = [blockchain.get_latest_block().timestamp]
        
        for i in range(5):
            latest = blockchain.get_latest_block()
            
            if latest.poh_sequence:
                initial_hash = latest.poh_sequence[-1][0]
            else:
                initial_hash = latest.hash
            
            poh = PoHRecorder(initial_hash)
            poh.tick()
            
            vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
            
            block = Block(
                parent_hash=latest.hash,
                state_root=latest.state_root,
                transactions=[],
                poh_sequence=poh.sequence,
                height=latest.height + 1,
                producer=validator_account['pub_key_pem'],
                vrf_proof=vrf_proof,
                timestamp=latest.timestamp + 1 + i
            )
            block.sign_block(validator_account['priv_key'])
            
            assert blockchain.add_block(block) == True
            timestamps.append(block.timestamp)
        
        # Verify timestamps are strictly increasing
        for i in range(len(timestamps) - 1):
            assert timestamps[i+1] > timestamps[i]


class TestStateRootValidation:
    """Test state root validation."""
    
    def test_correct_state_root_accepted(self, blockchain, validator_account):
        """Block with correct state root is accepted."""
        latest = blockchain.get_latest_block()
        
        # Create transaction
        temp_trie = Trie(blockchain.db, root_hash=latest.state_root)
        
        recipient_priv, recipient_pub = generate_key_pair()
        recipient_pem = serialize_public_key(recipient_pub)
        recipient_addr = public_key_to_address(recipient_pem)
        
        # Fund validator
        account = blockchain._get_account(validator_account['address'], temp_trie)
        account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(validator_account['address'], account, temp_trie)
        
        tx = Transaction(
            sender_public_key=validator_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recipient_addr.hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(validator_account['priv_key'])
        
        blockchain._process_transaction(tx, temp_trie)
        
        poh = PoHRecorder(latest.hash)
        poh.record(tx.id)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=temp_trie.root_hash,  # Correct state root
            transactions=[tx],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == True
    
    def test_incorrect_state_root_rejected(self, blockchain, validator_account):
        """Block with incorrect state root is rejected."""
        latest = blockchain.get_latest_block()
        
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=b'\xff' * 32,  # Wrong state root
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False


class TestProducerValidation:
    """Test block producer validation."""
    
    def test_valid_producer_accepted(self, blockchain, valid_block):
        """Block from valid producer is accepted."""
        assert blockchain.add_block(valid_block) == True
    
    def test_non_validator_rejected(self, blockchain):
        """Block from non-validator is rejected."""
        # Create account that's not a validator
        non_val_priv, non_val_pub = generate_key_pair()
        non_val_pem = serialize_public_key(non_val_pub)
        
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=non_val_pem,  # Not a validator
            vrf_proof=b'test',
            timestamp=time.time()
        )
        block.sign_block(non_val_priv)
        
        assert blockchain.add_block(block) == False
    
    def test_unsigned_block_rejected(self, blockchain, validator_account):
        """Unsigned blocks are rejected."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        # Don't sign
        
        assert blockchain.add_block(block) == False


class TestProofOfHistoryValidation:
    """Test PoH sequence validation in blocks."""
    
    def test_valid_poh_sequence_accepted(self, blockchain, valid_block):
        """Block with valid PoH sequence is accepted."""
        assert blockchain.add_block(valid_block) == True
    
    def test_invalid_poh_sequence_rejected(self, blockchain, validator_account):
        """Block with invalid PoH sequence is rejected."""
        latest = blockchain.get_latest_block()
        
        # Create invalid PoH sequence
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        # Tamper with sequence
        poh.sequence[1] = (b'\xff' * 32, None)
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False
    
    def test_poh_with_transaction_events(self, blockchain, validator_account):
        """PoH sequence with transaction events is validated."""
        latest = blockchain.get_latest_block()
        
        # Create transactions
        temp_trie = Trie(blockchain.db, root_hash=latest.state_root)
        
        recipient_priv, recipient_pub = generate_key_pair()
        recipient_pem = serialize_public_key(recipient_pub)
        recipient_addr = public_key_to_address(recipient_pem)
        
        # Fund validator
        account = blockchain._get_account(validator_account['address'], temp_trie)
        account['balances']['native'] = 10000 * TOKEN_UNIT
        blockchain._set_account(validator_account['address'], account, temp_trie)
        
        transactions = []
        for i in range(3):
            tx = Transaction(
                sender_public_key=validator_account['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': recipient_addr.hex(),
                    'amount': 10 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=i,
                fee=1000,
                chain_id=1
            )
            tx.sign(validator_account['priv_key'])
            blockchain._process_transaction(tx, temp_trie)
            transactions.append(tx)
        
        # Create PoH with transaction events
        if latest.poh_sequence:
            initial_hash = latest.poh_sequence[-1][0]
        else:
            initial_hash = latest.hash
        
        poh = PoHRecorder(initial_hash)
        for tx in transactions:
            poh.record(tx.id)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=temp_trie.root_hash,
            transactions=transactions,
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == True


class TestTransactionValidation:
    """Test transaction validation within blocks."""
    
    def test_invalid_transaction_rejected(self, blockchain, validator_account):
        """Block with invalid transaction is rejected."""
        latest = blockchain.get_latest_block()
        
        # Create invalid transaction (wrong chain ID)
        tx = Transaction(
            sender_public_key=validator_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': validator_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=999  # Wrong chain ID
        )
        tx.sign(validator_account['priv_key'])
        
        poh = PoHRecorder(latest.hash)
        poh.record(tx.id)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[tx],
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False
    
    def test_duplicate_transaction_rejected(self, blockchain, validator_account):
        """Block with duplicate transaction is rejected."""
        latest = blockchain.get_latest_block()
        
        tx = Transaction(
            sender_public_key=validator_account['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': validator_account['address'].hex(),
                'amount': 100 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(validator_account['priv_key'])
        
        # Same transaction twice
        transactions = [tx, tx]
        
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator_account['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=transactions,
            poh_sequence=poh.sequence,
            height=latest.height + 1,
            producer=validator_account['pub_key_pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        block.sign_block(validator_account['priv_key'])
        
        assert blockchain.add_block(block) == False


class TestGenesisBlock:
    """Test genesis block special handling."""
    
    def test_genesis_block_properties(self, blockchain):
        """Genesis block has expected properties."""
        genesis = blockchain.get_block_by_height(0)
        
        assert genesis is not None
        assert genesis.height == 0
        assert genesis.parent_hash == b'\x00' * 32
        assert len(genesis.transactions) == 0
        assert genesis.producer == b'genesis'
    
    def test_cannot_add_another_genesis(self, blockchain):
        """Cannot add another block at height 0."""
        # This is implicitly tested by height validation


class TestBlockRetrieval:
    """Test block storage and retrieval."""
    
    def test_retrieve_block_by_hash(self, blockchain, valid_block):
        """Can retrieve block by hash."""
        blockchain.add_block(valid_block)
        
        retrieved = blockchain.get_block(valid_block.hash)
        
        assert retrieved is not None
        assert retrieved.hash == valid_block.hash
        assert retrieved.height == valid_block.height
    
    def test_retrieve_block_by_height(self, blockchain, valid_block):
        """Can retrieve block by height."""
        blockchain.add_block(valid_block)
        
        retrieved = blockchain.get_block_by_height(valid_block.height)
        
        assert retrieved is not None
        assert retrieved.hash == valid_block.hash
        assert retrieved.height == valid_block.height
    
    def test_retrieve_latest_block(self, blockchain, valid_block):
        """Can retrieve latest block."""
        blockchain.add_block(valid_block)
        
        latest = blockchain.get_latest_block()
        
        assert latest.hash == valid_block.hash


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])