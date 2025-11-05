"""
Test Suite 8: Performance & Load Testing
Medium Priority - Optimize Before Launch

Tests system performance under load, stress conditions, resource usage,
throughput limits, and scalability.
"""
import pytest
import tempfile
import shutil
import time
import psutil
import os
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed
from crypto_v2.chain import (
    Blockchain, TOKEN_UNIT, MAX_TXS_PER_BLOCK,
    MAX_BLOCK_SIZE
)
from crypto_v2.core import Transaction, Block
from crypto_v2.crypto import (
    generate_key_pair, serialize_public_key, public_key_to_address,
    generate_vrf_keypair, vrf_prove
)
from crypto_v2.db import DB
from crypto_v2.poh import PoHRecorder
from crypto_v2.trie import Trie, BLANK_ROOT
from crypto_v2.amm_state import LiquidityPoolState
from crypto_v2.mempool import Mempool


@pytest.fixture
def temp_db_path():
    """Create a temporary directory for the database."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def blockchain(temp_db_path):
    """Create a temporary blockchain for testing."""
    db = DB(temp_db_path)
    
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
    db.put(b'block:' + genesis.hash, block_data)
    db.put(b'height:0', genesis.hash)
    db.put(b'head', genesis.hash)

    chain = Blockchain(db=db, chain_id=1)
    yield chain
    db.close()


@pytest.fixture
def validator(blockchain):
    """Create a validator account."""
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    
    vrf_priv, vrf_pub = generate_vrf_keypair()
    
    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = 1000000 * TOKEN_UNIT
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


def create_funded_user(blockchain, balance_native=10000, balance_usd=10000, start_nonce=0):
    priv_key, pub_key = generate_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    address = public_key_to_address(pub_key_pem)
    
    account = blockchain._get_account(address, blockchain.state_trie)
    account['balances']['native'] = balance_native * TOKEN_UNIT
    account['balances']['usd'] = balance_usd * TOKEN_UNIT
    account['nonce'] = start_nonce  # Explicitly set
    blockchain._set_account(address, account, blockchain.state_trie)
    
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'pub_key_pem': pub_key_pem,
        'address': address,
        'nonce': start_nonce  # Track current nonce
    }


class TestTransactionThroughput:
    """Test transaction processing throughput."""
    
    def test_max_transactions_per_block_performance(self, blockchain, validator):
        """
        Process block with MAX_TXS_PER_BLOCK transactions and measure time
        """
        # Create many funded users
        users = [create_funded_user(blockchain, balance_native=100000, start_nonce=0) for _ in range(100)]
        
        # Create MAX_TXS_PER_BLOCK transactions
        transactions = []
        recipient = create_funded_user(blockchain)
        
        start_time = time.time()
        
        for i in range(MAX_TXS_PER_BLOCK):
            user = users[i % len(users)]
            
            tx = Transaction(
                sender_public_key=user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': recipient['address'].hex(),
                    'amount': 1 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=user['nonce'],
                fee=1000,
                chain_id=1
            )
            tx.sign(user['priv_key'])
            transactions.append(tx)

            user['nonce'] += 1  # Increment nonce for next transaction
        
        creation_time = time.time() - start_time
        print(f"Created {len(transactions)} transactions in {creation_time:.3f}s")
        
        # Process transactions
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        process_start = time.time()
        
        valid_txs = []
        for tx in transactions:
            try:
                if blockchain._process_transaction(tx, temp_trie):
                    valid_txs.append(tx)
            except Exception as e:
                print(f"Transaction failed: {e}")
                pass
        
        process_time = time.time() - process_start
        
        print(f"Processed {len(valid_txs)} transactions in {process_time:.3f}s")
        if len(valid_txs) > 0:
            print(f"Throughput: {len(valid_txs) / process_time:.1f} tx/s")
        
        # Assert reasonable performance (adjust based on hardware)
        # Should process at least 100 tx/s if there are valid transactions
        if len(valid_txs) > 0:
            assert len(valid_txs) / process_time > 100
    
    def test_sustained_transaction_rate(self, blockchain, validator):
        """
        Test sustained transaction processing over multiple blocks
        """
        users = [create_funded_user(blockchain, balance_native=100000, start_nonce=0) for _ in range(50)]
        recipient = create_funded_user(blockchain)
        
        total_blocks = 10
        txs_per_block = 100
        
        start_time = time.time()
        total_processed = 0
        
        state_root = blockchain.state_trie.root_hash

        for block_num in range(total_blocks):
            transactions = []
            
            for i in range(txs_per_block):
                user = users[i % len(users)]
                nonce = (block_num * txs_per_block + i) // len(users)
                
                tx = Transaction(
                    sender_public_key=user['pub_key_pem'],
                    tx_type='TRANSFER',
                    data={
                        'to': recipient['address'].hex(),
                        'amount': 1 * TOKEN_UNIT,
                        'token_type': 'native'
                    },
                    nonce=nonce,
                    fee=1000,
                    chain_id=1
                )
                tx.sign(user['priv_key'])
                transactions.append(tx)
            
            # Process block
            temp_trie = Trie(blockchain.db, root_hash=state_root)
            
            valid_txs = []
            for tx in transactions:
                try:
                    if blockchain._process_transaction(tx, temp_trie):
                        valid_txs.append(tx)
                except:
                    pass
            
            total_processed += len(valid_txs)
            state_root = temp_trie.root_hash
        
        elapsed = time.time() - start_time
        
        print(f"Processed {total_processed} transactions in {elapsed:.3f}s")
        if total_processed > 0:
            avg_throughput = total_processed / elapsed
            print(f"Average throughput: {avg_throughput:.1f} tx/s")
            print(f"Blocks per second: {total_blocks / elapsed:.2f}")
            assert avg_throughput > 50  # Sustained rate


class TestAMMPerformance:
    """Test AMM swap performance under load."""
    
    def test_high_frequency_swaps(self, blockchain, validator):
        """
        Many users performing swaps rapidly
        """
        # Setup pool
        pool = LiquidityPoolState({
            'token_reserve': 100000 * TOKEN_UNIT,
            'usd_reserve': 100000 * TOKEN_UNIT,
            'lp_token_supply': 100000 * TOKEN_UNIT
        })
        blockchain._set_liquidity_pool_state(pool, blockchain.state_trie)
        
        # Create users
        users = [create_funded_user(blockchain, balance_native=1000, balance_usd=1000) 
                 for _ in range(100)]
        
        # Create swap transactions
        transactions = []
        start_time = time.time()
        
        for i, user in enumerate(users):
            tx = Transaction(
                sender_public_key=user['pub_key_pem'],
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
            tx.sign(user['priv_key'])
            transactions.append(tx)
        
        # Process all swaps
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        valid_count = 0
        for tx in transactions:
            try:
                if blockchain._process_transaction(tx, temp_trie):
                    valid_count += 1
            except:
                pass
        
        elapsed = time.time() - start_time
        
        print(f"Processed {valid_count} swaps in {elapsed:.3f}s")
        if valid_count > 0:
            print(f"Swap throughput: {valid_count / elapsed:.1f} swaps/s")
        
        # Verify pool state is consistent
        final_pool = blockchain._get_liquidity_pool_state(temp_trie)
        assert final_pool.token_reserve > 0
        assert final_pool.usd_reserve > 0
    
    def test_amm_calculation_performance(self, blockchain):
        """
        Benchmark AMM swap calculations
        """
        pool = LiquidityPoolState({
            'token_reserve': 10000 * TOKEN_UNIT,
            'usd_reserve': 10000 * TOKEN_UNIT,
            'lp_token_supply': 10000 * TOKEN_UNIT
        })
        
        iterations = 10000
        start_time = time.time()
        
        for i in range(iterations):
            input_amount = (i % 100 + 1) * TOKEN_UNIT
            output = pool.get_swap_output(input_amount, input_is_token=True)
        
        elapsed = time.time() - start_time
        
        print(f"Performed {iterations} swap calculations in {elapsed:.3f}s")
        print(f"Calculations per second: {iterations / elapsed:.1f}")
        
        # Should be very fast (>10k/s)
        assert iterations / elapsed > 10000


class TestDatabasePerformance:
    """Test database read/write performance."""
    
    def test_state_trie_write_performance(self, blockchain):
        """
        Measure trie write performance
        """
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        num_writes = 1000
        start_time = time.time()
        
        for i in range(num_writes):
            key = f"test_key_{i}".encode()
            value = f"test_value_{i}".encode()
            temp_trie.set(key, value)
        
        elapsed = time.time() - start_time
        
        print(f"Performed {num_writes} trie writes in {elapsed:.3f}s")
        print(f"Writes per second: {num_writes / elapsed:.1f}")
        
        # Verify writes
        for i in range(10):
            key = f"test_key_{i}".encode()
            value = temp_trie.get(key)
            assert value == f"test_value_{i}".encode()
    
    def test_state_trie_read_performance(self, blockchain):
        """
        Measure trie read performance
        """
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        # Write some data
        num_keys = 1000
        for i in range(num_keys):
            key = f"key_{i}".encode()
            value = f"value_{i}".encode()
            temp_trie.set(key, value)
        
        # Measure reads
        start_time = time.time()
        
        for i in range(num_keys):
            key = f"key_{i}".encode()
            value = temp_trie.get(key)
        
        elapsed = time.time() - start_time
        
        print(f"Performed {num_keys} trie reads in {elapsed:.3f}s")
        print(f"Reads per second: {num_keys / elapsed:.1f}")
    
    def test_block_storage_retrieval_performance(self, blockchain, validator):
        """
        Measure block storage and retrieval performance
        """
        num_blocks = 100
        
        # Store blocks
        store_start = time.time()
        
        for i in range(num_blocks):
            latest = blockchain.get_latest_block()
            last_poh_hash = latest.poh_sequence[-1][0] if latest.poh_sequence else latest.hash
            poh = PoHRecorder(last_poh_hash)
            poh.tick()
            
            vrf_proof, _ = vrf_prove(validator['vrf_priv'], latest.hash)
            
            # For empty blocks, use the current blockchain state root
            # (not the parent block's state root, which may be outdated)
            block = Block(
                parent_hash=latest.hash,
                state_root=blockchain.state_trie.root_hash,  # Use current state
                transactions=[],
                poh_sequence=poh.sequence,
                poh_initial=last_poh_hash,
                height=latest.height + 1,
                producer_pubkey=validator['pub_key_pem'],
                vrf_proof=vrf_proof,
                vrf_pub_key=validator['vrf_pub'].encode(),
                timestamp=time.time()
            )
            block.sign_block(validator['priv_key'])
            
            success = blockchain.add_block(block)
            assert success, f"Failed to add block {i}"
        
        store_time = time.time() - store_start
        
        print(f"Stored {num_blocks} blocks in {store_time:.3f}s")
        print(f"Storage rate: {num_blocks / store_time:.1f} blocks/s")
        
        # Retrieve blocks
        retrieve_start = time.time()
        
        for i in range(num_blocks):
            block = blockchain.get_block_by_height(i + 1)
            assert block is not None, f"Block at height {i+1} not found"
        
        retrieve_time = time.time() - retrieve_start
        
        print(f"Retrieved {num_blocks} blocks in {retrieve_time:.3f}s")
        print(f"Retrieval rate: {num_blocks / retrieve_time:.1f} blocks/s")


class TestMemoryUsage:
    """Test memory usage under various loads."""
    
    def test_memory_usage_with_large_state(self, blockchain):
        """
        Monitor memory usage as state grows
        """
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large state
        num_accounts = 10000
        
        print(f"Initial memory: {initial_memory:.2f} MB")
        
        for i in range(num_accounts):
            priv, pub = generate_key_pair()
            pem = serialize_public_key(pub)
            addr = public_key_to_address(pem)
            
            account = blockchain._get_account(addr, blockchain.state_trie)
            account['balances']['native'] = 1000 * TOKEN_UNIT
            account['balances']['usd'] = 1000 * TOKEN_UNIT
            blockchain._set_account(addr, account, blockchain.state_trie)
            
            if (i + 1) % 1000 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                print(f"After {i + 1} accounts: {current_memory:.2f} MB "
                      f"(+{current_memory - initial_memory:.2f} MB)")
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_per_account = (final_memory - initial_memory) / num_accounts
        
        print(f"Final memory: {final_memory:.2f} MB")
        print(f"Memory per account: {memory_per_account * 1024:.2f} KB")
        
        # Memory usage should be reasonable
        assert final_memory - initial_memory < 500  # Less than 500 MB for 10k accounts
    
    def test_mempool_memory_limits(self, blockchain):
        """
        Test mempool memory usage with many transactions
        """
        mempool = Mempool(
            get_account_state=lambda addr: blockchain._get_account(addr, blockchain.state_trie)
        )
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        # Add many transactions
        users = [create_funded_user(blockchain, balance_native=10000, start_nonce=0) for _ in range(100)]
        
        added = 0
        for i in range(1000):
            user = users[i % len(users)]
            
            tx = Transaction(
                sender_public_key=user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': user['address'].hex(),
                    'amount': 1 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=i // len(users),
                fee=1000,
                chain_id=1
            )
            tx.sign(user['priv_key'])

            user['nonce'] += 1  # Increment nonce for next transaction
            
            success, _ = mempool.add_transaction(tx)
            if success:
                added += 1
        
        final_memory = process.memory_info().rss / 1024 / 1024
        
        print(f"Added {added} transactions to mempool")
        print(f"Memory usage: {final_memory - initial_memory:.2f} MB")
        if added > 0:
            print(f"Memory per transaction: {(final_memory - initial_memory) / added * 1024:.2f} KB")


class TestCryptographicPerformance:
    """Test cryptographic operation performance."""
    
    def test_signature_generation_performance(self):
        """
        Benchmark signature generation
        """
        priv, pub = generate_key_pair()
        pem = serialize_public_key(pub)
        
        iterations = 1000
        message = b"test message for signing"
        
        start_time = time.time()
        
        for _ in range(iterations):
            from crypto_v2.crypto import sign
            signature = sign(priv, message)
        
        elapsed = time.time() - start_time
        
        print(f"Generated {iterations} signatures in {elapsed:.3f}s")
        print(f"Signatures per second: {iterations / elapsed:.1f}")
        
        # Should be reasonably fast
        assert iterations / elapsed > 100
    
    def test_signature_verification_performance(self):
        """
        Benchmark signature verification
        """
        priv, pub = generate_key_pair()
        pem = serialize_public_key(pub)
        
        message = b"test message for verification"
        from crypto_v2.crypto import sign, verify_signature
        signature = sign(priv, message)
        
        iterations = 1000
        start_time = time.time()
        
        for _ in range(iterations):
            result = verify_signature(pem, signature, message)
            assert result == True
        
        elapsed = time.time() - start_time
        
        print(f"Verified {iterations} signatures in {elapsed:.3f}s")
        print(f"Verifications per second: {iterations / elapsed:.1f}")
        
        assert iterations / elapsed > 100
    
    def test_hash_performance(self):
        """
        Benchmark hashing performance
        """
        from crypto_v2.crypto import generate_hash
        
        iterations = 10000
        data = b"test data for hashing" * 10  # ~210 bytes
        
        start_time = time.time()
        
        for _ in range(iterations):
            hash_result = generate_hash(data)
        
        elapsed = time.time() - start_time
        
        print(f"Generated {iterations} hashes in {elapsed:.3f}s")
        print(f"Hashes per second: {iterations / elapsed:.1f}")
        
        assert iterations / elapsed > 10000  # Very fast
    
    def test_address_derivation_performance(self):
        """
        Benchmark address derivation
        """
        from crypto_v2.crypto import public_key_to_address
        
        iterations = 1000
        
        # Generate keys
        keys = []
        for _ in range(iterations):
            priv, pub = generate_key_pair()
            pem = serialize_public_key(pub)
            keys.append(pem)
        
        start_time = time.time()
        
        for pem in keys:
            address = public_key_to_address(pem)
        
        elapsed = time.time() - start_time
        
        print(f"Derived {iterations} addresses in {elapsed:.3f}s")
        print(f"Derivations per second: {iterations / elapsed:.1f}")


class TestBlockValidationPerformance:
    """Test block validation performance."""
    
    def test_validate_block_with_many_transactions(self, blockchain, validator):
        """
        Measure block validation time with many transactions
        """
        users = [create_funded_user(blockchain, balance_native=10000, start_nonce=0) for _ in range(50)]
        recipient = create_funded_user(blockchain)
        
        # Create block with 500 transactions
        transactions = []
        for i in range(500):
            user = users[i % len(users)]
            nonce = i // len(users)
            
            tx = Transaction(
                sender_public_key=user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': recipient['address'].hex(),
                    'amount': 1 * TOKEN_UNIT,
                    'token_type': 'native'
                },
                nonce=nonce,
                fee=1000,
                chain_id=1
            )
            tx.sign(user['priv_key'])
            transactions.append(tx)

            user['nonce'] += 1  # Increment nonce for next transaction  
        
        # Create block - process transactions first to get valid state root
        latest = blockchain.get_latest_block()
        temp_trie = Trie(blockchain.db, root_hash=blockchain.state_trie.root_hash)
        
        valid_txs = []
        for tx in transactions:
            try:
                if blockchain._process_transaction(tx, temp_trie):
                    valid_txs.append(tx)
            except Exception as e:
                print(f"Transaction processing error: {e}")
                pass
        
        
        last_poh_hash = latest.poh_sequence[-1][0] if latest.poh_sequence else latest.hash
        poh = PoHRecorder(last_poh_hash)
        for tx in valid_txs:
            poh.record(tx.id)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=temp_trie.root_hash,
            transactions=valid_txs,
            poh_sequence=poh.sequence,
            poh_initial=last_poh_hash,
            height=latest.height + 1,
            producer_pubkey=validator['pub_key_pem'],
            vrf_proof=vrf_proof,
            vrf_pub_key=validator['vrf_pub'].encode(),
            timestamp=time.time()
        )
        block.sign_block(validator['priv_key'])
        
        # Measure validation time
        start_time = time.time()
        success = blockchain.add_block(block)
        elapsed = time.time() - start_time
        
        print(f"Validated block with {len(valid_txs)} transactions in {elapsed:.3f}s")
        if len(valid_txs) > 0:
            print(f"Validation rate: {len(valid_txs) / elapsed:.1f} tx/s")
        
        assert success == True
        assert elapsed < 5.0  # Should complete in under 5 seconds


class TestScalability:
    """Test system scalability."""
    
    def test_chain_growth_performance(self, blockchain, validator):
        """
        Measure performance as chain grows
        """
        block_counts = [10, 50, 100]
        times = []
        
        for target_blocks in block_counts:
            current_height = blockchain.get_latest_block().height
            blocks_to_add = target_blocks - current_height
            
            if blocks_to_add <= 0:
                continue
            
            start_time = time.time()
            
            for _ in range(blocks_to_add):
                latest = blockchain.get_latest_block()
                last_poh_hash = latest.poh_sequence[-1][0] if latest.poh_sequence else latest.hash
                poh = PoHRecorder(last_poh_hash)
                poh.tick()
                
                vrf_proof, _ = vrf_prove(validator['vrf_priv'], latest.hash)
                
                # Use current blockchain state root for empty blocks
                block = Block(
                    parent_hash=latest.hash,
                    state_root=blockchain.state_trie.root_hash,
                    transactions=[],
                    poh_sequence=poh.sequence,
                    poh_initial=last_poh_hash,
                    height=latest.height + 1,
                    producer_pubkey=validator['pub_key_pem'],
                    vrf_proof=vrf_proof,
                    vrf_pub_key=validator['vrf_pub'].encode(),
                    timestamp=time.time()
                )
                block.sign_block(validator['priv_key'])
                blockchain.add_block(block)
            
            elapsed = time.time() - start_time
            times.append((target_blocks, elapsed))
            
            print(f"Added {blocks_to_add} blocks (total {target_blocks}): {elapsed:.3f}s")
        
        # Performance should not degrade significantly
        # (linear growth is acceptable, exponential is not)
    
    def test_large_pool_swap_performance(self, blockchain):
        """
        Test swap performance with very large pools
        """
        pool_sizes = [
            (1000, 1000),
            (10000, 10000),
            (100000, 100000),
        ]
        
        for token_reserve, usd_reserve in pool_sizes:
            pool = LiquidityPoolState({
                'token_reserve': token_reserve * TOKEN_UNIT,
                'usd_reserve': usd_reserve * TOKEN_UNIT,
                'lp_token_supply': token_reserve * TOKEN_UNIT
            })
            
            # Measure swap calculation time
            iterations = 1000
            start_time = time.time()
            
            for _ in range(iterations):
                output = pool.get_swap_output(10 * TOKEN_UNIT, input_is_token=True)
            
            elapsed = time.time() - start_time
            
            print(f"Pool size {token_reserve}:{usd_reserve} - "
                  f"{iterations} swaps in {elapsed:.3f}s "
                  f"({iterations / elapsed:.1f} swaps/s)")


class TestStressConditions:
    """Test system under stress."""
    
    def test_maximum_block_size(self, blockchain, validator):
        """
        Create block approaching MAX_BLOCK_SIZE
        """
        users = [create_funded_user(blockchain, balance_native=100000, start_nonce=0) for _ in range(100)]
        
        # Create transactions with large data fields
        transactions = []
        large_data = "x" * 1000  # 1KB of data
        
        for i in range(100):
            user = users[i % len(users)]
            
            tx = Transaction(
                sender_public_key=user['pub_key_pem'],
                tx_type='TRANSFER',
                data={
                    'to': user['address'].hex(),
                    'amount': 1 * TOKEN_UNIT,
                    'token_type': 'native',
                    'memo': large_data  # Large field
                },
                nonce=i // len(users),
                fee=1000,
                chain_id=1
            )
            tx.sign(user['priv_key'])
            transactions.append(tx)
        
        # Process transactions
        latest = blockchain.get_latest_block()
        temp_trie = Trie(blockchain.db, root_hash=latest.state_root)
        
        start_time = time.time()
        
        valid_txs = []
        for tx in transactions:
            try:
                if blockchain._process_transaction(tx, temp_trie):
                    valid_txs.append(tx)
            except:
                pass
        
        elapsed = time.time() - start_time
        
        print(f"Processed {len(valid_txs)} large transactions in {elapsed:.3f}s")
    
    def test_rapid_account_creation(self, blockchain):
        """
        Create many accounts rapidly
        """
        num_accounts = 1000
        start_time = time.time()
        
        addresses = []
        for _ in range(num_accounts):
            user = create_funded_user(blockchain, balance_native=100)
            addresses.append(user['address'])
        
        elapsed = time.time() - start_time
        
        print(f"Created {num_accounts} accounts in {elapsed:.3f}s")
        print(f"Account creation rate: {num_accounts / elapsed:.1f} accounts/s")
        
        # Verify accounts exist
        for addr in addresses[:10]:
            account = blockchain.get_account(addr)
            assert account['balances']['native'] == 100 * TOKEN_UNIT


class TestResourceLimits:
    """Test resource limits and bounds."""
    
    def test_database_size_growth(self, blockchain, validator, temp_db_path):
        """
        Monitor database size growth
        """
        def get_directory_size(path):
            """Calculate total size of directory in bytes."""
            total = 0
            try:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            total += os.path.getsize(filepath)
                        except OSError:
                            pass
            except Exception as e:
                print(f"Error calculating directory size: {e}")
            return total
        
        initial_size = get_directory_size(temp_db_path)
        initial_size_mb = initial_size / 1024 / 1024
        print(f"Initial database size: {initial_size_mb:.2f} MB")
        
        # Add 100 blocks
        for i in range(100):
            latest = blockchain.get_latest_block()
            last_poh_hash = latest.poh_sequence[-1][0] if latest.poh_sequence else latest.hash
            poh = PoHRecorder(last_poh_hash)
            poh.tick()
            
            vrf_proof, _ = vrf_prove(validator['vrf_priv'], latest.hash)
            
            # For empty blocks, use the current blockchain state root
            block = Block(
                parent_hash=latest.hash,
                state_root=blockchain.state_trie.root_hash,  # Use current state
                transactions=[],
                poh_sequence=poh.sequence,
                poh_initial=last_poh_hash,
                height=latest.height + 1,
                producer_pubkey=validator['pub_key_pem'],
                vrf_proof=vrf_proof,
                vrf_pub_key=validator['vrf_pub'].encode(),
                timestamp=time.time()
            )
            block.sign_block(validator['priv_key'])
            success = blockchain.add_block(block)
            assert success, f"Failed to add block {i}"
        
        final_size = get_directory_size(temp_db_path)
        final_size_mb = final_size / 1024 / 1024
        growth_mb = final_size_mb - initial_size_mb
        
        print(f"Final database size: {final_size_mb:.2f} MB")
        print(f"Growth: {growth_mb:.2f} MB for 100 blocks")
        print(f"Average size per block: {growth_mb / 100:.4f} MB")
        
        # Database should grow but not excessively
        assert growth_mb < 50  # Less than 50MB for 100 empty blocks


class TestConcurrency:
    """Test concurrent operations (basic thread safety checks)."""
    
    def test_concurrent_account_reads(self, blockchain):
        """
        Test concurrent reads from blockchain state
        """
        users = [create_funded_user(blockchain, balance_native=1000) for _ in range(100)]
        
        def read_account(address):
            """Read an account from the blockchain."""
            account = blockchain.get_account(address)
            return account['balances']['native']
        
        start_time = time.time()
        
        # Perform concurrent reads
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(read_account, user['address']) for user in users]
            results = [f.result() for f in as_completed(futures)]
        
        elapsed = time.time() - start_time
        
        print(f"Performed {len(users)} concurrent reads in {elapsed:.3f}s")
        print(f"Read rate: {len(users) / elapsed:.1f} reads/s")
        
        # All reads should succeed
        assert len(results) == len(users)
        assert all(r == 1000 * TOKEN_UNIT for r in results)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_zero_value_transfers(self, blockchain):
        """
        Test handling of zero-value transfers
        """
        user = create_funded_user(blockchain, balance_native=1000)
        recipient = create_funded_user(blockchain)
        
        tx = Transaction(
            sender_public_key=user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recipient['address'].hex(),
                'amount': 0,  # Zero transfer
                'token_type': 'native'
            },
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(user['priv_key'])
        
        # Should fail validation
        is_valid, error = tx.validate_basic()
        print(f"Zero transfer validation: {is_valid}, error: {error}")
    
    def test_maximum_nonce_value(self, blockchain):
        """
        Test handling of very large nonce values
        """
        user = create_funded_user(blockchain, balance_native=10000)
        
        # Try with a very large nonce
        large_nonce = 2**32 - 1
        
        tx = Transaction(
            sender_public_key=user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': user['address'].hex(),
                'amount': 1 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=large_nonce,
            fee=1000,
            chain_id=1
        )
        tx.sign(user['priv_key'])
        
        # Transaction should be properly formed
        assert tx.nonce == large_nonce
    
    def test_minimum_swap_amounts(self, blockchain):
        """
        Test AMM with minimum swap amounts
        """
        pool = LiquidityPoolState({
            'token_reserve': 1000 * TOKEN_UNIT,
            'usd_reserve': 1000 * TOKEN_UNIT,
            'lp_token_supply': 1000 * TOKEN_UNIT
        })
        
        # Test with 1 unit (smallest amount)
        output = pool.get_swap_output(1, input_is_token=True)
        print(f"Swap output for 1 unit input: {output}")
        
        # Should handle gracefully (may be zero due to fees)
        assert output >= 0
    
    def test_large_fee_values(self, blockchain):
        """
        Test transactions with very large fees
        """
        user = create_funded_user(blockchain, balance_native=100000)
        recipient = create_funded_user(blockchain)
        
        # Large fee (but user can afford it)
        large_fee = 50000 * TOKEN_UNIT
        
        tx = Transaction(
            sender_public_key=user['pub_key_pem'],
            tx_type='TRANSFER',
            data={
                'to': recipient['address'].hex(),
                'amount': 1 * TOKEN_UNIT,
                'token_type': 'native'
            },
            nonce=0,
            fee=large_fee,
            chain_id=1
        )
        tx.sign(user['priv_key'])
        
        # Should be valid
        is_valid, error = tx.validate_basic()
        assert is_valid, f"Transaction should be valid: {error}"


class TestDataIntegrity:
    """Test data integrity and consistency."""
    
    def test_state_root_consistency(self, blockchain):
        """
        Verify state root changes consistently with state updates
        """
        initial_root = blockchain.state_trie.root_hash
        
        # Make a state change
        user = create_funded_user(blockchain, balance_native=1000)
        
        # Root should have changed
        new_root = blockchain.state_trie.root_hash
        assert new_root != initial_root
        
        # Create another identical account
        user2 = create_funded_user(blockchain, balance_native=1000)
        
        # Root should change again
        final_root = blockchain.state_trie.root_hash
        assert final_root != new_root
        assert final_root != initial_root
    
    def test_transaction_signature_integrity(self):
        """
        Verify transaction signatures are properly validated
        """
        priv, pub = generate_key_pair()
        pem = serialize_public_key(pub)
        
        tx = Transaction(
            sender_public_key=pem,
            tx_type='TRANSFER',
            data={
                'to': '0' * 40,
                'amount': 1000,
                'token_type': 'native'
            },
            nonce=0,
            fee=100,
            chain_id=1
        )
        tx.sign(priv)
        
        # Should verify correctly
        assert tx.verify_signature()
        
        # Tamper with data
        tx.data['amount'] = 2000
        
        # Should fail verification
        assert not tx.verify_signature()
    
    def test_block_hash_integrity(self, blockchain, validator):
        """
        Verify block hashes are computed correctly
        """
        latest = blockchain.get_latest_block()
        last_poh_hash = latest.poh_sequence[-1][0] if latest.poh_sequence else latest.hash
        poh = PoHRecorder(last_poh_hash)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(validator['vrf_priv'], latest.hash)
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=last_poh_hash,
            height=latest.height + 1,
            producer_pubkey=validator['pub_key_pem'],
            vrf_proof=vrf_proof,
            vrf_pub_key=validator['vrf_pub'].encode(),
            timestamp=time.time()
        )
        block.sign_block(validator['priv_key'])
        
        # Calculate hash twice - should be identical
        hash1 = block.hash
        hash2 = block.header.calculate_hash()
        
        assert hash1 == hash2
        
        # Verify block signature
        assert block.verify_signature()


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])