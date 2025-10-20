"""
Comprehensive, end-to-end integration test suite for the improved blockchain.
Tests all components including state trie, consensus, PoH, VRF, and state transitions.
"""
import unittest
import shutil
import tempfile
import time
import msgpack
from crypto_v2.chain import Blockchain
from crypto_v2.core import Block, Transaction
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address,
    generate_vrf_keypair,
    vrf_prove
)
from crypto_v2.trie import Trie
from crypto_v2.poh import PoHRecorder
from crypto_v2.consensus import LeaderScheduler
from crypto_v2.mempool import Mempool


class TestFullSystem(unittest.TestCase):
    def setUp(self):
        """Set up test environment with multiple validators."""
        self.test_dir = tempfile.mkdtemp()
        self.bc = Blockchain(self.test_dir, chain_id=1)

        # Create wallets for Alice, Bob, and Charlie
        self.wallets = {}
        for name in ['alice', 'bob', 'charlie']:
            priv_key, pub_key = generate_key_pair()
            vrf_priv, vrf_pub = generate_vrf_keypair()
            self.wallets[name] = {
                'priv_key': priv_key,
                'pub_key': pub_key,
                'pem': serialize_public_key(pub_key),
                'address': public_key_to_address(serialize_public_key(pub_key)),
                'vrf_priv': vrf_priv,
                'vrf_pub': vrf_pub,
            }

        # Set up genesis state with pre-funded and pre-staked accounts
        genesis_trie = self.bc.state_trie
        
        initial_validators = {}
        for name, wallet in self.wallets.items():
            # Pre-fund all accounts
            account = {
                'balance': 10000,
                'nonce': 0,
                'vrf_pub_key': wallet['vrf_pub'].encode().hex()
            }
            self.bc._set_account(wallet['address'], account, genesis_trie)
            
            # Pre-stake Alice and Bob as validators
            if name in ['alice', 'bob']:
                initial_validators[wallet['address'].hex()] = 1000
        
        self.bc._set_validator_set(initial_validators, genesis_trie)
        
        # Update genesis block
        genesis = self.bc.get_latest_block()
        genesis.state_root = genesis_trie.root_hash
        self.bc._store_block(genesis)
        self.bc.db.put(b'head', genesis.hash)
        self.bc.head_hash = genesis.hash
        self.bc.state_trie = genesis_trie

    def tearDown(self):
        """Clean up test environment."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def _determine_leader(self) -> str:
        """Determine the next block leader using VRF-based selection."""
        latest_block = self.bc.get_latest_block()
        validators = self.bc._get_validator_set(self.bc.state_trie)
        
        scheduler = LeaderScheduler(
            validators,
            lambda addr: self.bc._get_account(addr, self.bc.state_trie)
        )
        leader_address_hex = scheduler.get_leader(latest_block.hash)
        
        for name, wallet in self.wallets.items():
            if wallet['address'].hex() == leader_address_hex:
                return name
        return None

    def _create_and_add_block(self, transactions: list[Transaction]) -> Block:
        """Helper to create and add a valid block to the chain."""
        leader_name = self._determine_leader()
        self.assertIsNotNone(leader_name, "Could not determine a leader")
        
        latest_block = self.bc.get_latest_block()
        producer = self.wallets[leader_name]

        # Process transactions to calculate state root
        temp_trie = Trie(self.bc.db, root_hash=latest_block.state_root)
        for tx in transactions:
            success = self.bc._process_transaction(tx, temp_trie)
            if not success:
                self.fail(f"Transaction processing failed: {tx.id.hex()[:16]}")

        # Create PoH sequence
        if latest_block.poh_sequence:
            initial_hash = latest_block.poh_sequence[-1][0]
        else:
            initial_hash = latest_block.hash
            
        poh = PoHRecorder(initial_hash)
        for tx in transactions:
            poh.record(tx.id)
        poh.tick()
        
        # Generate VRF proof
        vrf_proof, _ = vrf_prove(producer['vrf_priv'], latest_block.hash)

        # Create block
        new_block = Block(
            parent_hash=latest_block.hash,
            state_root=temp_trie.root_hash,
            transactions=transactions,
            poh_sequence=poh.sequence,
            height=latest_block.height + 1,
            producer=producer['pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        
        # Sign block
        new_block.sign_block(producer['priv_key'])
        
        # Add to chain
        success = self.bc.add_block(new_block)
        self.assertTrue(success, f"Failed to add block {new_block.height}")
        
        # Update state trie
        self.bc.state_trie = Trie(self.bc.db, root_hash=new_block.state_root)
        
        return new_block

    def test_genesis_initialization(self):
        """Test that genesis block is properly initialized."""
        genesis = self.bc.get_latest_block()
        
        self.assertEqual(genesis.height, 0)
        self.assertEqual(genesis.parent_hash, b'\x00' * 32)
        self.assertIsNotNone(genesis.state_root)
        
        # Verify validator set
        validators = self.bc._get_validator_set(self.bc.state_trie)
        self.assertEqual(len(validators), 2)
        self.assertIn(self.wallets['alice']['address'].hex(), validators)
        self.assertIn(self.wallets['bob']['address'].hex(), validators)
        
        # Verify account balances
        for name in ['alice', 'bob', 'charlie']:
            account = self.bc._get_account(
                self.wallets[name]['address'],
                self.bc.state_trie
            )
            self.assertEqual(account['balance'], 10000)
            self.assertEqual(account['nonce'], 0)

    def test_leader_selection_deterministic(self):
        """Test that leader selection is deterministic."""
        leader1 = self._determine_leader()
        leader2 = self._determine_leader()
        
        self.assertEqual(leader1, leader2)
        self.assertIn(leader1, ['alice', 'bob'])
        print(f"\nDeterministic leader: {leader1}")

    def test_basic_transfer(self):
        """Test basic token transfer."""
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        # Create transfer transaction
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': charlie['address'], 'amount': 500},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        # Add block with transaction
        block = self._create_and_add_block([tx])
        
        # Verify balances
        alice_account = self.bc._get_account(alice['address'], self.bc.state_trie)
        charlie_account = self.bc._get_account(charlie['address'], self.bc.state_trie)
        
        self.assertEqual(alice_account['balance'], 10000 - 500 - 10)
        self.assertEqual(alice_account['nonce'], 1)
        self.assertEqual(charlie_account['balance'], 10000 + 500)

    def test_multiple_transactions_in_block(self):
        """Test block with multiple transactions."""
        alice = self.wallets['alice']
        bob = self.wallets['bob']
        charlie = self.wallets['charlie']
        
        # Create multiple transactions
        txs = []
        
        # Alice sends to Charlie
        tx1 = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': charlie['address'], 'amount': 100},
            nonce=0,
            fee=5,
            chain_id=1
        )
        tx1.sign(alice['priv_key'])
        txs.append(tx1)
        
        # Bob sends to Charlie
        tx2 = Transaction(
            sender_public_key=bob['pem'],
            tx_type='TRANSFER',
            data={'recipient': charlie['address'], 'amount': 200},
            nonce=0,
            fee=5,
            chain_id=1
        )
        tx2.sign(bob['priv_key'])
        txs.append(tx2)
        
        # Add block
        block = self._create_and_add_block(txs)
        
        # Verify all balances
        alice_account = self.bc._get_account(alice['address'], self.bc.state_trie)
        bob_account = self.bc._get_account(bob['address'], self.bc.state_trie)
        charlie_account = self.bc._get_account(charlie['address'], self.bc.state_trie)
        
        self.assertEqual(alice_account['balance'], 10000 - 100 - 5)
        self.assertEqual(bob_account['balance'], 10000 - 200 - 5)
        self.assertEqual(charlie_account['balance'], 10000 + 100 + 200)

    def test_staking_mechanism(self):
        """Test staking and validator set updates."""
        charlie = self.wallets['charlie']
        
        # Charlie stakes to become a validator
        stake_tx = Transaction(
            sender_public_key=charlie['pem'],
            tx_type='STAKE',
            data={
                'amount': 500,
                'vrf_pub_key': charlie['vrf_pub'].encode().hex()
            },
            nonce=0,
            fee=10,
            chain_id=1
        )
        stake_tx.sign(charlie['priv_key'])
        
        block = self._create_and_add_block([stake_tx])
        
        # Verify Charlie is now a validator
        validators = self.bc._get_validator_set(self.bc.state_trie)
        self.assertIn(charlie['address'].hex(), validators)
        self.assertEqual(validators[charlie['address'].hex()], 500)
        
        # Verify balance deducted
        charlie_account = self.bc._get_account(charlie['address'], self.bc.state_trie)
        self.assertEqual(charlie_account['balance'], 10000 - 500 - 10)

    def test_unstaking_mechanism(self):
        """Test unstaking and validator set updates."""
        alice = self.wallets['alice']
        
        # Alice unstakes part of her stake
        unstake_tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='UNSTAKE',
            data={'amount': 300},
            nonce=0,
            fee=10,
            chain_id=1
        )
        unstake_tx.sign(alice['priv_key'])
        
        block = self._create_and_add_block([unstake_tx])
        
        # Verify stake reduced
        validators = self.bc._get_validator_set(self.bc.state_trie)
        self.assertEqual(validators[alice['address'].hex()], 700)  # 1000 - 300
        
        # Verify balance increased
        alice_account = self.bc._get_account(alice['address'], self.bc.state_trie)
        self.assertEqual(alice_account['balance'], 10000 + 300 - 10)

    def test_complete_unstake(self):
        """Test complete unstaking removes validator."""
        alice = self.wallets['alice']
        
        # Alice unstakes everything
        unstake_tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='UNSTAKE',
            data={'amount': 1000},
            nonce=0,
            fee=10,
            chain_id=1
        )
        unstake_tx.sign(alice['priv_key'])
        
        block = self._create_and_add_block([unstake_tx])
        
        # Verify Alice removed from validators
        validators = self.bc._get_validator_set(self.bc.state_trie)
        self.assertNotIn(alice['address'].hex(), validators)
        
        # Verify balance
        alice_account = self.bc._get_account(alice['address'], self.bc.state_trie)
        self.assertEqual(alice_account['balance'], 10000 + 1000 - 10)

    def test_chain_progression(self):
        """Test multiple blocks in sequence."""
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        initial_height = self.bc.get_latest_block().height
        
        # Create 5 blocks
        for i in range(5):
            tx = Transaction(
                sender_public_key=alice['pem'],
                tx_type='TRANSFER',
                data={'recipient': charlie['address'], 'amount': 10},
                nonce=i,
                fee=1,
                chain_id=1
            )
            tx.sign(alice['priv_key'])
            
            block = self._create_and_add_block([tx])
            self.assertEqual(block.height, initial_height + i + 1)
        
        # Verify final height
        final_height = self.bc.get_latest_block().height
        self.assertEqual(final_height, initial_height + 5)
        
        # Verify final balances
        alice_account = self.bc._get_account(alice['address'], self.bc.state_trie)
        charlie_account = self.bc._get_account(charlie['address'], self.bc.state_trie)
        
        self.assertEqual(alice_account['balance'], 10000 - (10 + 1) * 5)
        self.assertEqual(charlie_account['balance'], 10000 + 10 * 5)

    def test_nonce_enforcement(self):
        """Test that incorrect nonces are rejected."""
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        # Try to use wrong nonce
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': charlie['address'], 'amount': 10},
            nonce=5,  # Wrong nonce
            fee=1,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        # Should fail to add block
        with self.assertRaises(AssertionError):
            self._create_and_add_block([tx])

    def test_persistence_and_reload(self):
        """Test blockchain persistence across restarts."""
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        # Create some transactions
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='STAKE',
            data={
                'amount': 500,
                'vrf_pub_key': alice['vrf_pub'].encode().hex()
            },
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        self._create_and_add_block([tx])
        
        latest_block_hash = self.bc.get_latest_block().hash
        latest_height = self.bc.get_latest_block().height
        
        # Close and reopen blockchain
        db_path = self.test_dir
        self.bc.db.close()
        
        reloaded_bc = Blockchain(db_path, chain_id=1)
        
        # Verify state is intact
        self.assertEqual(reloaded_bc.get_latest_block().hash, latest_block_hash)
        self.assertEqual(reloaded_bc.get_latest_block().height, latest_height)
        
        # Verify validator set
        reloaded_validators = reloaded_bc._get_validator_set(reloaded_bc.state_trie)
        self.assertIn(alice['address'].hex(), reloaded_validators)
        self.assertEqual(reloaded_validators[alice['address'].hex()], 1500)  # 1000 + 500
        
        reloaded_bc.db.close()

    def test_mempool_integration(self):
        """Test mempool with blockchain state."""
        mempool = Mempool(
            get_account_state=lambda addr: self.bc._get_account(addr, self.bc.state_trie)
        )
        
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        # Add valid transaction
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': charlie['address'], 'amount': 100},
            nonce=0,
            fee=10,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        success, error = mempool.add_transaction(tx)
        self.assertTrue(success, error)
        
        # Get pending transactions
        pending = mempool.get_pending_transactions(max_txs=10)
        self.assertEqual(len(pending), 1)
        
        # Add block with transaction
        self._create_and_add_block([tx])
        
        # Remove from mempool
        mempool.remove_transactions([tx])
        self.assertEqual(len(mempool), 0)

    def test_chain_validation(self):
        """Test full chain validation."""
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        # Build a chain
        for i in range(3):
            tx = Transaction(
                sender_public_key=alice['pem'],
                tx_type='TRANSFER',
                data={'recipient': charlie['address'], 'amount': 10},
                nonce=i,
                fee=1,
                chain_id=1
            )
            tx.sign(alice['priv_key'])
            self._create_and_add_block([tx])
        
        # Validate entire chain
        self.assertTrue(self.bc.validate_chain())

    def test_block_signature_required(self):
        """Test that blocks without signatures are rejected."""
        alice = self.wallets['alice']
        charlie = self.wallets['charlie']
        
        tx = Transaction(
            sender_public_key=alice['pem'],
            tx_type='TRANSFER',
            data={'recipient': charlie['address'], 'amount': 10},
            nonce=0,
            fee=1,
            chain_id=1
        )
        tx.sign(alice['priv_key'])
        
        latest_block = self.bc.get_latest_block()
        leader_name = self._determine_leader()
        producer = self.wallets[leader_name]
        
        # Create block without signature
        temp_trie = Trie(self.bc.db, root_hash=latest_block.state_root)
        self.bc._process_transaction(tx, temp_trie)
        
        poh = PoHRecorder(latest_block.poh_sequence[-1][0])
        poh.record(tx.id)
        poh.tick()
        
        vrf_proof, _ = vrf_prove(producer['vrf_priv'], latest_block.hash)
        
        block = Block(
            parent_hash=latest_block.hash,
            state_root=temp_trie.root_hash,
            transactions=[tx],
            poh_sequence=poh.sequence,
            height=latest_block.height + 1,
            producer=producer['pem'],
            vrf_proof=vrf_proof,
            timestamp=time.time(),
            signature=None  # No signature!
        )
        
        # Should be rejected
        self.assertFalse(self.bc.add_block(block))


if __name__ == '__main__':
    unittest.main()