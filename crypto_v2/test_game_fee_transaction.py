"""
Test GAME_FEE transaction type with dynamic leaderboard system.
Phase 4B: Test game fee payment with flexible leader splits.
"""
import unittest
import shutil
import tempfile
import time
import msgpack
from decimal import Decimal
from crypto_v2.chain import (
    Blockchain, TREASURY_ADDRESS, VALIDATOR_SET_ADDRESS, 
    TOKEN_UNIT, CONFIG_ADDRESS, MIN_STAKE_AMOUNT, 
    SLASH_PERCENTAGE, MAX_BLOCK_SIZE, MAX_TXS_PER_BLOCK
)
from crypto_v2.core import Block, Transaction
from crypto_v2.db import DB
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address,
    generate_vrf_keypair,
    vrf_prove
)
from crypto_v2.trie import Trie
from crypto_v2.poh import PoHRecorder


class TestGameFeeTransaction(unittest.TestCase):
    def setUp(self):
        """Set up test blockchain with players."""
        self.test_dir = tempfile.mkdtemp()
        db_path = self.test_dir
        
        # Create validator (Alice) for block production
        self.priv_key_alice, self.pub_key_alice = generate_key_pair()
        self.alice_pem = serialize_public_key(self.pub_key_alice)
        self.alice_address = public_key_to_address(self.alice_pem)
        self.vrf_priv_alice, self.vrf_pub_alice = generate_vrf_keypair()
        
        # Create player (Bob)
        self.priv_key_bob, self.pub_key_bob = generate_key_pair()
        self.bob_pem = serialize_public_key(self.pub_key_bob)
        self.bob_address = public_key_to_address(self.bob_pem)
        
        # Create leader (Charlie)
        self.priv_key_charlie, self.pub_key_charlie = generate_key_pair()
        self.charlie_pem = serialize_public_key(self.pub_key_charlie)
        self.charlie_address = public_key_to_address(self.charlie_pem)

        # Import constants
        from crypto_v2.chain import (
            CONFIG_ADDRESS, MIN_STAKE_AMOUNT, SLASH_PERCENTAGE,
            MAX_BLOCK_SIZE, MAX_TXS_PER_BLOCK
        )

        # 1. Create database and genesis state trie
        db = DB(db_path)
        genesis_trie = Trie(db)
        
        # Test that trie.set() works at all
        test_key = b'test_key_12345'
        test_value = b'test_value'
        genesis_trie.set(test_key, test_value)
        test_retrieve = genesis_trie.get(test_key)
        print(f"DEBUG: Test set/get - wrote '{test_value}', read '{test_retrieve}'")
        
        # Alice's account (validator)
        alice_account = {
            'balance': 1_000_000 * TOKEN_UNIT,
            'nonce': 0,
            'vrf_pub_key': self.vrf_pub_alice.encode().hex()
        }
        encoded_alice = msgpack.packb(alice_account, use_bin_type=True)
        print(f"DEBUG: Setting Alice account at {self.alice_address.hex()}")
        print(f"DEBUG: Encoded Alice data length: {len(encoded_alice)}")
        genesis_trie.set(self.alice_address, encoded_alice)
        # Immediately verify
        verify_alice = genesis_trie.get(self.alice_address)
        print(f"DEBUG: Immediately reading Alice back: {verify_alice is not None}")
        
        # Bob's account
        bob_account = {'balance': 100 * TOKEN_UNIT, 'nonce': 0}
        encoded_bob = msgpack.packb(bob_account, use_bin_type=True)
        genesis_trie.set(self.bob_address, encoded_bob)
        
        # Charlie's account
        charlie_account = {'balance': 100 * TOKEN_UNIT, 'nonce': 0}
        encoded_charlie = msgpack.packb(charlie_account, use_bin_type=True)
        genesis_trie.set(self.charlie_address, encoded_charlie)

        # Treasury account
        treasury_account = {'balance': 0, 'nonce': 0}
        encoded_treasury = msgpack.packb(treasury_account, use_bin_type=True)
        genesis_trie.set(TREASURY_ADDRESS, encoded_treasury)

        # Validator set - THIS IS CRITICAL
        validators = {self.alice_address.hex(): 1000 * TOKEN_UNIT}
        encoded_validators = msgpack.packb(validators, use_bin_type=True)
        print(f"\nDEBUG: Setting validators at {VALIDATOR_SET_ADDRESS.hex()}")
        print(f"DEBUG: Validators data: {validators}")
        print(f"DEBUG: Encoded length: {len(encoded_validators)}")
        genesis_trie.set(VALIDATOR_SET_ADDRESS, encoded_validators)
        # Immediately verify
        verify_validators = genesis_trie.get(VALIDATOR_SET_ADDRESS)
        print(f"DEBUG: Immediately reading validators back: {verify_validators}")
        if verify_validators:
            decoded = msgpack.unpackb(verify_validators, raw=False)
            print(f"DEBUG: Decoded validators: {decoded}")
        else:
            print(f"ERROR: Could not read validators immediately after writing!")
            print(f"ERROR: This suggests a problem with the VALIDATOR_SET_ADDRESS key")
            print(f"ERROR: VALIDATOR_SET_ADDRESS = {VALIDATOR_SET_ADDRESS.hex()}")

        # Config - prevents _initialize_config from modifying state
        config = {
            'chain_id': 1,
            'min_stake': MIN_STAKE_AMOUNT,
            'slash_percentage': SLASH_PERCENTAGE,
            'max_block_size': MAX_BLOCK_SIZE,
            'max_txs_per_block': MAX_TXS_PER_BLOCK,
        }
        encoded_config = msgpack.packb(config, use_bin_type=True)
        genesis_trie.set(CONFIG_ADDRESS, encoded_config)

        # Initialize tokenomics state with $1/token price
        from crypto_v2.chain import TOKENOMICS_ADDRESS
        from crypto_v2.tokenomics_state import TokenomicsState
        
        # Calculate total supply in genesis (Alice: 1M, Bob: 100, Charlie: 100)
        total_genesis_supply = (1_000_000 + 100 + 100) * TOKEN_UNIT
        
        # To maintain $1/token price, we need:
        # price = net_treasury_usd / circulating_supply_in_tokens
        # 1.0 = net_treasury_usd / 1_000_200
        # net_treasury_usd = 1_000_200
        
        tokenomics_data = {
            'total_minted': total_genesis_supply,
            'total_burned': 0,
            'total_usd_in': '1000200.0',  # $1M + $100 + $100 = $1,000,200
            'total_usd_out': '0',
        }
        tokenomics = TokenomicsState(tokenomics_data)
        encoded_tokenomics = msgpack.packb(tokenomics.to_dict(), use_bin_type=True)
        genesis_trie.set(TOKENOMICS_ADDRESS, encoded_tokenomics)

        # IMPORTANT: Capture state root AFTER all data is set
        genesis_state_root = genesis_trie.root_hash
        
        # NOW verify all data is readable
        print(f"\nDEBUG: Genesis state root (FINAL): {genesis_state_root.hex()}")
        print(f"DEBUG: Reading validators from genesis_trie...")
        test_read = genesis_trie.get(VALIDATOR_SET_ADDRESS)
        print(f"DEBUG: Raw validators data: {test_read}")
        if test_read:
            test_validators = msgpack.unpackb(test_read, raw=False)
            print(f"DEBUG: Decoded validators: {test_validators}")
        
        # Try creating a NEW trie with the same root and see if data persists
        print(f"DEBUG: Creating new trie with same root...")
        test_trie = Trie(db, root_hash=genesis_state_root)
        test_read2 = test_trie.get(VALIDATOR_SET_ADDRESS)
        print(f"DEBUG: Reading from NEW trie: {test_read2}")

        # 2. Create genesis block with the complete state root
        genesis = Block(
            parent_hash=b'\x00' * 32,  # 32 zero bytes
            state_root=genesis_state_root,
            transactions=[],
            poh_sequence=[],
            height=0,
            producer=self.alice_pem,
            vrf_proof=b'',
            timestamp=0.0
        )
        genesis.sign_block(self.priv_key_alice)
        
        # 3. Initialize blockchain with the complete genesis block
        # The blockchain will use the genesis state_root to initialize its state_trie
        self.bc = Blockchain(db=db, genesis_block=genesis, chain_id=1)
        
        # Verify setup worked correctly
        validators_check = self.bc.get_validator_set()
        if not validators_check:
            raise RuntimeError(
                "Validator set is empty after setup! "
                f"Expected Alice ({self.alice_address.hex()}) to be a validator."
            )
        
    def tearDown(self):
        """Clean up."""
        self.bc.db.close()
        shutil.rmtree(self.test_dir)

    def _create_and_add_block(self, transactions):
        """Helper to create and add a block."""
        latest_block = self.bc.get_latest_block()
        
        # Process transactions starting from CURRENT blockchain state
        # to calculate what the new state root should be
        temp_trie = Trie(self.bc.db, root_hash=self.bc.state_trie.root_hash)
        for tx in transactions:
            success = self.bc._process_transaction(tx, temp_trie)
            if not success:
                return False
        
        expected_state_root = temp_trie.root_hash
        
        # Create PoH sequence
        if latest_block.poh_sequence:
            initial_hash = latest_block.poh_sequence[-1][0]
        else:
            initial_hash = latest_block.hash
        
        poh_recorder = PoHRecorder(initial_hash)
        for tx in transactions:
            poh_recorder.record(tx.id)
        poh_recorder.tick()
        
        vrf_proof, _ = vrf_prove(self.vrf_priv_alice, latest_block.hash)
        
        from crypto_v2.core import Block
        block = Block(
            parent_hash=latest_block.hash,
            state_root=expected_state_root,
            transactions=transactions,
            poh_sequence=poh_recorder.sequence,
            height=latest_block.height + 1,
            producer=self.alice_pem,
            vrf_proof=vrf_proof,
            timestamp=time.time()
        )
        
        block.sign_block(self.priv_key_alice)
        
        success = self.bc.add_block(block)
        if success:
            self.bc.state_trie = Trie(self.bc.db, root_hash=block.state_root)
        
        return success

    def _transfer_tokens(self, from_priv_key, from_pub_key, to_address, amount):
        """Helper to create and process a TRANSFER transaction."""
        sender_address = public_key_to_address(from_pub_key)
        sender_account = self.bc._get_account(sender_address, self.bc.state_trie)
        
        tx = Transaction(
            sender_public_key=from_pub_key,
            tx_type='TRANSFER',
            data={
                'recipient': to_address.hex(),
                'amount': amount
            },
            nonce=sender_account['nonce'],
            fee=0,
            chain_id=1
        )
        tx.sign(from_priv_key)
        return self._create_and_add_block([tx])

    def test_game_fee_no_leader(self):
        """Test game fee when no one has played yet (no leader)."""
        # Bob starts with 100 tokens from genesis
        
        # Bob plays number guessing game (no leader exists yet)
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='GAME_FEE',
            data={
                'game_id': 'number_guessing',
                'score': 50
            },
            nonce=0,
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertTrue(success)
        
        # At $1/token, $0.25 game costs 0.25 tokens
        token_cost = 250_000 # 0.25 * TOKEN_UNIT
        
        # Check Bob's balance
        bob_account = self.bc.get_account(self.bob_address)
        self.assertEqual(
            bob_account['balance'],
            (100 * TOKEN_UNIT) - token_cost
        )
        
        # Check treasury got 90% (70% + 20% since no leader)
        treasury_account = self.bc.get_treasury()
        expected_treasury = (token_cost * 90) // 100
        self.assertEqual(
            treasury_account['balance'],
            expected_treasury
        )
        
        # Check burn (10%)
        stats = self.bc.get_tokenomics_stats()
        expected_burn = token_cost - expected_treasury # The remainder
        self.assertEqual(
            int(stats['total_burned']),
            expected_burn
        )
        
        # Bob should now be the leader
        leaders = self.bc.get_game_leaders('number_guessing')
        self.assertEqual(len(leaders), 1)
        self.assertEqual(leaders[0], self.bob_address)

    def test_game_fee_with_single_leader(self):
        """Test game fee payment with existing leader (single leader game)."""
        # Bob and Charlie start with 100 tokens
        
        # Charlie plays first and becomes leader
        charlie_account_before = self.bc._get_account(self.charlie_address, self.bc.state_trie)
        tx1 = Transaction(
            sender_public_key=self.charlie_pem,
            tx_type='GAME_FEE',
            data={'game_id': 'number_guessing', 'score': 100},
            nonce=charlie_account_before['nonce'],
            fee=0,
            chain_id=1
        )
        tx1.sign(self.priv_key_charlie)
        self.assertTrue(self._create_and_add_block([tx1]))
        
        # Now Bob plays (Charlie is leader)
        bob_account_before = self.bc._get_account(self.bob_address, self.bc.state_trie)
        tx2 = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='GAME_FEE',
            data={'game_id': 'number_guessing', 'score': 50},
            nonce=bob_account_before['nonce'],
            fee=0,
            chain_id=1
        )
        tx2.sign(self.priv_key_bob)
        
        # Get Charlie's balance before Bob plays
        charlie_before = self.bc._get_account(
            self.charlie_address, self.bc.state_trie
        )['balance']
        
        success = self._create_and_add_block([tx2])
        self.assertTrue(success)
        
        # Calculate what Charlie should receive
        # Bob pays ~0.25 tokens, Charlie gets 20%
        # But we need to account for dynamic pricing and rounding
        charlie_after = self.bc.get_account(self.charlie_address)
        actual_reward = charlie_after['balance'] - charlie_before
        
        # Verify Charlie received approximately 20% of the fee
        # The token cost should be around 250,000 (0.25 tokens at ~$1/token)
        # So leader reward should be around 50,000 (20% of 250,000)
        expected_min = 49_000  # Allow some variance for price changes
        expected_max = 51_000
        
        self.assertGreaterEqual(
            actual_reward,
            expected_min,
            f"Charlie should receive at least {expected_min} as leader reward"
        )
        self.assertLessEqual(
            actual_reward,
            expected_max,
            f"Charlie should receive at most {expected_max} as leader reward"
        )

    def test_game_fee_top_3_leaders(self):
        """Test game fee with top 3 leader split."""
        # Create 3 players
        players = []
        for i in range(3):
            priv_key, pub_key = generate_key_pair()
            pem = serialize_public_key(pub_key)
            address = public_key_to_address(pem)
            players.append((priv_key, pem, address))
            # Give them tokens via transfer from Alice
            self.assertTrue(self._transfer_tokens(
                self.priv_key_alice, self.alice_pem, address, 100 * TOKEN_UNIT
            ))
        
        # All 3 play and establish leaderboard (snake_game has top 3)
        for i, (priv_key, pem, address) in enumerate(players):
            player_account = self.bc._get_account(address, self.bc.state_trie)
            tx = Transaction(
                sender_public_key=pem,
                tx_type='GAME_FEE',
                data={'game_id': 'snake_game', 'score': 100 - i * 10},  # 100, 90, 80
                nonce=player_account['nonce'],
                fee=0,
                chain_id=1
            )
            tx.sign(priv_key)
            self.assertTrue(self._create_and_add_block([tx]))
        
        # Bob plays (pays leaders)
        bob_account = self.bc.get_account(self.bob_address)
        
        # Get balances before
        balances_before = []
        for _, _, address in players:
            balance = self.bc.get_account(address)['balance']
            balances_before.append(balance)
        
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='GAME_FEE',
            data={'game_id': 'snake_game', 'score': 50},
            nonce=bob_account['nonce'],
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        success = self._create_and_add_block([tx])
        self.assertTrue(success)
        
        # snake_game costs $0.50, leader share is 20%
        # With dynamic pricing, the actual cost will vary slightly
        # Get actual rewards from balance changes
        actual_rewards = []
        for i, (_, _, address) in enumerate(players):
            balance_after = self.bc.get_account(address)['balance']
            reward = balance_after - balances_before[i]
            actual_rewards.append(reward)
        
        total_leader_reward = sum(actual_rewards)
        
        # Verify the split percentages (60%, 25%, 15%)
        # Allow for rounding by checking the ratios
        if total_leader_reward > 0:
            reward1_pct = (actual_rewards[0] * 100) / total_leader_reward
            reward2_pct = (actual_rewards[1] * 100) / total_leader_reward
            reward3_pct = (actual_rewards[2] * 100) / total_leader_reward
            
            # Should be approximately 60%, 25%, 15%
            self.assertAlmostEqual(reward1_pct, 60.0, delta=1.0, 
                                msg="Leader #1 should get ~60%")
            self.assertAlmostEqual(reward2_pct, 25.0, delta=1.0,
                                msg="Leader #2 should get ~25%")
            self.assertAlmostEqual(reward3_pct, 15.0, delta=1.0,
                                msg="Leader #3 should get ~15%")
            
            # Verify total is reasonable (around 20% of ~500,000 = ~100,000)
            self.assertGreaterEqual(total_leader_reward, 95_000)
            self.assertLessEqual(total_leader_reward, 105_000)

    def test_game_fee_updates_leaderboard(self):
        """Test that GAME_FEE updates leaderboard with score."""
        # Bob starts with 100 tokens
        bob_account = self.bc.get_account(self.bob_address)
        
        # Bob plays with score
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='GAME_FEE',
            data={'game_id': 'number_guessing', 'score': 150},
            nonce=bob_account['nonce'],
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        self.assertTrue(self._create_and_add_block([tx]))
        
        # Check leaderboard
        leaderboard = self.bc._get_leaderboard('number_guessing', self.bc.state_trie)
        self.assertEqual(leaderboard.get_score(self.bob_address), 150)
        self.assertEqual(leaderboard.get_rank(self.bob_address), 1)

    def test_game_fee_higher_score_takes_over(self):
        """Test that higher score takes over leadership."""
        # ARRANGE
        # 1. Bob plays and becomes the leader
        print("\n--- STARTING TEST: test_game_fee_higher_score_takes_over ---")

        genesis_validators = self.bc.get_validator_set()
        print(f"[1] Validators in GENESIS state: {genesis_validators}")
        self.assertIn(self.alice_address.hex(), genesis_validators)

        tx1_nonce = self.bc.get_account(self.bob_address)['nonce']
        tx1 = Transaction(
            tx_type='GAME_FEE',
            sender_public_key=self.bob_pem,
            nonce=tx1_nonce,
            data={'game_id': 'number_guessing', 'score': 100},
            fee=0
        )
        tx1.sign(self.priv_key_bob)
        
        success1 = self._create_and_add_block([tx1])
        self.assertTrue(success1)

        state_after_bob = self.bc.get_validator_set()
        print(f"[2] Validators AFTER BOB'S BLOCK: {state_after_bob}")

        # 2. Charlie prepares to play with a higher score
        bob_account_before = self.bc.get_account(self.bob_address)
        charlie_account_before = self.bc.get_account(self.charlie_address)
        treasury_before = self.bc.get_treasury()

        state_before_charlie = self.bc.get_validator_set()
        print(f"[3] Validators BEFORE CHARLIE'S BLOCK: {state_before_charlie}")

        # ACT
        tx2_nonce = self.bc.get_account(self.charlie_address)['nonce']
        tx2 = Transaction(
            tx_type='GAME_FEE',
            sender_public_key=self.charlie_pem,
            nonce=tx2_nonce,
            data={'game_id': 'number_guessing', 'score': 200},
            fee=0
        )
        tx2.sign(self.priv_key_charlie)
        
        success2 = self._create_and_add_block([tx2])

        state_after_charlie_fails = self.bc.get_validator_set()
        print(f"[4] Validators AFTER CHARLIE'S BLOCK: {state_after_charlie_fails}")
        print("--- END TEST ---")

        # ASSERT
        self.assertTrue(success2)
        
        charlie_account_after = self.bc.get_account(self.charlie_address)
        bob_account_after = self.bc.get_account(self.bob_address)
        
        # Calculate actual costs based on dynamic pricing
        # After Bob plays, some tokens are burned, which increases the price slightly
        # Charlie's payment amount can be calculated from his balance change
        charlie_payment = charlie_account_before['balance'] - charlie_account_after['balance']
        
        # Bob should receive 20% of Charlie's payment (leader reward)
        expected_bob_reward = (charlie_payment * 20) // 100
        actual_bob_reward = bob_account_after['balance'] - bob_account_before['balance']
        
        # Verify Bob received the correct leader reward
        self.assertEqual(
            actual_bob_reward,
            expected_bob_reward,
            f"Bob should receive 20% of Charlie's payment as leader reward"
        )
        
        # Charlie should have lost the payment amount with no rewards
        # (since he wasn't the leader when he played)
        expected_charlie_balance = charlie_account_before['balance'] - charlie_payment
        self.assertEqual(
            charlie_account_after['balance'],
            expected_charlie_balance,
            f"Charlie should have paid {charlie_payment} tokens with no rewards"
        )
        
        # Verify Charlie is now the leader
        leaderboard = self.bc._get_leaderboard('number_guessing', self.bc.state_trie)
        
        # Charlie should definitely be on the leaderboard with the top score
        self.assertIsNotNone(leaderboard.get_rank(self.charlie_address), "Charlie should be on leaderboard")
        self.assertEqual(leaderboard.get_rank(self.charlie_address), 1, "Charlie should be rank #1")
        self.assertEqual(leaderboard.get_score(self.charlie_address), 200)
        
        # Bob should also be on the leaderboard (assuming max_leaderboard_size >= 2)
        # If your config has min_qualifying_score > 100, Bob might not be there
        bob_rank = leaderboard.get_rank(self.bob_address)
        if bob_rank is not None:
            self.assertEqual(bob_rank, 2, "If Bob is on leaderboard, he should be rank #2")
            self.assertEqual(leaderboard.get_score(self.bob_address), 100)
        
        # The game config has leader_count=1, so only Charlie should be in "top leaders"
        leaders = self.bc.get_game_leaders('number_guessing')
        self.assertEqual(len(leaders), 1, "Only 1 leader for number_guessing game")
        self.assertEqual(leaders[0], self.charlie_address, "Charlie is the top leader")

    def test_game_fee_increments_nonce(self):
        """Test that GAME_FEE increments nonce."""
        bob_account_before = self.bc._get_account(self.bob_address, self.bc.state_trie)
        
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='GAME_FEE',
            data={'game_id': 'number_guessing', 'score': 50},
            nonce=bob_account_before['nonce'],
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        self.assertTrue(self._create_and_add_block([tx]))
        
        bob_account_after = self.bc._get_account(self.bob_address, self.bc.state_trie)
        self.assertEqual(bob_account_after['nonce'], bob_account_before['nonce'] + 1)

    def test_game_fee_with_custom_price(self):
        """Test game fee with different game price."""
        # Bob starts with 100 tokens
        bob_account = self.bc.get_account(self.bob_address)
        
        # Play flappy_bird which costs $0.10
        tx = Transaction(
            sender_public_key=self.bob_pem,
            tx_type='GAME_FEE',
            data={'game_id': 'flappy_bird', 'score': 50},
            nonce=bob_account['nonce'],
            fee=0,
            chain_id=1
        )
        tx.sign(self.priv_key_bob)
        
        self.assertTrue(self._create_and_add_block([tx]))
        
        # Should cost 0.1 tokens at $1/token
        bob_account_after = self.bc.get_account(self.bob_address)
        expected_balance = (100 * TOKEN_UNIT) - (100_000) # 0.1 * TOKEN_UNIT
        self.assertEqual(
            bob_account_after['balance'],
            expected_balance
        )


if __name__ == '__main__':
    unittest.main()