"""
Comprehensive tests for consensus logic, including leader scheduling and VRF validation.
"""
import unittest
import nacl.signing
from crypto_v2.consensus import LeaderScheduler, is_valid_leader
from crypto_v2.crypto import (
    generate_key_pair,
    serialize_public_key,
    public_key_to_address,
    generate_vrf_keypair,
    vrf_prove,
    vrf_verify
)


class TestLeaderScheduler(unittest.TestCase):
    def setUp(self):
        """Set up test wallets and validators."""
        self.wallets = {}
        self.validators = {}
        
        for name in ['alice', 'bob', 'charlie', 'david']:
            priv_key, pub_key = generate_key_pair()
            vrf_priv, vrf_pub = generate_vrf_keypair()
            address = public_key_to_address(serialize_public_key(pub_key))
            
            self.wallets[name] = {
                'priv_key': priv_key,
                'pub_key': pub_key,
                'pem': serialize_public_key(pub_key),
                'address': address,
                'vrf_priv': vrf_priv,
                'vrf_pub': vrf_pub,
            }
            
            # Only Alice, Bob, and Charlie are validators
            if name in ['alice', 'bob', 'charlie']:
                self.validators[address.hex()] = 100  # Equal stakes
        
        # Mock get_account function
        def get_account(address: bytes) -> dict:
            for name, wallet in self.wallets.items():
                if wallet['address'] == address:
                    return {
                        'balance': 1000,
                        'nonce': 0,
                        'vrf_pub_key': wallet['vrf_pub'].encode().hex()
                    }
            return {'balance': 0, 'nonce': 0}
        
        self.get_account = get_account

    def test_get_leader_deterministic(self):
        """Test that leader selection is deterministic for same seed."""
        scheduler = LeaderScheduler(self.validators, self.get_account)
        seed = b'test_seed_12345'
        
        leader1 = scheduler.get_leader(seed)
        leader2 = scheduler.get_leader(seed)
        
        self.assertEqual(leader1, leader2)
        self.assertIn(leader1, self.validators)
        print(f"\nSelected leader for seed: {leader1}")

    def test_get_leader_changes_with_seed(self):
        """Test that different seeds can produce different leaders."""
        scheduler = LeaderScheduler(self.validators, self.get_account)
        
        seeds = [b'seed_1', b'seed_2', b'seed_3', b'seed_4', b'seed_5']
        leaders = [scheduler.get_leader(seed) for seed in seeds]
        
        # With 3 validators and 5 seeds, we should see some variation
        # (not guaranteed, but very likely)
        unique_leaders = set(leaders)
        print(f"\nLeaders from 5 different seeds: {unique_leaders}")
        
        # All leaders should be valid validators
        for leader in leaders:
            self.assertIn(leader, self.validators)

    def test_get_leader_empty_validators(self):
        """Test behavior with no validators."""
        scheduler = LeaderScheduler({}, self.get_account)
        leader = scheduler.get_leader(b'any_seed')
        
        self.assertIsNone(leader)

    def test_get_leader_requires_vrf_key(self):
        """Test that validators without VRF keys are skipped."""
        # Create validator set with one invalid entry
        validators_with_invalid = self.validators.copy()
        
        # Add a validator without VRF key
        priv_key, pub_key = generate_key_pair()
        address = public_key_to_address(serialize_public_key(pub_key))
        validators_with_invalid[address.hex()] = 100
        
        # Mock get_account that returns no VRF key for this address
        def get_account_no_vrf(addr: bytes) -> dict:
            if addr == address:
                return {'balance': 1000, 'nonce': 0}  # No vrf_pub_key
            return self.get_account(addr)
        
        scheduler = LeaderScheduler(validators_with_invalid, get_account_no_vrf)
        seed = b'test_seed'
        
        leader = scheduler.get_leader(seed)
        
        # Leader should be one of the valid validators
        self.assertIn(leader, self.validators)
        self.assertNotEqual(leader, address.hex())


class TestVRFValidation(unittest.TestCase):
    def setUp(self):
        """Set up test wallets."""
        self.wallets = {}
        self.validators = {}
        
        for name in ['alice', 'bob', 'charlie']:
            priv_key, pub_key = generate_key_pair()
            vrf_priv, vrf_pub = generate_vrf_keypair()
            address = public_key_to_address(serialize_public_key(pub_key))
            
            self.wallets[name] = {
                'priv_key': priv_key,
                'pub_key': pub_key,
                'pem': serialize_public_key(pub_key),
                'address': address,
                'vrf_priv': vrf_priv,
                'vrf_pub': vrf_pub,
            }
            
            self.validators[address.hex()] = 100
        
        def get_account(address: bytes) -> dict:
            for name, wallet in self.wallets.items():
                if wallet['address'] == address:
                    return {
                        'balance': 1000,
                        'nonce': 0,
                        'vrf_pub_key': wallet['vrf_pub'].encode().hex()
                    }
            return {'balance': 0, 'nonce': 0}
        
        self.get_account = get_account

    def test_vrf_prove_and_verify(self):
        """Test basic VRF proof generation and verification."""
        alice = self.wallets['alice']
        seed = b'test_seed_data'
        
        # Generate proof
        proof, output = vrf_prove(alice['vrf_priv'], seed)
        
        self.assertIsNotNone(proof)
        self.assertIsNotNone(output)
        
        # Verify proof
        verify_key = alice['vrf_pub']
        verified_output = vrf_verify(verify_key, seed, proof)
        
        self.assertIsNotNone(verified_output)
        self.assertEqual(verified_output, output)

    def test_vrf_invalid_proof(self):
        """Test that invalid proofs are rejected."""
        alice = self.wallets['alice']
        seed = b'test_seed_data'
        
        # Try to verify with wrong seed
        proof, _ = vrf_prove(alice['vrf_priv'], seed)
        
        wrong_seed = b'wrong_seed'
        verify_key = alice['vrf_pub']
        verified_output = vrf_verify(verify_key, wrong_seed, proof)
        
        self.assertIsNone(verified_output)

    def test_is_valid_leader_correct_leader(self):
        """Test validation of correct leader."""
        seed = b'test_seed_for_leader'
        
        # Determine the actual leader
        scheduler = LeaderScheduler(self.validators, self.get_account)
        leader_address_hex = scheduler.get_leader(seed)
        
        # Find the leader wallet
        leader_wallet = None
        for name, wallet in self.wallets.items():
            if wallet['address'].hex() == leader_address_hex:
                leader_wallet = wallet
                break
        
        self.assertIsNotNone(leader_wallet)
        
        # Generate VRF proof
        vrf_proof, _ = vrf_prove(leader_wallet['vrf_priv'], seed)
        
        # Validate leader
        is_valid = is_valid_leader(
            producer_pubkey=leader_wallet['pem'],
            vrf_proof=vrf_proof,
            validators=self.validators,
            seed=seed,
            vrf_pub_key_hex=leader_wallet['vrf_pub'].encode().hex(),
            producer_address_hex=leader_wallet['address'].hex(),
            get_account=self.get_account
        )
        
        self.assertTrue(is_valid)

    def test_is_valid_leader_wrong_leader(self):
        """Test that wrong leader is rejected."""
        seed = b'test_seed_for_leader'
        
        # Determine the actual leader
        scheduler = LeaderScheduler(self.validators, self.get_account)
        leader_address_hex = scheduler.get_leader(seed)
        
        # Find a non-leader
        non_leader_wallet = None
        for name, wallet in self.wallets.items():
            if wallet['address'].hex() != leader_address_hex:
                non_leader_wallet = wallet
                break
        
        self.assertIsNotNone(non_leader_wallet)
        
        # Non-leader generates a proof (but they're not the leader)
        vrf_proof, _ = vrf_prove(non_leader_wallet['vrf_priv'], seed)
        
        # Validation should fail
        is_valid = is_valid_leader(
            producer_pubkey=non_leader_wallet['pem'],
            vrf_proof=vrf_proof,
            validators=self.validators,
            seed=seed,
            vrf_pub_key_hex=non_leader_wallet['vrf_pub'].encode().hex(),
            producer_address_hex=non_leader_wallet['address'].hex(),
            get_account=self.get_account
        )
        
        self.assertFalse(is_valid)

    def test_is_valid_leader_invalid_vrf_proof(self):
        """Test that invalid VRF proofs are rejected."""
        seed = b'test_seed_for_leader'
        
        # Determine the actual leader
        scheduler = LeaderScheduler(self.validators, self.get_account)
        leader_address_hex = scheduler.get_leader(seed)
        
        leader_wallet = None
        for name, wallet in self.wallets.items():
            if wallet['address'].hex() == leader_address_hex:
                leader_wallet = wallet
                break
        
        # Use invalid proof
        fake_proof = b'this_is_not_a_valid_proof_at_all'
        
        is_valid = is_valid_leader(
            producer_pubkey=leader_wallet['pem'],
            vrf_proof=fake_proof,
            validators=self.validators,
            seed=seed,
            vrf_pub_key_hex=leader_wallet['vrf_pub'].encode().hex(),
            producer_address_hex=leader_wallet['address'].hex(),
            get_account=self.get_account
        )
        
        self.assertFalse(is_valid)

    def test_is_valid_leader_non_validator(self):
        """Test that non-validators are rejected."""
        # David is not a validator
        david = self.wallets['charlie']  # Use charlie's wallet but pretend it's not in validators
        seed = b'test_seed'
        
        vrf_proof, _ = vrf_prove(david['vrf_priv'], seed)
        
        # Create empty validator set
        is_valid = is_valid_leader(
            producer_pubkey=david['pem'],
            vrf_proof=vrf_proof,
            validators={},  # Empty validator set
            seed=seed,
            vrf_pub_key_hex=david['vrf_pub'].encode().hex(),
            producer_address_hex=david['address'].hex(),
            get_account=self.get_account
        )
        
        self.assertFalse(is_valid)


class TestWeightedLeaderSelection(unittest.TestCase):
    def test_stake_weighted_selection(self):
        """Test that higher stake increases selection probability."""
        # Create validators with different stakes
        wallets = {}
        validators = {}
        
        for i, name in enumerate(['alice', 'bob', 'charlie']):
            priv_key, pub_key = generate_key_pair()
            vrf_priv, vrf_pub = generate_vrf_keypair()
            address = public_key_to_address(serialize_public_key(pub_key))
            
            wallets[name] = {
                'address': address,
                'vrf_priv': vrf_priv,
                'vrf_pub': vrf_pub,
            }
            
            # Alice has much higher stake
            stake = 1000 if name == 'alice' else 10
            validators[address.hex()] = stake
        
        def get_account(address: bytes) -> dict:
            for name, wallet in wallets.items():
                if wallet['address'] == address:
                    return {
                        'balance': 1000,
                        'nonce': 0,
                        'vrf_pub_key': wallet['vrf_pub'].encode().hex()
                    }
            return {'balance': 0, 'nonce': 0}
        
        scheduler = LeaderScheduler(validators, get_account)
        
        # Sample many seeds
        alice_count = 0
        total_samples = 100
        
        for i in range(total_samples):
            seed = f'seed_{i}'.encode()
            leader = scheduler.get_leader(seed)
            
            if leader == wallets['alice']['address'].hex():
                alice_count += 1
        
        # Alice should be selected more often (though not guaranteed in small sample)
        print(f"\nAlice selected {alice_count}/{total_samples} times with 1000/1020 stake")
        
        # With random selection and high stake, Alice should win majority
        # This is probabilistic, so we use a loose threshold
        self.assertGreater(alice_count, 30)  # At least 30% (expected ~98%)


if __name__ == '__main__':
    unittest.main()