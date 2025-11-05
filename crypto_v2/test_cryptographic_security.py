"""
Test Suite 4: Cryptographic Security
Critical Priority - Must Pass Before Launch

Tests signature verification, VRF proofs, key derivation, hash functions,
replay attack prevention, and cryptographic primitives.
"""
import pytest
import tempfile
import shutil
import time
from crypto_v2.chain import Blockchain, TOKEN_UNIT
from crypto_v2.core import Transaction, Block, BlockHeader
from crypto_v2.crypto import (
    generate_key_pair, serialize_public_key, public_key_to_address,
    generate_hash, sign, verify_signature, deserialize_public_key,
    generate_vrf_keypair, vrf_prove, vrf_verify
)
from crypto_v2.db import DB
from crypto_v2.poh import PoHRecorder, verify_poh_sequence
from crypto_v2.trie import BLANK_ROOT
import nacl.signing


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
    db.put(b'block:' + genesis.hash, block_data)
    db.put(b'height:0', genesis.hash)
    db.put(b'head', genesis.hash)

    chain = Blockchain(db=db, chain_id=1)
    yield chain
    db.close()
    shutil.rmtree(temp_dir)


@pytest.fixture
def keypair():
    """Generate a keypair for testing."""
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
def vrf_keypair():
    """Generate a VRF keypair for testing."""
    signing_key, verify_key = generate_vrf_keypair()
    return {
        'signing_key': signing_key,
        'verify_key': verify_key
    }


class TestSignatureVerification:
    """Test ECDSA signature creation and verification."""
    
    def test_valid_signature_verifies(self, keypair):
        """Valid signatures pass verification."""
        message = b"test message"
        signature = sign(keypair['priv_key'], message)
        
        assert verify_signature(keypair['pub_key_pem'], signature, message)
    
    def test_invalid_signature_fails(self, keypair):
        """Invalid signatures fail verification."""
        message = b"test message"
        invalid_signature = b"invalid_signature_bytes_here_xxxxxxxxxx"
        
        assert not verify_signature(keypair['pub_key_pem'], invalid_signature, message)
    
    def test_tampered_message_fails(self, keypair):
        """Signatures fail if message is tampered."""
        original_message = b"original message"
        signature = sign(keypair['priv_key'], original_message)
        
        tampered_message = b"tampered message"
        
        assert not verify_signature(keypair['pub_key_pem'], signature, tampered_message)
    
    def test_wrong_public_key_fails(self, keypair):
        """Signatures fail with wrong public key."""
        message = b"test message"
        signature = sign(keypair['priv_key'], message)
        
        # Generate different keypair
        other_priv, other_pub = generate_key_pair()
        other_pub_pem = serialize_public_key(other_pub)
        
        assert not verify_signature(other_pub_pem, signature, message)
    
    def test_signature_deterministic(self, keypair):
        """Same message produces verifiable signature (may differ due to randomness)."""
        message = b"deterministic test"
        
        sig1 = sign(keypair['priv_key'], message)
        sig2 = sign(keypair['priv_key'], message)
        
        # Both should verify (even if different due to ECDSA randomness)
        assert verify_signature(keypair['pub_key_pem'], sig1, message)
        assert verify_signature(keypair['pub_key_pem'], sig2, message)
    
    def test_empty_message_signature(self, keypair):
        """Can sign empty messages."""
        message = b""
        signature = sign(keypair['priv_key'], message)
        
        assert verify_signature(keypair['pub_key_pem'], signature, message)
    
    def test_large_message_signature(self, keypair):
        """Can sign large messages."""
        message = b"x" * 10000  # 10KB message
        signature = sign(keypair['priv_key'], message)
        
        assert verify_signature(keypair['pub_key_pem'], signature, message)


class TestTransactionSignatures:
    """Test transaction signature security."""
    
    def test_transaction_signature_verification(self, keypair):
        """Transaction signatures verify correctly."""
        tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(keypair['priv_key'])
        
        assert tx.verify_signature()
    
    def test_unsigned_transaction_fails(self, keypair):
        """Unsigned transactions fail verification."""
        tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        # Don't sign
        
        assert not tx.verify_signature()
    
    def test_tampered_amount_fails(self, keypair):
        """Tampering with amount invalidates signature."""
        tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(keypair['priv_key'])
        
        # Tamper with amount
        tx.data['amount'] = 200
        
        assert not tx.verify_signature()
    
    def test_tampered_recipient_fails(self, keypair):
        """Tampering with recipient invalidates signature."""
        tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(keypair['priv_key'])
        
        # Tamper with recipient
        tx.data['to'] = 'def456'
        
        assert not tx.verify_signature()
    
    def test_tampered_nonce_fails(self, keypair):
        """Tampering with nonce invalidates signature."""
        tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(keypair['priv_key'])
        
        # Tamper with nonce
        tx.nonce = 1
        
        assert not tx.verify_signature()
    
    def test_tampered_fee_fails(self, keypair):
        """Tampering with fee invalidates signature."""
        tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx.sign(keypair['priv_key'])
        
        # Tamper with fee
        tx.fee = 2000
        
        assert not tx.verify_signature()
    
    def test_transaction_id_deterministic(self, keypair):
        """Same transaction produces same ID."""
        tx1 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1,
            timestamp=12345.0  # Fixed timestamp
        )
        
        tx2 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1,
            timestamp=12345.0  # Same timestamp
        )
        
        assert tx1.id == tx2.id


class TestBlockSignatures:
    """Test block signature security."""
    
    def test_block_signature_verification(self, blockchain, keypair):
        """Block signatures verify correctly."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=poh.sequence[0][0] if poh.sequence else latest.hash,
            height=latest.height + 1,
            producer_pubkey=keypair['pub_key_pem'],
            vrf_proof=b'test_proof',
            vrf_pub_key=b'test_vrf_key',
            timestamp=time.time()
        )
        
        block.sign_block(keypair['priv_key'])
        
        assert block.verify_signature()
    
    def test_unsigned_block_fails(self, blockchain, keypair):
        """Unsigned blocks fail verification."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=poh.sequence[0][0] if poh.sequence else latest.hash,
            height=latest.height + 1,
            producer_pubkey=keypair['pub_key_pem'],
            vrf_proof=b'test_proof',
            vrf_pub_key=b'test_vrf_key',
            timestamp=time.time()
        )
        # Don't sign
        
        assert not block.verify_signature()
    
    def test_tampered_transactions_fails(self, blockchain, keypair):
        """Tampering with transactions invalidates block signature."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=poh.sequence[0][0] if poh.sequence else latest.hash,
            height=latest.height + 1,
            producer_pubkey=keypair['pub_key_pem'],
            vrf_proof=b'test_proof',
            vrf_pub_key=b'test_vrf_key',
            timestamp=time.time()
        )
        
        block.sign_block(keypair['priv_key'])
        
        # Add transaction after signing
        fake_tx = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        block.transactions = block.transactions + [fake_tx]
        
        # Signature should fail (transactions root changed)
        assert not block.verify_signature()
    
    def test_tampered_state_root_fails(self, blockchain, keypair):
        """Tampering with state root invalidates block signature."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        block = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=poh.sequence[0][0] if poh.sequence else latest.hash,
            height=latest.height + 1,
            producer_pubkey=keypair['pub_key_pem'],
            vrf_proof=b'test_proof',
            vrf_pub_key=b'test_vrf_key',
            timestamp=time.time()
        )
        
        block.sign_block(keypair['priv_key'])
        
        # Tamper with state root
        block.state_root = b'\x00' * 32
        
        assert not block.verify_signature()
    
    def test_block_hash_deterministic(self, blockchain, keypair):
        """Same block produces same hash."""
        latest = blockchain.get_latest_block()
        poh = PoHRecorder(latest.hash)
        poh.tick()
        
        block1 = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=poh.sequence[0][0] if poh.sequence else latest.hash,
            height=latest.height + 1,
            producer_pubkey=keypair['pub_key_pem'],
            vrf_proof=b'test_proof',
            vrf_pub_key=b'test_vrf_key',
            timestamp=12345.0  # Fixed timestamp
        )
        
        block2 = Block(
            parent_hash=latest.hash,
            state_root=latest.state_root,
            transactions=[],
            poh_sequence=poh.sequence,
            poh_initial=poh.sequence[0][0] if poh.sequence else latest.hash,
            height=latest.height + 1,
            producer_pubkey=keypair['pub_key_pem'],
            vrf_proof=b'test_proof',
            vrf_pub_key=b'test_vrf_key',
            timestamp=12345.0  # Same timestamp
        )
        
        assert block1.hash == block2.hash


class TestVRFProofs:
    """Test Verifiable Random Function proofs."""
    
    def test_vrf_proof_generation(self, vrf_keypair):
        """VRF proofs can be generated."""
        seed = b"test_seed"
        proof, output = vrf_prove(vrf_keypair['signing_key'], seed)
        
        assert proof is not None
        assert output is not None
        assert len(proof) > 0
    
    def test_vrf_proof_verification(self, vrf_keypair):
        """Valid VRF proofs verify correctly."""
        seed = b"test_seed"
        proof, expected_output = vrf_prove(vrf_keypair['signing_key'], seed)
        
        verified_output = vrf_verify(vrf_keypair['verify_key'], seed, proof)
        
        assert verified_output is not None
        assert verified_output == expected_output
    
    def test_vrf_invalid_proof_fails(self, vrf_keypair):
        """Invalid VRF proofs fail verification."""
        seed = b"test_seed"
        invalid_proof = b"\x00" * 64  # Correct length, but invalid content
        
        verified_output = vrf_verify(vrf_keypair['verify_key'], seed, invalid_proof)
        
        assert verified_output is None
    
    def test_vrf_wrong_seed_fails(self, vrf_keypair):
        """VRF proofs fail with wrong seed."""
        original_seed = b"original_seed"
        wrong_seed = b"wrong_seed"
        
        proof, _ = vrf_prove(vrf_keypair['signing_key'], original_seed)
        
        # Try to verify with wrong seed
        verified_output = vrf_verify(vrf_keypair['verify_key'], wrong_seed, proof)
        
        assert verified_output is None
    
    def test_vrf_wrong_verify_key_fails(self, vrf_keypair):
        """VRF proofs fail with wrong verify key."""
        seed = b"test_seed"
        proof, _ = vrf_prove(vrf_keypair['signing_key'], seed)
        
        # Generate different keypair
        other_signing, other_verify = generate_vrf_keypair()
        
        # Try to verify with wrong key
        verified_output = vrf_verify(other_verify, seed, proof)
        
        assert verified_output is None
    
    def test_vrf_deterministic_output(self, vrf_keypair):
        """Same seed produces same VRF output."""
        seed = b"deterministic_seed"
        
        proof1, output1 = vrf_prove(vrf_keypair['signing_key'], seed)
        proof2, output2 = vrf_prove(vrf_keypair['signing_key'], seed)
        
        # Outputs should be identical
        assert output1 == output2
    
    def test_vrf_different_seeds_different_outputs(self, vrf_keypair):
        """Different seeds produce different outputs."""
        seed1 = b"seed_one"
        seed2 = b"seed_two"
        
        proof1, output1 = vrf_prove(vrf_keypair['signing_key'], seed1)
        proof2, output2 = vrf_prove(vrf_keypair['signing_key'], seed2)
        
        assert output1 != output2


class TestHashFunctions:
    """Test hash function properties."""
    
    def test_hash_deterministic(self):
        """Same input produces same hash."""
        data = b"test data"
        
        hash1 = generate_hash(data)
        hash2 = generate_hash(data)
        
        assert hash1 == hash2
    
    def test_hash_different_inputs(self):
        """Different inputs produce different hashes."""
        data1 = b"data one"
        data2 = b"data two"
        
        hash1 = generate_hash(data1)
        hash2 = generate_hash(data2)
        
        assert hash1 != hash2
    
    def test_hash_length(self):
        """Hash output is 32 bytes (256 bits)."""
        data = b"any data"
        hash_output = generate_hash(data)
        
        assert len(hash_output) == 32
    
    def test_hash_avalanche_effect(self):
        """Small change in input produces large change in output."""
        data1 = b"test data"
        data2 = b"test datb"  # Changed last character
        
        hash1 = generate_hash(data1)
        hash2 = generate_hash(data2)
        
        # Count different bits
        different_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(hash1, hash2))
        
        # Should differ in many bits (avalanche effect)
        # Expect ~50% of bits to flip (128 bits out of 256)
        assert different_bits > 50  # At least some significant difference
    
    def test_hash_empty_input(self):
        """Can hash empty input."""
        data = b""
        hash_output = generate_hash(data)
        
        assert len(hash_output) == 32
        assert hash_output != b'\x00' * 32  # Should not be all zeros
    
    def test_hash_large_input(self):
        """Can hash large inputs."""
        data = b"x" * 1000000  # 1MB
        hash_output = generate_hash(data)
        
        assert len(hash_output) == 32
    
    def test_hash_collision_resistance(self):
        """Different inputs produce different hashes (collision resistance)."""
        hashes = set()
        
        # Generate hashes for many inputs
        for i in range(1000):
            data = str(i).encode()
            hash_output = generate_hash(data)
            hashes.add(hash_output)
        
        # All hashes should be unique (no collisions)
        assert len(hashes) == 1000


class TestAddressDerivation:
    """Test address derivation from public keys."""
    
    def test_address_derivation_deterministic(self, keypair):
        """Same public key produces same address."""
        addr1 = public_key_to_address(keypair['pub_key_pem'])
        addr2 = public_key_to_address(keypair['pub_key_pem'])
        
        assert addr1 == addr2
    
    def test_address_length(self, keypair):
        """Addresses are 20 bytes."""
        address = public_key_to_address(keypair['pub_key_pem'])
        
        assert len(address) == 20
    
    def test_different_keys_different_addresses(self):
        """Different public keys produce different addresses."""
        priv1, pub1 = generate_key_pair()
        priv2, pub2 = generate_key_pair()
        
        pub1_pem = serialize_public_key(pub1)
        pub2_pem = serialize_public_key(pub2)
        
        addr1 = public_key_to_address(pub1_pem)
        addr2 = public_key_to_address(pub2_pem)
        
        assert addr1 != addr2
    
    def test_address_no_collision(self):
        """Many keys produce unique addresses."""
        addresses = set()
        
        for i in range(100):
            priv, pub = generate_key_pair()
            pub_pem = serialize_public_key(pub)
            address = public_key_to_address(pub_pem)
            addresses.add(address)
        
        # All addresses should be unique
        assert len(addresses) == 100


class TestReplayAttackPrevention:
    """Test protection against replay attacks."""
    
    def test_chain_id_prevents_cross_chain_replay(self, keypair):
        """Chain ID prevents replaying on different chain."""
        # Transaction for chain 1
        tx_chain1 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx_chain1.sign(keypair['priv_key'])
        
        # Same transaction for chain 2
        tx_chain2 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=2
        )
        tx_chain2.sign(keypair['priv_key'])
        
        # Should have different IDs and signatures
        assert tx_chain1.id != tx_chain2.id
        assert tx_chain1.signature != tx_chain2.signature
    
    def test_nonce_prevents_transaction_replay(self, keypair):
        """Nonce prevents replaying same transaction."""
        # Two transactions with different nonces
        tx1 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1
        )
        tx1.sign(keypair['priv_key'])
        
        tx2 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=1,  # Different nonce
            fee=1000,
            chain_id=1
        )
        tx2.sign(keypair['priv_key'])
        
        # Should have different IDs
        assert tx1.id != tx2.id
    
    def test_timestamp_in_signature(self, keypair):
        """Timestamp is included in signature."""
        tx1 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1,
            timestamp=12345.0
        )
        tx1.sign(keypair['priv_key'])
        
        tx2 = Transaction(
            sender_public_key=keypair['pub_key_pem'],
            tx_type='TRANSFER',
            data={'to': 'abc123', 'amount': 100, 'token_type': 'native'},
            nonce=0,
            fee=1000,
            chain_id=1,
            timestamp=67890.0  # Different timestamp
        )
        tx2.sign(keypair['priv_key'])
        
        # Different timestamps produce different signatures
        assert tx1.signature != tx2.signature


class TestProofOfHistory:
    """Test Proof of History sequence verification."""
    
    def test_poh_sequence_valid(self):
        """Valid PoH sequences verify correctly."""
        initial_hash = b'\x00' * 32
        poh = PoHRecorder(initial_hash)
        
        for _ in range(10):
            poh.tick()
        
        assert verify_poh_sequence(initial_hash, poh.sequence)
    
    def test_poh_sequence_with_events(self):
        """PoH sequences with events verify correctly."""
        initial_hash = b'\x00' * 32
        poh = PoHRecorder(initial_hash)
        
        poh.tick()
        poh.record(b"event1")
        poh.tick()
        poh.record(b"event2")
        poh.tick()
        
        assert verify_poh_sequence(initial_hash, poh.sequence)
    
    def test_poh_tampered_sequence_fails(self):
        """Tampered PoH sequences fail verification."""
        initial_hash = b'\x00' * 32
        poh = PoHRecorder(initial_hash)
        
        for _ in range(10):
            poh.tick()
        
        # Tamper with sequence
        poh.sequence[5] = (b'\xff' * 32, None)
        
        assert not verify_poh_sequence(initial_hash, poh.sequence)
    
    def test_poh_wrong_initial_hash_fails(self):
        """PoH verification fails with wrong initial hash."""
        initial_hash = b'\x00' * 32
        wrong_hash = b'\xff' * 32
        
        poh = PoHRecorder(initial_hash)
        
        for _ in range(10):
            poh.tick()
        
        assert not verify_poh_sequence(wrong_hash, poh.sequence)
    
    def test_poh_sequence_deterministic(self):
        """Same operations produce same PoH sequence."""
        initial_hash = b'\xaa' * 32
        
        poh1 = PoHRecorder(initial_hash)
        poh1.tick()
        poh1.record(b"event")
        poh1.tick()
        
        poh2 = PoHRecorder(initial_hash)
        poh2.tick()
        poh2.record(b"event")
        poh2.tick()
        
        assert poh1.sequence == poh2.sequence


class TestKeyGeneration:
    """Test cryptographic key generation."""
    
    def test_keypair_generation(self):
        """Can generate keypairs."""
        priv, pub = generate_key_pair()
        
        assert priv is not None
        assert pub is not None
    
    def test_keypairs_unique(self):
        """Generated keypairs are unique."""
        priv1, pub1 = generate_key_pair()
        priv2, pub2 = generate_key_pair()
        
        pub1_pem = serialize_public_key(pub1)
        pub2_pem = serialize_public_key(pub2)
        
        assert pub1_pem != pub2_pem
    
    def test_public_key_serialization(self):
        """Public keys can be serialized and deserialized."""
        priv, pub = generate_key_pair()
        
        pub_pem = serialize_public_key(pub)
        pub_recovered = deserialize_public_key(pub_pem)
        
        # Should be able to serialize again and get same result
        pub_pem2 = serialize_public_key(pub_recovered)
        assert pub_pem == pub_pem2
    
    def test_vrf_keypair_generation(self):
        """Can generate VRF keypairs."""
        signing_key, verify_key = generate_vrf_keypair()
        
        assert signing_key is not None
        assert verify_key is not None
        assert isinstance(signing_key, nacl.signing.SigningKey)
        assert isinstance(verify_key, nacl.signing.VerifyKey)
    
    def test_vrf_keypairs_unique(self):
        """Generated VRF keypairs are unique."""
        sign1, verify1 = generate_vrf_keypair()
        sign2, verify2 = generate_vrf_keypair()
        
        assert verify1.encode() != verify2.encode()


class TestCryptographicConstants:
    """Test security of cryptographic parameters."""
    
    def test_hash_output_size(self):
        """Hash output is 256 bits (secure size)."""
        data = b"test"
        hash_output = generate_hash(data)
        
        assert len(hash_output) == 32  # 256 bits
    
    def test_address_size(self):
        """Addresses are 160 bits (20 bytes)."""
        priv, pub = generate_key_pair()
        pub_pem = serialize_public_key(pub)
        address = public_key_to_address(pub_pem)
        
        assert len(address) == 20  # 160 bits
    
    def test_signature_size(self):
        """Signatures have reasonable size."""
        priv, pub = generate_key_pair()
        message = b"test"
        signature = sign(priv, message)
        
        # ECDSA signatures are typically 64-71 bytes
        assert 60 <= len(signature) <= 80


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])