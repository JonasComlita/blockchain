"""
Core data structures for the blockchain with improved security.
"""
import time
import msgpack
from typing import Optional
from .crypto import (
    generate_hash, 
    serialize_public_key, 
    public_key_to_address, 
    sign,
    verify_signature,
    deserialize_public_key
)

class Transaction:
    def __init__(self,
                 sender_public_key: str,
                 tx_type: str,
                 data: dict,
                 nonce: int,
                 fee: int,
                 signature: Optional[bytes] = None,
                 timestamp: Optional[float] = None,
                 chain_id: Optional[int] = 1):  # Replay protection
        self.sender_public_key = sender_public_key
        self.tx_type = tx_type
        self.data = data
        self.nonce = nonce
        self.fee = fee
        self.timestamp = timestamp or time.time()
        self.signature = signature
        self.chain_id = chain_id

    def to_dict(self, include_signature=True):
        data = {
            "sender_public_key": self.sender_public_key,
            "tx_type": self.tx_type,
            "data": self.data,
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "chain_id": self.chain_id,
        }
        if include_signature and self.signature:
            data["signature"] = self.signature
        return data

    def get_signing_data(self) -> bytes:
        """Returns the canonical byte representation for signing."""
        return msgpack.packb(self.to_dict(include_signature=False), use_bin_type=True)

    def sign(self, private_key):
        """Signs the transaction."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self):
        """Verifies the transaction's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.sender_public_key,
            self.signature,
            self.get_signing_data()
        )

    @property
    def id(self) -> bytes:
        """The unique hash identifier of the transaction."""
        return generate_hash(self.get_signing_data())

    def validate_basic(self) -> tuple[bool, str]:
        """
        Performs basic validation checks on the transaction.
        Returns (is_valid, error_message)
        """
        # Check signature
        if not self.verify_signature():
            return False, "Invalid signature"
        
        # Check fee is non-negative
        if self.fee < 0:
            return False, "Negative fee"
        
        # Check timestamp is reasonable (not too far in future)
        current_time = time.time()
        if self.timestamp > current_time + 300:  # 5 minutes tolerance
            return False, "Timestamp too far in future"
        
        # Validate transaction type and data
        if self.tx_type == 'TRANSFER':
            if 'to' not in self.data or 'amount' not in self.data:
                return False, "TRANSFER requires 'to' and 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Transfer amount must be positive"
            except Exception:
                return False, "Invalid transfer amount"
                
        elif self.tx_type == 'ATTEST':
            if 'block_hash' not in self.data:
                return False, "ATTEST requires 'block_hash'"
            
        elif self.tx_type == 'PURCHASE':
            if 'usd_amount' not in self.data:
                return False, "PURCHASE requires 'usd_amount'"
            try:
                if int(self.data['usd_amount']) <= 0:
                    return False, "Purchase amount must be positive"
            except Exception:
                return False, "Invalid purchase amount"
            
        elif self.tx_type == 'GAME_FEE':
            if 'game_id' not in self.data or 'score' not in self.data:
                return False, "GAME_FEE requires 'game_id' and 'score'"
            try:
                int(self.data['score'])
            except (ValueError, TypeError):
                return False, "Invalid score format"
                
        elif self.tx_type == 'STAKE':
            if 'amount' not in self.data or 'vrf_pub_key' not in self.data:
                return False, "STAKE requires 'amount' and 'vrf_pub_key'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Stake amount must be positive"
            except Exception:
                return False, "Invalid stake amount"
                
        elif self.tx_type == 'UNSTAKE':
            if 'amount' not in self.data:
                return False, "UNSTAKE requires 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Unstake amount must be positive"
            except Exception:
                return False, "Invalid unstake amount"
                
        elif self.tx_type == 'SLASH':
            if 'header1' not in self.data or 'header2' not in self.data:
                return False, "SLASH requires 'header1' and 'header2'"
        else:
            return False, f"Unknown transaction type: {self.tx_type}"
        
        return True, ""


class BlockHeader:
    """Separate block header for signing and verification."""
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions_root: bytes,
                 height: int,
                 timestamp: float,
                 producer: str,
                 vrf_proof: bytes):
        self.parent_hash = parent_hash
        self.state_root = state_root

        self._transactions = transactions
        self._cached_header = None
        self._cached_hash = None

        @property
        def transactions(self):
            return self._transactions

        @transactions.setter
        def transactions(self, value):
            self._transactions = value
            self._cached_header = None
            self._cached_hash = None

        self.height = height
        self.timestamp = timestamp
        self.producer = producer
        self.vrf_proof = vrf_proof

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions_root": self.transactions_root,
            "height": self.height,
            "timestamp": self.timestamp,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
        }

    def get_hash(self) -> bytes:
        """Calculate the hash of this header."""
        return generate_hash(msgpack.packb(self.to_dict(), use_bin_type=True))


class Block:
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions: list[Transaction],
                 poh_sequence: list[tuple[bytes, bytes | None]],
                 height: int,
                 producer: str,
                 vrf_proof: bytes,
                 timestamp: Optional[float] = None,
                 signature: Optional[bytes] = None):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self._transactions = transactions
        self.poh_sequence = poh_sequence
        self.height = height
        self.producer = producer
        self.vrf_proof = vrf_proof
        self.timestamp = timestamp or time.time()
        self.signature = signature
        
        self._cached_header = None
        self._cached_hash = None

    @property
    def transactions(self):
        return self._transactions

    @transactions.setter
    def transactions(self, value):
        self._transactions = value
        self._cached_header = None
        self._cached_hash = None

    def _calculate_transactions_root(self) -> bytes:
        """Calculate Merkle root of transaction IDs."""
        if not self.transactions:
            return b'\x00' * 32
        
        tx_ids = [tx.id for tx in self.transactions]
        return self._merkle_root(tx_ids)
    
    def _merkle_root(self, hashes: list[bytes]) -> bytes:
        """Calculate Merkle root from a list of hashes."""
        if not hashes:
            return b'\x00' * 32
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = generate_hash(hashes[i] + hashes[i + 1])
            next_level.append(combined)
        
        return self._merkle_root(next_level)

    @property
    def header(self) -> BlockHeader:
        """Get the block header."""
        if not self._cached_header:
            self._cached_header = BlockHeader(
                parent_hash=self.parent_hash,
                state_root=self.state_root,
                transactions_root=self._calculate_transactions_root(),
                height=self.height,
                timestamp=self.timestamp,
                producer=self.producer,
                vrf_proof=self.vrf_proof
            )
        return self._cached_header

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "poh_sequence": self.poh_sequence,
            "height": self.height,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    def get_signing_data(self) -> bytes:
        """Get the data to be signed (the header hash)."""
        return self.header.get_hash()

    def sign_block(self, private_key):
        """Sign the block with the producer's private key."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self) -> bool:
        """Verify the block's signature."""
        if not self.signature:
            return False
        
        # Re-calculate the header hash to ensure block contents haven't been tampered with
        current_hash = self.header.get_hash()
        
        return verify_signature(
            self.producer,
            self.signature,
            current_hash
        )

    @property
    def hash(self) -> bytes:
        """The unique hash identifier of the block."""
        if not self._cached_hash:
            self._cached_hash = self.header.calculate_hash()
        return self._cached_hash

import time
import msgpack
from typing import Optional
from .crypto import (
    generate_hash, 
    serialize_public_key, 
    public_key_to_address, 
    sign,
    verify_signature,
    deserialize_public_key
)

class Transaction:
    def __init__(self,
                 sender_public_key: str,
                 tx_type: str,
                 data: dict,
                 nonce: int,
                 fee: int,
                 signature: Optional[bytes] = None,
                 timestamp: Optional[float] = None,
                 chain_id: Optional[int] = 1):  # Replay protection
        self.sender_public_key = sender_public_key
        self.tx_type = tx_type
        self.data = data
        self.nonce = nonce
        self.fee = fee
        self.timestamp = timestamp or time.time()
        self.signature = signature
        self.chain_id = chain_id

    def to_dict(self, include_signature=True):
        data = {
            "sender_public_key": self.sender_public_key,
            "tx_type": self.tx_type,
            "data": self.data,
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "chain_id": self.chain_id,
        }
        if include_signature and self.signature:
            data["signature"] = self.signature
        return data

    def get_signing_data(self) -> bytes:
        """Returns the canonical byte representation for signing."""
        return msgpack.packb(self.to_dict(include_signature=False), use_bin_type=True)

    def sign(self, private_key):
        """Signs the transaction."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self):
        """Verifies the transaction's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.sender_public_key,
            self.signature,
            self.get_signing_data()
        )

    @property
    def id(self) -> bytes:
        """The unique hash identifier of the transaction."""
        return generate_hash(self.get_signing_data())

    def validate_basic(self) -> tuple[bool, str]:
        """
        Performs basic validation checks on the transaction.
        Returns (is_valid, error_message)
        """
        # Check signature
        if not self.verify_signature():
            return False, "Invalid signature"
        
        # Check fee is non-negative
        if self.fee < 0:
            return False, "Negative fee"
        
        # Check timestamp is reasonable (not too far in future)
        current_time = time.time()
        if self.timestamp > current_time + 300:  # 5 minutes tolerance
            return False, "Timestamp too far in future"
        
        # Validate transaction type and data
        if self.tx_type == 'TRANSFER':
            if 'to' not in self.data or 'amount' not in self.data:
                return False, "TRANSFER requires 'to' and 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Transfer amount must be positive"
            except Exception:
                return False, "Invalid transfer amount"
                
        elif self.tx_type == 'ATTEST':
            if 'block_hash' not in self.data:
                return False, "ATTEST requires 'block_hash'"
            
        elif self.tx_type == 'PURCHASE':
            if 'usd_amount' not in self.data:
                return False, "PURCHASE requires 'usd_amount'"
            try:
                if int(self.data['usd_amount']) <= 0:
                    return False, "Purchase amount must be positive"
            except Exception:
                return False, "Invalid purchase amount"
            
        elif self.tx_type == 'GAME_FEE':
            if 'game_id' not in self.data or 'score' not in self.data:
                return False, "GAME_FEE requires 'game_id' and 'score'"
            try:
                int(self.data['score'])
            except (ValueError, TypeError):
                return False, "Invalid score format"
                
        elif self.tx_type == 'STAKE':
            if 'amount' not in self.data or 'vrf_pub_key' not in self.data:
                return False, "STAKE requires 'amount' and 'vrf_pub_key'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Stake amount must be positive"
            except Exception:
                return False, "Invalid stake amount"
                
        elif self.tx_type == 'UNSTAKE':
            if 'amount' not in self.data:
                return False, "UNSTAKE requires 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Unstake amount must be positive"
            except Exception:
                return False, "Invalid unstake amount"
                
        elif self.tx_type == 'SLASH':
            if 'header1' not in self.data or 'header2' not in self.data:
                return False, "SLASH requires 'header1' and 'header2'"
        else:
            return False, f"Unknown transaction type: {self.tx_type}"
        
        return True, ""


class BlockHeader:
    """Separate block header for signing and verification."""
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions_root: bytes,
                 height: int,
                 timestamp: float,
                 producer: str,
                 vrf_proof: bytes):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions_root = transactions_root
        self.height = height
        self.timestamp = timestamp
        self.producer = producer
        self.vrf_proof = vrf_proof

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions_root": self.transactions_root,
            "height": self.height,
            "timestamp": self.timestamp,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
        }

    def get_hash(self) -> bytes:
        """Calculate the hash of this header."""
        return generate_hash(msgpack.packb(self.to_dict(), use_bin_type=True))


class Block:
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions: list[Transaction],
                 poh_sequence: list[tuple[bytes, bytes | None]],
                 height: int,
                 producer: str,
                 vrf_proof: bytes,
                 timestamp: Optional[float] = None,
                 signature: Optional[bytes] = None):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self._transactions = transactions
        self.poh_sequence = poh_sequence
        self.height = height
        self.producer = producer
        self.vrf_proof = vrf_proof
        self.timestamp = timestamp or time.time()
        self.signature = signature
        
        self._cached_header = None
        self._cached_hash = None

    @property
    def transactions(self):
        return self._transactions

    @transactions.setter
    def transactions(self, value):
        self._transactions = value
        self._cached_header = None
        self._cached_hash = None

    def _calculate_transactions_root(self) -> bytes:
        """Calculate Merkle root of transaction IDs."""
        if not self.transactions:
            return b'\x00' * 32
        
        tx_ids = [tx.id for tx in self.transactions]
        return self._merkle_root(tx_ids)
    
    def _merkle_root(self, hashes: list[bytes]) -> bytes:
        """Calculate Merkle root from a list of hashes."""
        if not hashes:
            return b'\x00' * 32
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = generate_hash(hashes[i] + hashes[i + 1])
            next_level.append(combined)
        
        return self._merkle_root(next_level)

    @property
    def header(self) -> BlockHeader:
        """Get the block header."""
        if not self._cached_header:
            self._cached_header = BlockHeader(
                parent_hash=self.parent_hash,
                state_root=self.state_root,
                transactions_root=self._calculate_transactions_root(),
                height=self.height,
                timestamp=self.timestamp,
                producer=self.producer,
                vrf_proof=self.vrf_proof
            )
        return self._cached_header

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "poh_sequence": self.poh_sequence,
            "height": self.height,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    def get_signing_data(self) -> bytes:
        """Get the data to be signed (the header hash)."""
        return self.header.get_hash()

    def sign_block(self, private_key):
        """Sign the block with the producer's private key."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self) -> bool:
        """Verify the block's signature."""
        if not self.signature:
            return False
        
        # Re-calculate the header hash to ensure block contents haven't been tampered with
        current_hash = self.header.get_hash()
        
        return verify_signature(
            self.producer,
            self.signature,
            current_hash
        )

    @property
    def hash(self) -> bytes:
        """The unique hash identifier of the block."""
        if not self._cached_hash:
            self._cached_hash = self.header.get_hash()
        return self._cached_hash

import time
import msgpack
from typing import Optional
from .crypto import (
    generate_hash, 
    serialize_public_key, 
    public_key_to_address, 
    sign,
    verify_signature,
    deserialize_public_key
)

class Transaction:
    def __init__(self,
                 sender_public_key: str,
                 tx_type: str,
                 data: dict,
                 nonce: int,
                 fee: int,
                 signature: Optional[bytes] = None,
                 timestamp: Optional[float] = None,
                 chain_id: Optional[int] = 1):  # Replay protection
        self.sender_public_key = sender_public_key
        self.tx_type = tx_type
        self.data = data
        self.nonce = nonce
        self.fee = fee
        self.timestamp = timestamp or time.time()
        self.signature = signature
        self.chain_id = chain_id

    def to_dict(self, include_signature=True):
        data = {
            "sender_public_key": self.sender_public_key,
            "tx_type": self.tx_type,
            "data": self.data,
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "chain_id": self.chain_id,
        }
        if include_signature and self.signature:
            data["signature"] = self.signature
        return data

    def get_signing_data(self) -> bytes:
        """Returns the canonical byte representation for signing."""
        return msgpack.packb(self.to_dict(include_signature=False), use_bin_type=True)

    def sign(self, private_key):
        """Signs the transaction."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self):
        """Verifies the transaction's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.sender_public_key,
            self.signature,
            self.get_signing_data()
        )

    @property
    def id(self) -> bytes:
        """The unique hash identifier of the transaction."""
        return generate_hash(self.get_signing_data())

    def validate_basic(self) -> tuple[bool, str]:
        """
        Performs basic validation checks on the transaction.
        Returns (is_valid, error_message)
        """
        # Check signature
        if not self.verify_signature():
            return False, "Invalid signature"
        
        # Check fee is non-negative
        if self.fee < 0:
            return False, "Negative fee"
        
        # Check timestamp is reasonable (not too far in future)
        current_time = time.time()
        if self.timestamp > current_time + 300:  # 5 minutes tolerance
            return False, "Timestamp too far in future"
        
        # Validate transaction type and data
        if self.tx_type == 'TRANSFER':
            if 'to' not in self.data or 'amount' not in self.data:
                return False, "TRANSFER requires 'to' and 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Transfer amount must be positive"
            except Exception:
                return False, "Invalid transfer amount"
                
        elif self.tx_type == 'ATTEST':
            if 'block_hash' not in self.data:
                return False, "ATTEST requires 'block_hash'"
            
        elif self.tx_type == 'PURCHASE':
            if 'usd_amount' not in self.data:
                return False, "PURCHASE requires 'usd_amount'"
            try:
                if int(self.data['usd_amount']) <= 0:
                    return False, "Purchase amount must be positive"
            except Exception:
                return False, "Invalid purchase amount"
            
        elif self.tx_type == 'GAME_FEE':
            if 'game_id' not in self.data or 'score' not in self.data:
                return False, "GAME_FEE requires 'game_id' and 'score'"
            try:
                int(self.data['score'])
            except (ValueError, TypeError):
                return False, "Invalid score format"
                
        elif self.tx_type == 'STAKE':
            if 'amount' not in self.data or 'vrf_pub_key' not in self.data:
                return False, "STAKE requires 'amount' and 'vrf_pub_key'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Stake amount must be positive"
            except Exception:
                return False, "Invalid stake amount"
                
        elif self.tx_type == 'UNSTAKE':
            if 'amount' not in self.data:
                return False, "UNSTAKE requires 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Unstake amount must be positive"
            except Exception:
                return False, "Invalid unstake amount"
                
        elif self.tx_type == 'SLASH':
            if 'header1' not in self.data or 'header2' not in self.data:
                return False, "SLASH requires 'header1' and 'header2'"
        else:
            return False, f"Unknown transaction type: {self.tx_type}"
        
        return True, ""


class BlockHeader:
    """Separate block header for signing and verification."""
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions_root: bytes,
                 height: int,
                 timestamp: float,
                 producer: str,
                 vrf_proof: bytes):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions_root = transactions_root
        self.height = height
        self.timestamp = timestamp
        self.producer = producer
        self.vrf_proof = vrf_proof

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions_root": self.transactions_root,
            "height": self.height,
            "timestamp": self.timestamp,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
        }

    def get_hash(self) -> bytes:
        """Calculate the hash of this header."""
        return generate_hash(msgpack.packb(self.to_dict(), use_bin_type=True))


class Block:
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions: list[Transaction],
                 poh_sequence: list[tuple[bytes, bytes | None]],
                 height: int,
                 producer: str,
                 vrf_proof: bytes,
                 timestamp: Optional[float] = None,
                 signature: Optional[bytes] = None):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self._transactions = transactions
        self.poh_sequence = poh_sequence
        self.height = height
        self.producer = producer
        self.vrf_proof = vrf_proof
        self.timestamp = timestamp or time.time()
        self.signature = signature
        
        self._cached_header = None
        self._cached_hash = None

    @property
    def transactions(self):
        return self._transactions

    @transactions.setter
    def transactions(self, value):
        self._transactions = value
        self._cached_header = None
        self._cached_hash = None

    def _calculate_transactions_root(self) -> bytes:
        """Calculate Merkle root of transaction IDs."""
        if not self.transactions:
            return b'\x00' * 32
        
        tx_ids = [tx.id for tx in self.transactions]
        return self._merkle_root(tx_ids)
    
    def _merkle_root(self, hashes: list[bytes]) -> bytes:
        """Calculate Merkle root from a list of hashes."""
        if not hashes:
            return b'\x00' * 32
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = generate_hash(hashes[i] + hashes[i + 1])
            next_level.append(combined)
        
        return self._merkle_root(next_level)

    @property
    def header(self) -> BlockHeader:
        """Get the block header."""
        if not self._cached_header:
            self._cached_header = BlockHeader(
                parent_hash=self.parent_hash,
                state_root=self.state_root,
                transactions_root=self._calculate_transactions_root(),
                height=self.height,
                timestamp=self.timestamp,
                producer=self.producer,
                vrf_proof=self.vrf_proof
            )
        return self._cached_header

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "poh_sequence": self.poh_sequence,
            "height": self.height,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    def get_signing_data(self) -> bytes:
        """Get the data to be signed (the header hash)."""
        return self.header.get_hash()

    def sign_block(self, private_key):
        """Sign the block with the producer's private key."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self) -> bool:
        """Verify the block's signature."""
        if not self.signature:
            return False
        
        # Re-calculate the header hash to ensure block contents haven't been tampered with
        current_hash = self.header.get_hash()
        
        return verify_signature(
            self.producer,
            self.signature,
            current_hash
        )

    @property
    def hash(self) -> bytes:
        """The unique hash identifier of the block."""
        if not self._cached_hash:
            self._cached_hash = self.header.get_hash()
        return self._cached_hash

import time
import msgpack
from typing import Optional
from crypto_v2.crypto import (
    generate_hash, 
    serialize_public_key, 
    public_key_to_address, 
    sign,
    verify_signature
)

class Transaction:
    def __init__(self,
                 sender_public_key: str,
                 tx_type: str,
                 data: dict,
                 nonce: int,
                 fee: int,
                 signature: Optional[bytes] = None,
                 timestamp: Optional[float] = None,
                 chain_id: Optional[int] = 1):  # Replay protection
        self.sender_public_key = sender_public_key
        self.tx_type = tx_type
        self.data = data
        self.nonce = nonce
        self.fee = fee
        self.timestamp = timestamp or time.time()
        self.signature = signature
        self.chain_id = chain_id

    def to_dict(self, include_signature=True):
        data = {
            "sender_public_key": self.sender_public_key,
            "tx_type": self.tx_type,
            "data": self.data,
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "chain_id": self.chain_id,
        }
        if include_signature and self.signature:
            data["signature"] = self.signature
        return data

    def get_signing_data(self) -> bytes:
        """Returns the canonical byte representation for signing."""
        return msgpack.packb(self.to_dict(include_signature=False), use_bin_type=True)

    def sign(self, private_key):
        """Signs the transaction."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self):
        """Verifies the transaction's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.sender_public_key,
            self.signature,
            self.get_signing_data()
        )

    @property
    def id(self) -> bytes:
        """The unique hash identifier of the transaction."""
        return generate_hash(self.get_signing_data())

    def validate_basic(self) -> tuple[bool, str]:
        """
        Performs basic validation checks on the transaction.
        Returns (is_valid, error_message)
        """
        # Check signature
        if not self.verify_signature():
            return False, "Invalid signature"
        
        # Check fee is non-negative
        if self.fee < 0:
            return False, "Negative fee"
        
        # Check timestamp is reasonable (not too far in future)
        current_time = time.time()
        if self.timestamp > current_time + 300:  # 5 minutes tolerance
            return False, "Timestamp too far in future"
        
        # Validate transaction type and data
        if self.tx_type == 'TRANSFER':
            if 'to' not in self.data or 'amount' not in self.data:
                return False, "TRANSFER requires 'to' and 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Transfer amount must be positive"
            except Exception:
                return False, "Invalid transfer amount"
                
        elif self.tx_type == 'ATTEST':
            if 'block_hash' not in self.data:
                return False, "ATTEST requires 'block_hash'"
            
        elif self.tx_type == 'PURCHASE':
            if 'usd_amount' not in self.data:
                return False, "PURCHASE requires 'usd_amount'"
            try:
                if int(self.data['usd_amount']) <= 0:
                    return False, "Purchase amount must be positive"
            except Exception:
                return False, "Invalid purchase amount"
            
        elif self.tx_type == 'GAME_FEE':
            if 'game_id' not in self.data or 'score' not in self.data:
                return False, "GAME_FEE requires 'game_id' and 'score'"
            try:
                int(self.data['score'])
            except (ValueError, TypeError):
                return False, "Invalid score format"
                
        elif self.tx_type == 'STAKE':
            if 'amount' not in self.data or 'vrf_pub_key' not in self.data:
                return False, "STAKE requires 'amount' and 'vrf_pub_key'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Stake amount must be positive"
            except Exception:
                return False, "Invalid stake amount"
                
        elif self.tx_type == 'UNSTAKE':
            if 'amount' not in self.data:
                return False, "UNSTAKE requires 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Unstake amount must be positive"
            except Exception:
                return False, "Invalid unstake amount"
                
        elif self.tx_type == 'SLASH':
            if 'header1' not in self.data or 'header2' not in self.data:
                return False, "SLASH requires 'header1' and 'header2'"
        else:
            return False, f"Unknown transaction type: {self.tx_type}"
        
        return True, ""


class BlockHeader:
    """Separate block header for signing and verification."""
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions_root: bytes,
                 height: int,
                 timestamp: float,
                 producer: str,
                 vrf_proof: bytes):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions_root = transactions_root
        self.height = height
        self.timestamp = timestamp
        self.producer = producer
        self.vrf_proof = vrf_proof

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions_root": self.transactions_root,
            "height": self.height,
            "timestamp": self.timestamp,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
        }

    def calculate_hash(self) -> bytes:
        """Calculate the hash of this header."""
        return generate_hash(msgpack.packb(self.to_dict(), use_bin_type=True))


class Block:
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions: list[Transaction],
                 poh_sequence: list[tuple[bytes, bytes | None]],
                 height: int,
                 producer: str,
                 vrf_proof: bytes,
                 timestamp: Optional[float] = None,
                 signature: Optional[bytes] = None):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions = transactions
        self.poh_sequence = poh_sequence
        self.height = height
        self.producer = producer
        self.vrf_proof = vrf_proof
        self.timestamp = timestamp or time.time()
        self.signature = signature
        
        # Calculate transactions root (Merkle root of transaction IDs)
        self.transactions_root = self._calculate_transactions_root()

    def _calculate_transactions_root(self) -> bytes:
        """Calculate Merkle root of transaction IDs."""
        if not self.transactions:
            return b'\x00' * 32
        
        tx_ids = [tx.id for tx in self.transactions]
        return self._merkle_root(tx_ids)
    
    def _merkle_root(self, hashes: list[bytes]) -> bytes:
        """Calculate Merkle root from a list of hashes."""
        if not hashes:
            return b'\x00' * 32
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = generate_hash(hashes[i] + hashes[i + 1])
            next_level.append(combined)
        
        return self._merkle_root(next_level)

    @property
    def header(self) -> BlockHeader:
        """Get the block header."""
        return BlockHeader(
            parent_hash=self.parent_hash,
            state_root=self.state_root,
            transactions_root=self.transactions_root,
            height=self.height,
            timestamp=self.timestamp,
            producer=self.producer,
            vrf_proof=self.vrf_proof
        )

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "poh_sequence": self.poh_sequence,
            "height": self.height,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    def get_signing_data(self) -> bytes:
        """Get the data to be signed (the header hash)."""
        return self.header.calculate_hash()

    def sign_block(self, private_key):
        """Sign the block with the producer's private key."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self) -> bool:
        """Verify the block's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.producer,
            self.signature,
            self.get_signing_data()
        )

    @property
    def hash(self) -> bytes:
        """The unique hash identifier of the block."""
        return self.header.calculate_hash()

    @property
    def id(self) -> bytes:
        """The unique hash identifier of the transaction."""
        return generate_hash(self.get_signing_data())

    def validate_basic(self) -> tuple[bool, str]:
        """
        Performs basic validation checks on the transaction.
        Returns (is_valid, error_message)
        """
        # Check signature
        if not self.verify_signature():
            return False, "Invalid signature"
        
        # Check fee is non-negative
        if self.fee < 0:
            return False, "Negative fee"
        
        # Check timestamp is reasonable (not too far in future)
        current_time = time.time()
        if self.timestamp > current_time + 300:  # 5 minutes tolerance
            return False, "Timestamp too far in future"
        
        # Validate transaction type and data
        if self.tx_type == 'TRANSFER':
            if 'to' not in self.data or 'amount' not in self.data:
                return False, "TRANSFER requires 'to' and 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Transfer amount must be positive"
            except Exception:
                return False, "Invalid transfer amount"
                
        elif self.tx_type == 'ATTEST':
            if 'block_hash' not in self.data:
                return False, "ATTEST requires 'block_hash'"
            
        elif self.tx_type == 'PURCHASE':
            if 'usd_amount' not in self.data:
                return False, "PURCHASE requires 'usd_amount'"
            try:
                if int(self.data['usd_amount']) <= 0:
                    return False, "Purchase amount must be positive"
            except Exception:
                return False, "Invalid purchase amount"
            
        elif self.tx_type == 'GAME_FEE':
            if 'game_id' not in self.data or 'score' not in self.data:
                return False, "GAME_FEE requires 'game_id' and 'score'"
            try:
                int(self.data['score'])
            except (ValueError, TypeError):
                return False, "Invalid score format"
                
        elif self.tx_type == 'STAKE':
            if 'amount' not in self.data or 'vrf_pub_key' not in self.data:
                return False, "STAKE requires 'amount' and 'vrf_pub_key'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Stake amount must be positive"
            except Exception:
                return False, "Invalid stake amount"
                
        elif self.tx_type == 'UNSTAKE':
            if 'amount' not in self.data:
                return False, "UNSTAKE requires 'amount'"
            try:
                if int(self.data['amount']) <= 0:
                    return False, "Unstake amount must be positive"
            except Exception:
                return False, "Invalid unstake amount"
                
        elif self.tx_type == 'SLASH':
            if 'header1' not in self.data or 'header2' not in self.data:
                return False, "SLASH requires 'header1' and 'header2'"
        else:
            return False, f"Unknown transaction type: {self.tx_type}"
        
        return True, ""


class BlockHeader:
    """Separate block header for signing and verification."""
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions_root: bytes,
                 height: int,
                 timestamp: float,
                 producer: str,
                 vrf_proof: bytes):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions_root = transactions_root
        self.height = height
        self.timestamp = timestamp
        self.producer = producer
        self.vrf_proof = vrf_proof

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions_root": self.transactions_root,
            "height": self.height,
            "timestamp": self.timestamp,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
        }

    def calculate_hash(self) -> bytes:
        """Calculate the hash of this header."""
        return generate_hash(msgpack.packb(self.to_dict(), use_bin_type=True))


class Block:
    def __init__(self,
                 parent_hash: bytes,
                 state_root: bytes,
                 transactions: list[Transaction],
                 poh_sequence: list[tuple[bytes, bytes | None]],
                 height: int,
                 producer: str,
                 vrf_proof: bytes,
                 timestamp: Optional[float] = None,
                 signature: Optional[bytes] = None):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions = transactions
        self.poh_sequence = poh_sequence
        self.height = height
        self.producer = producer
        self.vrf_proof = vrf_proof
        self.timestamp = timestamp or time.time()
        self.signature = signature
        
        # Calculate transactions root (Merkle root of transaction IDs)
        self.transactions_root = self._calculate_transactions_root()

    def _calculate_transactions_root(self) -> bytes:
        """Calculate Merkle root of transaction IDs."""
        if not self.transactions:
            return b'\x00' * 32
        
        tx_ids = [tx.id for tx in self.transactions]
        return self._merkle_root(tx_ids)
    
    def _merkle_root(self, hashes: list[bytes]) -> bytes:
        """Calculate Merkle root from a list of hashes."""
        if not hashes:
            return b'\x00' * 32
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = generate_hash(hashes[i] + hashes[i + 1])
            next_level.append(combined)
        
        return self._merkle_root(next_level)

    @property
    def header(self) -> BlockHeader:
        """Get the block header."""
        return BlockHeader(
            parent_hash=self.parent_hash,
            state_root=self.state_root,
            transactions_root=self.transactions_root,
            height=self.height,
            timestamp=self.timestamp,
            producer=self.producer,
            vrf_proof=self.vrf_proof
        )

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "poh_sequence": self.poh_sequence,
            "height": self.height,
            "producer": self.producer,
            "vrf_proof": self.vrf_proof,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    def get_signing_data(self) -> bytes:
        """Get the data to be signed (the header hash)."""
        return self.header.calculate_hash()

    def sign_block(self, private_key):
        """Sign the block with the producer's private key."""
        self.signature = sign(private_key, self.get_signing_data())

    def verify_signature(self) -> bool:
        """Verify the block's signature."""
        if not self.signature:
            return False
        return verify_signature(
            self.producer,
            self.signature,
            self.get_signing_data()
        )

    @property
    def hash(self) -> bytes:
        """The unique hash identifier of the block."""
        return self.header.calculate_hash()