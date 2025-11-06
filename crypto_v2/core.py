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

ORACLE_SUBMIT      = "ORACLE_SUBMIT"
ORACLE_REGISTER    = "ORACLE_REGISTER"
ORACLE_UNREGISTER  = "ORACLE_UNREGISTER"
ORACLE_NEW_ROUND   = "ORACLE_NEW_ROUND"

UPGRADE_LOGIC = "UPGRADE_LOGIC"
ATTEST = "ATTEST"
SLASH = "SLASH"

class Transaction:
    def __init__(self,
                 sender_public_key: str,
                 tx_type: str,
                 data: dict,
                 nonce: int,
                 fee: int,
                 signature: Optional[bytes] = None,
                 timestamp: Optional[float] = None,
                 chain_id: Optional[int] = 1,
                 gas_limit: Optional[int] = 1_000_000):  # Replay protection
        self.sender_public_key = sender_public_key
        self.tx_type = tx_type
        self.data = data
        self.nonce = nonce
        self.fee = fee
        self.timestamp = timestamp or time.time()
        self.signature = signature
        self.chain_id = chain_id
        self.gas_limit = gas_limit

    @classmethod
    def from_dict(cls, data: dict):
        """Creates a Transaction object from a dictionary."""
        return cls(
            sender_public_key=data["sender_public_key"],
            tx_type=data["tx_type"],
            data=data["data"],
            nonce=data["nonce"],
            fee=data["fee"],
            signature=bytes.fromhex(data.get("signature")) if data.get("signature") else None,
            timestamp=data.get("timestamp"),
            chain_id=data.get("chain_id"),
            gas_limit=data.get("gas_limit"),
        )

    def to_dict(self, include_signature=True):
        data = {
            "sender_public_key": self.sender_public_key,
            "tx_type": self.tx_type,
            "data": self.data,
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "chain_id": self.chain_id,
            "gas_limit": self.gas_limit,
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
            if not isinstance(self.data.get('amount'), int) or self.data['amount'] <= 0:
                return False, "Transfer amount must be a positive integer"
                
        elif self.tx_type == 'MINT_USD_TOKEN':
            if 'to' not in self.data or 'amount' not in self.data:
                return False, "MINT_USD_TOKEN requires 'to' and 'amount'"
            if not isinstance(self.data.get('amount'), int) or self.data['amount'] <= 0:
                return False, "Mint amount must be a positive integer"

        elif self.tx_type == 'GAME_FEE':
            if 'amount' not in self.data:
                return False, "GAME_FEE requires 'amount'"
            if not isinstance(self.data.get('amount'), int) or self.data['amount'] <= 0:
                return False, "Game fee amount must be a positive integer"

        elif self.tx_type == 'STAKE':
            if 'amount' not in self.data:
                return False, "STAKE requires 'amount'"
            if not isinstance(self.data.get('amount'), int) or self.data['amount'] <= 0:
                return False, "Stake amount must be a positive integer"

        elif self.tx_type == 'UNSTAKE':
            if 'amount' not in self.data:
                return False, "UNSTAKE requires 'amount'"
            if not isinstance(self.data.get('amount'), int) or self.data['amount'] <= 0:
                return False, "Unstake amount must be a positive integer"

        elif self.tx_type == 'BOND_MINT':
            if 'amount_in' not in self.data:
                return False, "BOND_MINT requires 'amount_in'"
            if not isinstance(self.data.get('amount_in'), int) or self.data['amount_in'] <= 0:
                return False, "Bond amount must be a positive integer"

        elif self.tx_type == 'RESERVE_BURN':
            if 'amount_in' not in self.data:
                return False, "RESERVE_BURN requires 'amount_in'"
            if not isinstance(self.data.get('amount_in'), int) or self.data['amount_in'] <= 0:
                return False, "Burn amount must be a positive integer"

        elif self.tx_type == 'DEPLOY_RESERVE_LIQUIDITY':
            # No specific data fields required, just sender verification
            pass

        elif self.tx_type == 'SWAP':
            if 'amount_in' not in self.data or 'token_in' not in self.data or 'min_amount_out' not in self.data:
                return False, "SWAP requires 'amount_in', 'token_in', and 'min_amount_out'"
            if self.data['token_in'] not in ['native', 'usd']:
                return False, "Invalid token_in for swap"
            if not isinstance(self.data.get('amount_in'), int) or self.data['amount_in'] <= 0:
                return False, "Swap amount_in must be a positive integer"
            if not isinstance(self.data.get('min_amount_out'), int) or self.data['min_amount_out'] < 0:
                return False, "Swap min_amount_out must be a non-negative integer"

        elif self.tx_type == 'ADD_LIQUIDITY':
            if 'native_amount' not in self.data or 'usd_amount' not in self.data:
                return False, "ADD_LIQUIDITY requires 'native_amount' and 'usd_amount'"
            if not isinstance(self.data.get('native_amount'), int) or self.data['native_amount'] <= 0:
                return False, "Native amount must be a positive integer"
            if not isinstance(self.data.get('usd_amount'), int) or self.data['usd_amount'] <= 0:
                return False, "USD amount must be a positive integer"

        elif self.tx_type == 'REMOVE_LIQUIDITY':
            if 'lp_amount' not in self.data:
                return False, "REMOVE_LIQUIDITY requires 'lp_amount'"
            if not isinstance(self.data.get('lp_amount'), int) or self.data['lp_amount'] <= 0:
                return False, "LP amount must be a positive integer"

        elif self.tx_type == 'UPDATE_MULTISIG_CONFIG':
            if 'required_sigs' not in self.data or 'authorized_signers' not in self.data:
                return False, "UPDATE_MULTISIG_CONFIG requires 'required_sigs' and 'authorized_signers'"
            if not isinstance(self.data.get('required_sigs'), int) or self.data['required_sigs'] <= 0:
                return False, "required_sigs must be a positive integer"
            if not isinstance(self.data.get('authorized_signers'), list):
                return False, "authorized_signers must be a list"

        elif self.tx_type == 'SLASH':
            if 'validator_address' not in self.data:
                return False, "SLASH requires 'validator_address'"
                
        elif self.tx_type in (
            "ORACLE_SUBMIT", "ORACLE_REGISTER",
            "ORACLE_UNREGISTER_REQUEST", "ORACLE_UNREGISTER_EXECUTE",
            "ORACLE_NEW_ROUND"
        ):
            # Validation for these is handled more deeply in the chain logic
            pass
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
                 producer_pubkey: bytes,
                 vrf_proof: bytes,
                 vrf_pub_key: bytes):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions_root = transactions_root
        self.height = height
        self.timestamp = timestamp
        self.producer_pubkey = producer_pubkey.encode('utf-8') if isinstance(producer_pubkey, str) else producer_pubkey
        self.vrf_proof = vrf_proof
        self.vrf_pub_key = vrf_pub_key

    @classmethod
    def from_dict(cls, data: dict):
        """Creates a BlockHeader object from a dictionary."""
        return cls(
            parent_hash=bytes.fromhex(data["parent_hash"]),
            state_root=bytes.fromhex(data["state_root"]),
            transactions_root=bytes.fromhex(data["transactions_root"]),
            height=data["height"],
            timestamp=data["timestamp"],
            producer_pubkey=bytes.fromhex(data["producer_pubkey"]),
            vrf_proof=bytes.fromhex(data["vrf_proof"]),
            vrf_pub_key=bytes.fromhex(data["vrf_pub_key"]),
        )

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash.hex(),
            "state_root": self.state_root.hex(),
            "transactions_root": self.transactions_root.hex(),
            "height": self.height,
            "timestamp": self.timestamp,
            "producer_pubkey": self.producer_pubkey.hex() if self.producer_pubkey else None,
            "vrf_proof": self.vrf_proof.hex() if self.vrf_proof else None,
            "vrf_pub_key": self.vrf_pub_key.hex() if self.vrf_pub_key else None,
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
                 producer_pubkey: bytes,
                 vrf_proof: bytes,
                 vrf_pub_key: bytes,
                 poh_initial: bytes,
                 timestamp: Optional[float] = None,
                 signature: Optional[bytes] = None,
                 attestations: Optional[list] = None):
        
        self.parent_hash = parent_hash
        self._state_root = state_root
        self._transactions = transactions
        self.poh_sequence = poh_sequence
        self.poh_initial = poh_initial
        self.height = height

        # Producer identification
        self.producer_pubkey = producer_pubkey
        
        # VRF fields
        self.vrf_proof = vrf_proof
        self.vrf_pub_key = vrf_pub_key
        
        # Finality
        self.attestations = attestations or []

        self.timestamp = timestamp or time.time()
        self.transactions_root = self._calculate_transactions_root()
        self.signature = signature
        
        self._cached_header = None
        self._cached_hash = None

    @property
    def transactions(self):
        return self._transactions

    @property
    def state_root(self):
        return self._state_root

    @state_root.setter
    def state_root(self, value):
        self._state_root = value
        self._cached_header = None
        self._cached_hash = None

    @transactions.setter
    def transactions(self, value):
        self._transactions = value
        self._cached_header = None
        self._cached_hash = None
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
        if not self._cached_header:
            self._cached_header = BlockHeader(
                parent_hash=self.parent_hash,
                state_root=self._state_root,
                transactions_root=self.transactions_root,
                height=self.height,
                timestamp=self.timestamp,
                producer_pubkey=self.producer_pubkey,
                vrf_proof=self.vrf_proof,
                vrf_pub_key=self.vrf_pub_key
            )
        return self._cached_header

    def to_dict(self):
        return {
            "parent_hash": self.parent_hash.hex(),
            "state_root": self.state_root.hex(),
            "transactions": [tx.to_dict() for tx in self.transactions],
            "attestations": self.attestations,
            "poh_sequence": [(h.hex(), e.hex() if e else None) for h, e in self.poh_sequence],
            "poh_initial": self.poh_initial.hex(),
            "height": self.height,
            "producer_pubkey": self.producer_pubkey.hex() if self.producer_pubkey else None,
            "vrf_proof": self.vrf_proof.hex() if self.vrf_proof else None,
            "vrf_pub_key": self.vrf_pub_key.hex() if self.vrf_pub_key else None,
            "timestamp": self.timestamp,
            "signature": self.signature.hex() if self.signature else None,
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
            self.producer_pubkey,
            self.signature,
            self.get_signing_data()
        )

    @property
    def hash(self) -> bytes:
        """The unique hash identifier of the block."""
        if not self._cached_hash:
            self._cached_hash = self.header.calculate_hash()
        return self._cached_hash
