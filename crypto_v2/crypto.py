"""
Core cryptographic functions for the blockchain.
"""
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import nacl.signing
import nacl.exceptions

# --- VRF-like functions using PyNaCl ---

def generate_vrf_keypair() -> tuple[nacl.signing.SigningKey, nacl.signing.VerifyKey]:
    """Generates a signing key for our VRF-like system."""
    signing_key = nacl.signing.SigningKey.generate()
    return signing_key, signing_key.verify_key

def vrf_prove(signing_key: nacl.signing.SigningKey, seed: bytes) -> tuple[bytes, bytes]:
    """
    Generates a verifiable random number (the signature) and a proof (the signature).
    In a real VRF, the output and proof are distinct. Here, they are the same.
    """
    signed_message = signing_key.sign(seed)
    return signed_message.signature, generate_hash(signed_message.signature)

def vrf_verify(verify_key, seed, proof):
    """Verify a VRF proof."""
    try:
        # This will raise an exception if verification fails
        verify_key.verify(seed, proof)
        # If it passes, we derive the output hash
        return generate_hash(proof)
    except (nacl.exceptions.BadSignatureError, ValueError):
        # Catch both cryptographic failures and format/length errors
        return None

def generate_hash(data: bytes) -> bytes:
    """Generates a Keccak-256 hash."""
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256, data=data).digest()

def generate_key_pair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generates an ECDSA private/public key pair (SECP256k1)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """Serializes a public key object into PEM format (string)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def deserialize_public_key(pem_data: str) -> ec.EllipticCurvePublicKey:
    """Deserializes a public key from a PEM formatted string."""
    return serialization.load_pem_public_key(pem_data.encode('utf-8'))

def public_key_to_address(public_key_pem: str) -> bytes:
    """Derives a blockchain address from a public key PEM string."""
    public_key = deserialize_public_key(public_key_pem)
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    address_hash = hashlib.sha256(der_bytes).digest()
    return address_hash[:20]

def sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Signs byte data using ECDSA with SHA256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key_pem: str, signature: bytes, data: bytes) -> bool:
    """Verifies an ECDSA/SHA256 signature."""
    try:
        public_key = deserialize_public_key(public_key_pem)
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
