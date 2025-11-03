# generate_keys.py
import os
import pickle
from crypto_v2.crypto import generate_key_pair, generate_vrf_keypair, serialize_public_key, public_key_to_address

from cryptography.hazmat.primitives import serialization

# --- Validator Key ---
print("--- Generating Validator Key (for Node 0) ---")
val_priv_key, val_pub_key = generate_key_pair()
val_vrf_priv, val_vrf_pub = generate_vrf_keypair()

# The node expects keys in a pickled tuple format
validator_keys = (
    val_priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ),
    val_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
    val_vrf_priv,
    val_vrf_pub
)
os.makedirs("validator_keys", exist_ok=True)
with open("validator_keys/validator_keys.pkl", "wb") as f:
    pickle.dump(validator_keys, f)

val_pub_pem = serialize_public_key(val_pub_key)
val_address = public_key_to_address(val_pub_pem)
print(f"  Validator Address: {val_address.hex()}")
print("  Saved validator keys to: validator_keys/validator_keys.pkl\n")


# --- Oracle Keys ---
print("--- Generating 3 Oracle Keys ---")
oracle_keys = []
for i in range(3):
    oracle_priv, oracle_pub = generate_key_pair()
    oracle_pub_pem = serialize_public_key(oracle_pub)
    oracle_address = public_key_to_address(oracle_pub_pem)
    
    # Save private key to a file
    key_filename = f"oracle_{i}_priv.key"
    with open(key_filename, "wb") as f:
        f.write(oracle_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    oracle_keys.append({
        "address": oracle_address.hex(),
        "pub_key": oracle_pub_pem.decode('utf-8'),
        "priv_key_file": key_filename
    })
    print(f"  Oracle {i}:")
    print(f"    Address: {oracle_address.hex()}")
    print(f"    Saved private key to: {key_filename}")

# You will need these addresses for the genesis.json file
print("\n--- Addresses for genesis.json ---")
print(f"Validator Address: {val_address.hex()}")
for i, key_info in enumerate(oracle_keys):
    print(f"Oracle {i} Address:  {key_info['address']}")
