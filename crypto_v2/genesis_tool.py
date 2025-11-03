"""
Genesis Block Generation Tool

This script creates the genesis block for the blockchain from a configuration file.
It allows for a transparent and auditable process for setting up the initial
state of the network, including pre-mined accounts, validators, and oracles.
"""
import json
import time
import argparse
from pathlib import Path

from crypto_v2.chain import Blockchain
from crypto_v2.core import Block
from crypto_v2.db import DB
from crypto_v2.trie import Trie
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address
from crypto_v2.chain import TOKEN_UNIT

def create_genesis_block(config_path: str, output_db_path: str):
    """
    Generates the genesis block and initializes the blockchain database.

    Args:
        config_path (str): Path to the genesis configuration JSON file.
        output_db_path (str): Path to store the newly created blockchain database.
    """
    print(f"Loading genesis configuration from: {config_path}")
    with open(config_path, 'r') as f:
        config = json.load(f)

    # Ensure the output directory is clean
    db_path = Path(output_db_path)
    if db_path.exists():
        print(f"Error: Output database path '{db_path}' already exists. Please remove it first.")
        return

    db = DB(str(db_path))
    state_trie = Trie(db)

    # --- 1. Process Pre-mined Accounts ---
    print("Processing pre-mined accounts...")
    for account_info in config.get('pre_mined_accounts', []):
        address = bytes.fromhex(account_info['address'])
        account_state = {
            'balances': {
                'native': int(account_info['balance_native']) * TOKEN_UNIT,
                'usd': int(account_info.get('balance_usd', 0)) * TOKEN_UNIT,
            },
            'nonce': 0,
            'storage': {},
            'vrf_pub_key': None,
        }
        state_trie.set(address, json.dumps(account_state).encode('utf-8'))
    print(f"Processed {len(config.get('pre_mined_accounts', []))} accounts.")

    # --- 2. Process Initial Validators ---
    print("Processing initial validators...")
    validator_set = {}
    for validator_info in config.get('initial_validators', []):
        address = validator_info['address']
        stake = int(validator_info['stake']) * TOKEN_UNIT
        validator_set[address] = stake
    
    state_trie.set(b'validators', json.dumps(validator_set).encode('utf-8'))
    print(f"Processed {len(validator_set)} validators.")

    # --- 3. Process Oracles and Admins ---
    print("Processing oracles and admins...")
    state_trie.set(b'oracles', json.dumps(config.get('oracles', [])).encode('utf-8'))
    state_trie.set(b'admins', json.dumps(config.get('admins', [])).encode('utf-8'))

    # --- 4. Create the Genesis Block ---
    genesis_block = Block(
        parent_hash=b'\x00' * 32,
        state_root=state_trie.root_hash,
        transactions=[],
        poh_sequence=[],
        poh_initial=b'\x00' * 32,
        height=0,
        producer_pubkey=b'genesis',
        vrf_proof=b'genesis',
        vrf_pub_key=b'genesis',
        timestamp=int(time.time()),
        signature=b'genesis_signature'
    )

    # --- 5. Initialize the Blockchain with the Genesis Block ---
    import msgpack
    db.put(b'height:0', genesis_block.hash)
    db.put(b'block:' + genesis_block.hash, msgpack.packb(genesis_block.to_dict(), use_bin_type=True))
    db.put(b'head', genesis_block.hash)
    
    print("\nGenesis block created successfully!")
    print(f"  - Hash: {genesis_block.hash.hex()}")
    print(f"  - State Root: {state_trie.root_hash.hex()}")
    print(f"Blockchain database initialized at: {db_path}")
    
    db.close()

def generate_sample_config(output_path: str):
    """Generates a sample genesis.json configuration file."""
    # Generate some sample keys for demonstration
    priv1, pub1 = generate_key_pair()
    addr1 = public_key_to_address(serialize_public_key(pub1)).hex()

    priv2, pub2 = generate_key_pair()
    addr2 = public_key_to_address(serialize_public_key(pub2)).hex()

    config = {
        "pre_mined_accounts": [
            {"address": addr1, "balance_native": 1000000},
            {"address": addr2, "balance_native": 500000, "balance_usd": 100000}
        ],
        "initial_validators": [
            {"address": addr1, "stake": 50000}
        ],
        "oracles": [addr2],
        "admins": [addr1]
    }

    with open(output_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\nGenerated sample genesis configuration at: {output_path}")
    print("Please review and edit this file before generating the genesis block.")
    print("\nSample private keys (DO NOT USE IN PRODUCTION):")
    print(f"  - Address {addr1}: {priv1.private_bytes(...)}") # Simplified for brevity
    print(f"  - Address {addr2}: {priv2.private_bytes(...)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Genesis Block Generation Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command to generate a sample config
    parser_sample = subparsers.add_parser("sample-config", help="Generate a sample genesis.json")
    parser_sample.add_argument("--output", type=str, default="genesis.json", help="Output file path")

    # Command to create the genesis block
    parser_create = subparsers.add_parser("create", help="Create the genesis block from a config file")
    parser_create.add_argument("--config", type=str, default="genesis.json", help="Path to genesis config file")
    parser_create.add_argument("--output-db", type=str, required=True, help="Path for the new blockchain database")

    args = parser.parse_args()

    if args.command == "sample-config":
        generate_sample_config(args.output)
    elif args.command == "create":
        create_genesis_block(args.config, args.output_db)
