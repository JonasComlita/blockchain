# tests/test_oracle.py
import pytest, json, time, msgpack
from crypto_v2.chain import Blockchain, TOKEN_UNIT, ORACLE_BOND
from crypto_v2.core import Transaction, Block
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address, sign
from crypto_v2.trie import Trie, BLANK_ROOT

@pytest.fixture
def chain():
    from tempfile import mkdtemp
    import shutil
    dir_ = mkdtemp()
    db = __import__("crypto_v2.db").db.DB(dir_)

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
    block_data = msgpack.packb(genesis.to_dict(), use_bin_type=True)
    db.put(b'block:' + genesis.hash, block_data)
    db.put(b'height:0', genesis.hash)
    db.put(b'head', genesis.hash)

    c = Blockchain(db=db, chain_id=1)
    yield c
    db.close()
    shutil.rmtree(dir_)

def make_oracle_tx(chain, priv, pub_pem, type_, data, nonce):
    tx = Transaction(
        sender_public_key=pub_pem,
        tx_type=type_,
        data=data,
        nonce=nonce,
        fee=1000,
        chain_id=1
    )
    tx.sign(priv)
    return tx

def test_oracle_lifecycle(chain):
    # 1. Register 3 oracles
    oracles = []
    oracle_nonces = {}

    for i in range(3):
        priv, pub = generate_key_pair()
        pem = serialize_public_key(pub)
        addr = public_key_to_address(pem)
        
        # Fund account and initialize nonce tracking
        acc = chain._get_account(addr, chain.state_trie)
        acc["balances"]["native"] = 10000 * TOKEN_UNIT
        chain._set_account(addr, acc, chain.state_trie)
        oracle_nonces[pem] = 0
        
        tx = make_oracle_tx(chain, priv, pem, "ORACLE_REGISTER", {}, nonce=oracle_nonces[pem])
        chain._process_transaction(tx, chain.state_trie)
        oracle_nonces[pem] += 1
        
        oracles.append((priv, pem))

    # 2. Admin starts round
    admin_priv, admin_pub = generate_key_pair()
    admin_pem = serialize_public_key(admin_pub)
    admin_addr = public_key_to_address(admin_pem)
    
    # Fund admin and set address
    acc = chain._get_account(admin_addr, chain.state_trie)
    acc["balances"]["native"] = 10000 * TOKEN_UNIT
    chain._set_account(admin_addr, acc, chain.state_trie)
    chain.reserve_admin_address = admin_addr
    admin_nonce = 0

    tx_new = Transaction(
        sender_public_key=admin_pem,
        tx_type="ORACLE_NEW_ROUND",
        data={},
        nonce=admin_nonce,
        fee=1000,
        chain_id=1
    )
    tx_new.sign(admin_priv)
    chain._process_transaction(tx_new, chain.state_trie)
    admin_nonce += 1
    round_id = chain.current_oracle_round

    # 3. Submit price updates
    for i, (priv, pem) in enumerate(oracles):
        payload = {
            "type": "PRICE_UPDATE",
            "round_id": round_id,
                        "oracle_id": chain.oracle_pubkey_to_id[pem],
            "usd_price": 60000000 + i*100000,   # $60k ± $0.1
            "timestamp": int(time.time())
        }
        sig = sign(priv, json.dumps(payload, sort_keys=True).encode())
        
        tx = Transaction(
            sender_public_key=pem,
            tx_type="ORACLE_SUBMIT",
            data={"round_id": round_id,
                  "payload": payload,
                  "signature": sig.hex()},
            nonce=oracle_nonces[pem],
            fee=1000,
            chain_id=1
        )
        tx.sign(priv)
        chain._process_transaction(tx, chain.state_trie)
        oracle_nonces[pem] += 1

    # 4. Verify finalization
    round_obj = chain._get_oracle_round(round_id, chain.state_trie)
    assert round_obj.finalized
    assert round_obj.final_value == 60100000   # median