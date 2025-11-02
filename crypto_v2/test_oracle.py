# tests/test_oracle.py
import pytest, json, time
from crypto_v2.chain import Blockchain, TOKEN_UNIT, ORACLE_BOND
from crypto_v2.core import Transaction
from crypto_v2.crypto import generate_key_pair, serialize_public_key, public_key_to_address, sign
from crypto_v2.trie import Trie

@pytest.fixture
def chain():
    from tempfile import mkdtemp
    import shutil
    dir_ = mkdtemp()
    db = __import__("crypto_v2.db").db.DB(dir_)
    c = Blockchain(db=db, chain_id=1)
    yield c
    db.close()
    shutil.rmtree(dir_)

def make_oracle_tx(chain, priv, pub_pem, type_, data):
    addr = public_key_to_address(pub_pem)
    acc = chain._get_account(addr, chain.state_trie)
    acc["balances"]["native"] = 10000 * TOKEN_UNIT
    chain._set_account(addr, acc, chain.state_trie)

    tx = Transaction(
        sender_public_key=pub_pem,
        tx_type=type_,
        data=data,
        nonce=0,
        fee=1000,
        chain_id=1
    )
    tx.sign(priv)
    return tx

def test_oracle_lifecycle(chain):
    # 1. Register 3 oracles
    oracles = []
    for i in range(3):
        priv, pub = generate_key_pair()
        pem = serialize_public_key(pub)
        tx = make_oracle_tx(chain, priv, pem, "ORACLE_REGISTER", {})
        chain._process_transaction(tx, chain.state_trie)
        oracles.append((priv, pem))

    # 2. Admin starts round
    admin_priv, admin_pub = generate_key_pair()
    admin_pem = serialize_public_key(admin_pub)
    # fund admin
    acc = chain._get_account(public_key_to_address(admin_pem), chain.state_trie)
    acc["balances"]["native"] = 10000 * TOKEN_UNIT
    chain._set_account(public_key_to_address(admin_pem), acc, chain.state_trie)
    # set admin address (normally done at genesis)
    chain.reserve_admin_address = public_key_to_address(admin_pem)

    tx_new = Transaction(
        sender_public_key=admin_pem,
        tx_type="ORACLE_NEW_ROUND",
        data={},
        nonce=0,
        fee=1000,
        chain_id=1
    )
    tx_new.sign(admin_priv)
    chain._process_transaction(tx_new, chain.state_trie)
    round_id = chain.current_oracle_round

    # 3. Submit price updates
    for i, (priv, pem) in enumerate(oracles):
        payload = {
            "type": "PRICE_UPDATE",
            "round_id": round_id,
            "oracle_id": pem[:16],   # short id
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
            nonce=i+1,
            fee=1000,
            chain_id=1
        )
        tx.sign(priv)
        chain._process_transaction(tx, chain.state_trie)

    # 4. Verify finalization
    round_obj = chain._get_oracle_round(round_id, chain.state_trie)
    assert round_obj.finalized
    assert round_obj.final_value == 60000000   # median