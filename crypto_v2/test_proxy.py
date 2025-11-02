# tests/test_proxy.py
import pytest
from crypto_v2.proxy import ProxyBlockchain
from crypto_v2.core import Transaction, ValidationError
from crypto_v2.crypto import generate_key_pair, serialize_public_key
from crypto_v2.db import DB

@pytest.fixture
def db():
    db = DB(":memory:")
    yield db
    db.close()

@pytest.fixture
def proxy(db):
    # Deploy logic
    db.put(b"LOGIC_CODE:v1", b"WASM_V1")
    db.put(b"LOGIC_CODE:v2", b"WASM_V2")

    proxy = ProxyBlockchain(db=db, chain_id=1, initial_logic_address=b"v1")

    # Set 2-of-3 admin
    keys = [generate_key_pair() for _ in range(3)]
    pubkeys = [serialize_public_key(pk) for _, pk in keys]
    multisig = proxy._multisig_address(pubkeys, 2)
    db.put(b"PROXY_ADMIN", multisig)
    return proxy, keys, pubkeys

def test_upgrade_with_2_of_3(proxy):
    proxy, keys, pubkeys = proxy

    tx = Transaction(
        sender_public_key=pubkeys[0],
        tx_type="UPGRADE_LOGIC",
        data={
            "new_logic": b"v2",
            "multisig_pubkeys": pubkeys,
            "threshold": 2
        },
        nonce=0,
        fee=1000,
        chain_id=1
    )
    tx.sign(keys[0][0])
    tx.sign(keys[1][0])

    proxy.upgrade_to(b"v2", tx)
    assert proxy.logic_address == b"v2"
    assert db.get(b"PROXY_LOGIC_ADDR") == b"v2"