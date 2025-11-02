# crypto_v2/upgrade.py
import os
from crypto_v2.proxy import ProxyBlockchain
from crypto_v2.core import Transaction
from crypto_v2.db import DB

# Load DB
DB_PATH = os.path.join(os.path.dirname(__file__), "blockchain.db")
db = DB(DB_PATH)
proxy = ProxyBlockchain(db=db, chain_id=1, initial_logic_address=b"v1.0.0")

# Load admin keys (in prod: from secure vault)
# For demo: re-generate same keys (or save to file)
from crypto_v2.crypto import generate_key_pair, serialize_public_key
admin_keys = [generate_key_pair() for _ in range(3)]
admin_pubkeys = [serialize_public_key(pk) for _, pk in admin_keys]

# Deploy v2
wasm_v2 = os.path.join(os.path.dirname(__file__), "logic_v2.wasm")
if not os.path.exists(wasm_v2):
    raise FileNotFoundError("Compile logic_v2.wat first")

with open(wasm_v2, "rb") as f:
    db.put(b"LOGIC_CODE:v2.0.0", f.read())

# Upgrade tx
tx = Transaction(
    sender_public_key=admin_pubkeys[0],
    tx_type="UPGRADE_LOGIC",
    data={
        "new_logic": b"v2.0.0",
        "multisig_pubkeys": admin_pubkeys,
        "threshold": 2
    },
    nonce=0,
    fee=1000,
    chain_id=1
)
tx.sign(admin_keys[0][0])
tx.sign(admin_keys[1][0])

proxy.upgrade_to(b"v2.0.0", tx)
print("Upgraded to v2.0.0")