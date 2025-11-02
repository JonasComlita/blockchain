# crypto_v2/deploy.py
"""
Deploy:
1. Open (or create) DB
2. Generate 3 admin keys
3. Upload logic_v1.wasm
4. Deploy Proxy
5. Register 2-of-3 multisig admin
"""
import os
from crypto_v2.proxy import ProxyBlockchain
from crypto_v2.db import DB
from crypto_v2.crypto import generate_key_pair, serialize_public_key

# ------------------------------------------------------------------ #
# 1. DB
# ------------------------------------------------------------------ #
DB_PATH = os.path.join(os.path.dirname(__file__), "blockchain.db")
db = DB(DB_PATH)

# ------------------------------------------------------------------ #
# 2. Admin keys (2-of-3)
# ------------------------------------------------------------------ #
admin_keys = [generate_key_pair() for _ in range(3)]
admin_pubkeys = [serialize_public_key(pk) for _, pk in admin_keys]

# ------------------------------------------------------------------ #
# 3. Deploy logic v1 (WASM)
# ------------------------------------------------------------------ #
logic_v1_addr = b"v1.0.0"
wasm_path = os.path.join(os.path.dirname(__file__), "logic_v1.wasm")

if not os.path.exists(wasm_path):
    raise FileNotFoundError(f"Compile logic first: wat2wasm logic_v1.wat -o {wasm_path}")

with open(wasm_path, "rb") as f:
    wasm_bytes = f.read()

db.put(b"LOGIC_CODE:" + logic_v1_addr, wasm_bytes)
print(f"Uploaded logic v1 → {len(wasm_bytes)} bytes")

# ------------------------------------------------------------------ #
# 4. Deploy proxy
# ------------------------------------------------------------------ #
proxy = ProxyBlockchain(db=db, chain_id=1, initial_logic_address=logic_v1_addr)

# ------------------------------------------------------------------ #
# 5. Set 2-of-3 multisig admin
# ------------------------------------------------------------------ #
multisig_addr = proxy._multisig_address(admin_pubkeys, threshold=2)
db.put(b"PROXY_ADMIN", multisig_addr)

print(f"Proxy deployed!")
print(f"   Admin multisig: {multisig_addr.hex()}")
print(f"   Pubkeys: {[p.hex()[:16]+'...' for p in admin_pubkeys]}")
print(f"   DB: {DB_PATH}")