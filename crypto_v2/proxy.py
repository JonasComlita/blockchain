# crypto_v2/proxy.py
"""
Proxy contract with:
- Persistent logic address
- WASM sandbox
- 2-of-3 multisig admin
"""
from __future__ import annotations

import hashlib
from typing import List

from .chain import Blockchain, RESERVE_ADMIN_ADDRESS, ValidationError
from .core import Transaction
from .crypto import public_key_to_address, verify_signature
from .wasm_runtime import WASMRuntime
from wasmtime import FuncType, ValType


class ProxyBlockchain:
    def __init__(self, db, chain_id: int, initial_logic_address: bytes):
        self.db = db
        self.chain = Blockchain(db=db, chain_id=chain_id)
        self.wasm_runtime = WASMRuntime()
        self.logic_address = initial_logic_address
        self.logic_instance = None
        self._load_logic()

    def _get_db(self, key: bytes) -> bytes:
        return self.db.get(key)

    def _set_db(self, key: bytes, value: bytes):
        self.db.put(key, value)

    def _load_logic(self):
        wasm_bytes = self.db.get(b"LOGIC_CODE:" + self.logic_address)
        if not wasm_bytes:
            raise ValueError("Logic code not found")

        imports = {
            "get_db": (self._get_db, FuncType([ValType.i32, ValType.i32], [ValType.i32])),
            "set_db": (self._set_db, FuncType([ValType.i32, ValType.i32, ValType.i32, ValType.i32], [])),
        }
        instance = self.wasm_runtime.instantiate(wasm_bytes, imports)
        self.logic_instance = instance


class ProxyBlockchain:
    def __init__(self, db, chain_id: int, initial_logic_address: bytes):
        self.db = db
        self.chain_id = chain_id
        self.wasm_runtime = WASMRuntime()
        self._logic_instance = None

        # Persist logic address
        self.logic_address = db.get(b"PROXY_LOGIC_ADDR")
        if not self.logic_address:
            self.logic_address = initial_logic_address
            db.put(b"PROXY_LOGIC_ADDR", self.logic_address)

        self._load_logic()

    def _load_logic(self):
        code_key = b"LOGIC_CODE:" + self.logic_address
        wasm_bytes = self.db.get(code_key)
        if not wasm_bytes:
            raise RuntimeError(f"Logic code missing: {self.logic_address.hex()}")

        imports = {
            "get_state": lambda key: self.db.get(key) or b"",
            "set_state": lambda key, value: self.db.put(key, value),
            "log": lambda ptr, len_: print("[WASM]", self._read_memory(ptr, len_))
        }
        instance = self.wasm_runtime.instantiate(wasm_bytes, imports)
        self._logic_instance = instance.exports

    def _read_memory(self, ptr: int, len_: int) -> bytes:
        # Simplified: real impl reads from WASM memory
        return b"<msg>"

    # ------------------------------------------------------------------ #
    # Multisig helpers
    # ------------------------------------------------------------------ #
    def _multisig_address(self, pubkeys: List[bytes], threshold: int) -> bytes:
        data = b"".join(sorted(pubkeys)) + threshold.to_bytes(1, "big")
        return hashlib.sha256(b"MULTISIG:" + data).digest()[-20:]

    def _verify_multisig(self, tx: Transaction) -> bool:
        admin_addr = self.db.get(b"PROXY_ADMIN")
        if not admin_addr:
            return False

        # Extract from tx.data
        pubkeys = tx.data.get("multisig_pubkeys", [])
        threshold = tx.data.get("threshold", 2)

        if not pubkeys or not isinstance(threshold, int):
            return False

        expected = self._multisig_address(pubkeys, threshold)
        if expected != admin_addr:
            return False

        msg = tx.hash()
        valid_sigs = 0
        for sig, pub in getattr(tx, "signatures", []):
            if verify_signature(pub, sig, msg):
                valid_sigs += 1
        return valid_sigs >= threshold

    # ------------------------------------------------------------------ #
    # Upgrade
    # ------------------------------------------------------------------ #
    def upgrade_to(self, new_logic_address: bytes, admin_tx: Transaction):
        if not self._verify_multisig(admin_tx):
            raise ValidationError("Invalid multisig authorization")

        code_key = b"LOGIC_CODE:" + new_logic_address
        if not self.db.get(code_key):
            raise ValidationError("Logic code not deployed")

        self.logic_address = new_logic_address
        self.db.put(b"PROXY_LOGIC_ADDR", new_logic_address)
        self._load_logic()

    # ------------------------------------------------------------------ #
    # Delegation
    # ------------------------------------------------------------------ #
    def __getattr__(self, name):
        if self._logic_instance is None:
            raise RuntimeError("Logic not loaded")
        return getattr(self._logic_instance, name)