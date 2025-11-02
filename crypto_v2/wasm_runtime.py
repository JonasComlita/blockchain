# crypto_v2/wasm_runtime.py
import wasmtime

class WASMRuntime:
    def __init__(self):
        self.store = wasmtime.Store()
        self.module_cache = {}

    def load(self, wasm_bytes: bytes) -> wasmtime.Module:
        if wasm_bytes not in self.module_cache:
            self.module_cache[wasm_bytes] = wasmtime.Module(self.store.engine, wasm_bytes)
        return self.module_cache[wasm_bytes]

    def instantiate(self, wasm_bytes: bytes, imports: dict):
        module = self.load(wasm_bytes)
        linker = wasmtime.Linker(self.store.engine)
        for name, (func, func_type) in imports.items():
            linker.define("env", name, wasmtime.Func(self.store, func_type, func))
        return linker.instantiate(self.store, module)