# crypto_v2/setup.py
from setuptools import setup, find_packages

setup(
    name="crypto_v2",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "wasmtime",        # WASM runtime
        "msgpack",         # for trie
        "PyNaCl",          # ed25519
        "psutil",          # monitoring
    ],
)