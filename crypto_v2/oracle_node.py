# oracle_node.py
import time
import requests
import msgpack
from crypto_v2.crypto import sign, get_public_key
from crypto_v2.core import Transaction

class OracleNode:
    def __init__(self, priv_key, price_api="https://api.coingecko.com/api/v3/simple/price"):
        self.priv_key   = priv_key
        self.pub_key    = get_public_key(priv_key)
        self.price_api  = price_api

    def _fetch_usd_price(self):
        try:
            r = requests.get(f"{self.price_api}?ids=bitcoin&vs_currencies=usd", timeout=5)
            return int(float(r.json()["bitcoin"]["usd"]) * 1_000_000)
        except Exception:
            return None

    def create_oracle_submission(self, round_id, value_type, value):
        """Creates a signed oracle submission transaction."""
        tx_data = {
            'type': 'ORACLE_SUBMIT',
            'round_id': round_id,
            'value_type': value_type, # e.g., 'USD_PRICE' or 'GAME_RESULT'
            'value': value,
        }
        tx = Transaction(
            sender_pubkey=self.pub_key,
            data=tx_data,
            nonce=int(time.time() * 1000), # Nonce needs to be unique
            gas_limit=50000,
            signature=b''
        )
        tx.sign(self.priv_key)
        return tx

    def price_update(self, round_id):
        price = self._fetch_usd_price()
        if price is None:
            return None
        
        return self.create_oracle_submission(round_id, 'USD_PRICE', price)

    def game_result(self, game_id, round_id, winner, score, reward_usd):
        game_data = {
            "game_id": game_id,
            "winner": winner,
            "score": score,
            "reward_usd": int(reward_usd * 1_000_000),
        }
        return self.create_oracle_submission(round_id, 'GAME_RESULT', game_data)