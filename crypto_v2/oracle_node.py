# oracle_node.py
import json, time, requests
from crypto_v2.crypto import sign, serialize_public_key, generate_key_pair
from nacl.bindings import crypto_sign_ed25519_sk_to_pk

class OracleNode:
    def __init__(self, priv_key, oracle_id, price_api="https://api.coingecko.com/api/v3/simple/price"):
        self.priv_key   = priv_key
        self.pub_key    = serialize_public_key(crypto_sign_ed25519_sk_to_pk(priv_key))
        self.oracle_id  = oracle_id
        self.price_api  = price_api

    def _fetch_usd_price(self):
        try:
            r = requests.get(f"{self.price_api}?ids=bitcoin&vs_currencies=usd", timeout=5)
            return int(float(r.json()["bitcoin"]["usd"]) * 1_000_000)
        except Exception:
            return None

    def price_update(self, round_id):
        price = self._fetch_usd_price()
        if price is None:
            return None
        payload = {
            "type": "PRICE_UPDATE",
            "round_id": round_id,
            "oracle_id": self.oracle_id,
            "usd_price": price,
            "timestamp": int(time.time())
        }
        sig = sign(self.priv_key, json.dumps(payload, sort_keys=True).encode())
        return {**payload, "signature": sig.hex()}

    def game_result(self, game_id, round_id, winner, score, reward_usd):
        payload = {
            "type": "GAME_RESULT",
            "round_id": round_id,
            "game_id": game_id,
            "oracle_id": self.oracle_id,
            "winner": winner,
            "score": score,
            "reward_usd": int(reward_usd * 1_000_000),
            "timestamp": int(time.time())
        }
        sig = sign(self.priv_key, json.dumps(payload, sort_keys=True).encode())
        return {**payload, "signature": sig.hex()}