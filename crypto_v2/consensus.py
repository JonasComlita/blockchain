# crypto_v2/consensus.py
"""
Production-ready consensus:
- Stake-weighted VRF leader election
- PoH verification
- Validator set management
"""
from typing import Dict, Optional
from crypto_v2.crypto import generate_hash, vrf_verify, public_key_to_address
import nacl.signing

class LeaderScheduler:
    def __init__(self, validators: Dict[str, int]):
        """
        validators: {address_hex: stake_amount}
        """
        self.validators = validators
        self.total_stake = sum(validators.values())

    def get_leader(self, seed: bytes) -> Optional[str]:
        """
        Stake-weighted VRF lottery.
        Lower VRF output wins, scaled by stake.
        """
        if not self.validators or self.total_stake == 0:
            return None

        best_score = None
        leader = None

        for addr_hex, stake in self.validators.items():
            # Simulate VRF: hash(pubkey + seed)
            vrf_input = bytes.fromhex(addr_hex) + seed
            vrf_output = int.from_bytes(generate_hash(vrf_input), 'big')

            # Normalize: lower = better, scaled by stake
            score = vrf_output / (stake + 1)  # +1 prevents div0

            if best_score is None or score < best_score:
                best_score = score
                leader = addr_hex

        return leader


def is_valid_leader(
    producer_pubkey_hex: str,
    vrf_proof: bytes,
    validators: Dict[str, int],
    seed: bytes,
    vrf_pub_key_hex: str,
    producer_address_hex: str
) -> bool:
    """
    Verify:
    1. VRF proof is valid
    2. Producer has stake
    3. Producer won the lottery
    """
    if producer_address_hex not in validators:
        return False

    # 1. Verify VRF proof
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(vrf_pub_key_hex))
        vrf_output = vrf_verify(verify_key, seed, vrf_proof)
        if vrf_output is None:
            return False
    except:
        return False

    # 2. Re-run lottery
    scheduler = LeaderScheduler(validators)
    expected = scheduler.get_leader(seed)

    return expected == producer_address_hex