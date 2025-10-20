"""
Consensus-related logic, including leader scheduling.
"""
from crypto_v2.crypto import public_key_to_address, vrf_verify, generate_hash
import nacl.signing

class LeaderScheduler:
    def __init__(self, validators: dict, get_account):
        # Validators are {address_hex: stake_amount}
        self.validators = validators
        self.get_account = get_account  # function(address_bytes) -> account dict

    def get_leader(self, seed: bytes) -> str | None:
        """
        Deterministically select a leader based on a seed (e.g., last block hash).
        Uses VRF output (simulated here as hash of (vrf_pub_key + seed)).
        Returns the hex address of the leader.
        """
        if not self.validators:
            return None
        
        lowest_vrf = None
        leader = None

        for address_hex in self.validators:
            address_bytes = bytes.fromhex(address_hex)
            account = self.get_account(address_bytes)
            vrf_pub_key_hex = account.get('vrf_pub_key')
            if not vrf_pub_key_hex:
                continue
            
            # Use the seed in the hash for leader selection
            vrf_input = bytes.fromhex(vrf_pub_key_hex) + seed
            vrf_output = int.from_bytes(generate_hash(vrf_input), 'big')

            if lowest_vrf is None or vrf_output < lowest_vrf:
                lowest_vrf = vrf_output
                leader = address_hex
        
        return leader

def is_valid_leader(producer_pubkey, vrf_proof, validators, seed, vrf_pub_key_hex, producer_address_hex, get_account):
    import nacl.signing
    import nacl.bindings
    # Use the provided VRF pubkey hex
    verify_key = nacl.signing.VerifyKey(bytes.fromhex(vrf_pub_key_hex))
    vrf_output = vrf_verify(verify_key, seed, vrf_proof)
    if vrf_output is None:
        return False # Invalid VRF proof

    # For now, we'll just check that they are the leader according to the simplified get_leader logic.
    scheduler = LeaderScheduler(validators, get_account)
    expected_leader = scheduler.get_leader(seed)

    return producer_address_hex == expected_leader
