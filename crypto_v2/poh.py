"""
A simple Proof of History (PoH) recorder.
"""
import time
from crypto_v2.crypto import generate_hash

class PoHRecorder:
    def __init__(self, initial_hash: bytes):
        self.sequence: list[tuple[bytes, bytes | None]] = [(initial_hash, None)] # (hash, event_hash)
        self.last_hash = initial_hash

    def record(self, event: bytes):
        """
        Records an event by mixing its hash into the sequence.
        This is a simplified model. A real implementation would run this in a tight loop.
        """
        event_hash = generate_hash(event)
        
        # The new hash is the hash of the previous hash plus the event hash
        new_hash = generate_hash(self.last_hash + event_hash)
        
        self.sequence.append((new_hash, event_hash))
        self.last_hash = new_hash

    def tick(self):
        """
        Records the passage of time by hashing the last hash.
        In a real implementation, this would be called continuously in a loop.
        """
        new_hash = generate_hash(self.last_hash)
        self.sequence.append((new_hash, None))
        self.last_hash = new_hash

def verify_poh_sequence(initial_hash: bytes, sequence: list[tuple[bytes, bytes | None]]) -> bool:
    """
    Verifies the integrity of a Proof of History sequence.
    This can be parallelized for high performance.
    """
    current_hash = initial_hash
    for i in range(1, len(sequence)):
        next_hash, event_hash = sequence[i]
        
        if event_hash:
            # This was a recorded event
            expected_hash = generate_hash(current_hash + event_hash)
        else:
            # This was a tick
            expected_hash = generate_hash(current_hash)
            
        if expected_hash != next_hash:
            return False
        
        current_hash = next_hash
        
    return True
