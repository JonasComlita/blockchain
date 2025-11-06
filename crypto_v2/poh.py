# crypto_v2/poh.py
"""
Production PoH:
- Records ticks + events
- Verifiable in parallel
- Used in block header
"""
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from crypto_v2.crypto import generate_hash

# --- For parallel verification ---
def verify_entry(prev_hash, entry):
    new_hash, event_hash = entry
    if event_hash:
        expected = generate_hash(prev_hash + event_hash)
    else:
        expected = generate_hash(prev_hash)
    return expected == new_hash

class PoHGenerator(threading.Thread):
    def __init__(self, initial_hash: bytes, ticks_per_second: int = 10):
        super().__init__()
        self.recorder = PoHRecorder(initial_hash)
        self.ticks_per_second = ticks_per_second
        self.running = False
        self.lock = threading.Lock()

    def run(self):
        self.running = True
        while self.running:
            self.recorder.tick()
            time.sleep(1 / self.ticks_per_second)

    def stop(self):
        self.running = False

    def record_event(self, event: bytes):
        with self.lock:
            self.recorder.record(event)

    def get_proof(self):
        with self.lock:
            return self.recorder.get_proof()

class PoHRecorder:
    def __init__(self, initial_hash: bytes = b'\x00'*32):
        self.sequence = [(initial_hash, None)]
        self.last_hash = initial_hash

    def record(self, event: bytes):
        event_hash = generate_hash(event)
        new_hash = generate_hash(self.last_hash + event_hash)
        self.sequence.append((new_hash, event_hash))
        self.last_hash = new_hash

    def tick(self):
        new_hash = generate_hash(self.last_hash)
        self.sequence.append((new_hash, None))
        self.last_hash = new_hash

    def get_proof(self):
        return self.sequence, self.last_hash


def verify_poh_sequence(initial_hash: bytes, sequence: list) -> bool:
    """Verify a PoH sequence starting from initial_hash."""
    if not sequence:
        return False
    
    # The sequence should start with a tick/event after initial_hash
    # Verify the first entry connects to initial_hash
    first_entry = sequence[0]
    first_hash, first_event = first_entry
    
    if first_event:
        expected_first = generate_hash(initial_hash + first_event)
    else:
        expected_first = generate_hash(initial_hash)
    
    if expected_first != first_hash:
        return False
    
    # Verify rest of sequence
    if len(sequence) == 1:
        return True
    
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(
            verify_entry,
            [s[0] for s in sequence[:-1]],
            sequence[1:]
        ))
    
    return all(results)
