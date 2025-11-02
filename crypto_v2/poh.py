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
    if not sequence or sequence[0][0] != initial_hash:
        return False

    with ThreadPoolExecutor() as executor:
        results = list(executor.map(
            verify_entry,
            [s[0] for s in sequence[:-1]],
            sequence[1:]
        ))

    return all(results)
