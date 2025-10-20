"""
Tests for the Proof of History recorder.
"""
import unittest
from crypto_v2.poh import PoHRecorder, verify_poh_sequence
from crypto_v2.crypto import generate_hash

class TestPoH(unittest.TestCase):
    def test_poh_recorder_init(self):
        initial_hash = b'\x00' * 32
        recorder = PoHRecorder(initial_hash)
        self.assertEqual(recorder.last_hash, initial_hash)
        self.assertEqual(len(recorder.sequence), 1)

    def test_poh_tick(self):
        initial_hash = b'\x00' * 32
        recorder = PoHRecorder(initial_hash)
        
        recorder.tick()
        
        expected_hash = generate_hash(initial_hash)
        self.assertEqual(recorder.last_hash, expected_hash)
        self.assertEqual(len(recorder.sequence), 2)

    def test_poh_record(self):
        initial_hash = b'\x00' * 32
        recorder = PoHRecorder(initial_hash)
        
        event = b'my test event'
        recorder.record(event)
        
        event_hash = generate_hash(event)
        expected_hash = generate_hash(initial_hash + event_hash)
        
        self.assertEqual(recorder.last_hash, expected_hash)
        self.assertEqual(len(recorder.sequence), 2)
        self.assertEqual(recorder.sequence[-1][1], event_hash)

    def test_verify_poh_sequence(self):
        initial_hash = b'\x00' * 32
        recorder = PoHRecorder(initial_hash)

        # Add some ticks and events
        recorder.tick()
        recorder.record(b'event 1')
        recorder.tick()
        recorder.record(b'event 2')

        self.assertTrue(verify_poh_sequence(initial_hash, recorder.sequence))

    def test_verify_tampered_poh_sequence(self):
        initial_hash = b'\x00' * 32
        recorder = PoHRecorder(initial_hash)

        recorder.tick()
        recorder.record(b'event 1')
        
        # Tamper with the sequence
        original_hash, event_hash = recorder.sequence[1]
        recorder.sequence[1] = (b'tampered', event_hash)

        self.assertFalse(verify_poh_sequence(initial_hash, recorder.sequence))

if __name__ == '__main__':
    unittest.main()
