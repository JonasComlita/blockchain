"""
Comprehensive tests for Merkle Patricia Trie implementation and encoding utilities.
"""
import unittest
import tempfile
import shutil
from crypto_v2.utils.encoding import hex_prefix_encode, hex_prefix_decode, bytes_to_nibbles
from crypto_v2.trie import Trie, BLANK_ROOT
from crypto_v2.db import DB


class TestHexPrefixEncoding(unittest.TestCase):
    def test_extension_node_even_length(self):
        """Test encoding extension node with even-length path."""
        path = (0, 1, 2, 3, 4, 5)
        encoded = hex_prefix_encode(path, is_leaf=False)
        
        decoded_path, is_leaf = hex_prefix_decode(encoded)
        
        self.assertEqual(decoded_path, path)
        self.assertFalse(is_leaf)

    def test_extension_node_odd_length(self):
        """Test encoding extension node with odd-length path."""
        path = (1, 2, 3, 4, 5)
        encoded = hex_prefix_encode(path, is_leaf=False)
        
        decoded_path, is_leaf = hex_prefix_decode(encoded)
        
        self.assertEqual(decoded_path, path)
        self.assertFalse(is_leaf)

    def test_leaf_node_even_length(self):
        """Test encoding leaf node with even-length path."""
        path = (0, 1, 2, 3)
        encoded = hex_prefix_encode(path, is_leaf=True)
        
        decoded_path, is_leaf = hex_prefix_decode(encoded)
        
        self.assertEqual(decoded_path, path)
        self.assertTrue(is_leaf)

    def test_leaf_node_odd_length(self):
        """Test encoding leaf node with odd-length path."""
        path = (1, 2, 3)
        encoded = hex_prefix_encode(path, is_leaf=True)
        
        decoded_path, is_leaf = hex_prefix_decode(encoded)
        
        self.assertEqual(decoded_path, path)
        self.assertTrue(is_leaf)

    def test_empty_path(self):
        """Test encoding empty path."""
        path = ()
        encoded = hex_prefix_encode(path, is_leaf=False)
        
        decoded_path, is_leaf = hex_prefix_decode(encoded)
        
        self.assertEqual(decoded_path, path)
        self.assertFalse(is_leaf)

    def test_single_nibble(self):
        """Test encoding single nibble path."""
        path = (5,)
        encoded = hex_prefix_encode(path, is_leaf=True)
        
        decoded_path, is_leaf = hex_prefix_decode(encoded)
        
        self.assertEqual(decoded_path, path)
        self.assertTrue(is_leaf)

    def test_bytes_to_nibbles(self):
        """Test conversion from bytes to nibbles."""
        data = b'\x12\x34\x56'
        nibbles = bytes_to_nibbles(data)
        
        expected = (1, 2, 3, 4, 5, 6)
        self.assertEqual(nibbles, expected)

    def test_bytes_to_nibbles_zeros(self):
        """Test conversion with zero bytes."""
        data = b'\x00\x0f\xf0'
        nibbles = bytes_to_nibbles(data)
        
        expected = (0, 0, 0, 15, 15, 0)
        self.assertEqual(nibbles, expected)


class TestTrieBasicOperations(unittest.TestCase):
    def setUp(self):
        """Set up test database and trie."""
        self.test_dir = tempfile.mkdtemp()
        self.db = DB(self.test_dir)
        self.trie = Trie(self.db)

    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_initial_state(self):
        """Test trie initialization."""
        self.assertEqual(self.trie.root_hash, BLANK_ROOT)
        self.assertIsNone(self.trie.get(b'any_key'))

    def test_set_single_value(self):
        """Test setting a single key-value pair."""
        self.trie.set(b'key1', b'value1')
        
        self.assertNotEqual(self.trie.root_hash, BLANK_ROOT)
        self.assertEqual(self.trie.get(b'key1'), b'value1')

    def test_set_and_update(self):
        """Test updating an existing key."""
        self.trie.set(b'key1', b'value1')
        initial_root = self.trie.root_hash
        
        self.trie.set(b'key1', b'value2')
        updated_root = self.trie.root_hash
        
        self.assertNotEqual(initial_root, updated_root)
        self.assertEqual(self.trie.get(b'key1'), b'value2')

    def test_multiple_keys(self):
        """Test setting multiple different keys."""
        keys_values = [
            (b'key1', b'value1'),
            (b'key2', b'value2'),
            (b'key3', b'value3'),
        ]
        
        for key, value in keys_values:
            self.trie.set(key, value)
        
        for key, value in keys_values:
            self.assertEqual(self.trie.get(key), value)

    def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist."""
        self.trie.set(b'existing_key', b'value')
        
        self.assertIsNone(self.trie.get(b'nonexistent_key'))

    def test_empty_value(self):
        """Test storing empty value."""
        self.trie.set(b'key', b'')
        self.assertEqual(self.trie.get(b'key'), b'')

    def test_binary_data(self):
        """Test storing binary data."""
        binary_value = bytes(range(256))
        self.trie.set(b'binary_key', binary_value)
        
        self.assertEqual(self.trie.get(b'binary_key'), binary_value)


class TestTrieNodeSplitting(unittest.TestCase):
    def setUp(self):
        """Set up test database and trie."""
        self.test_dir = tempfile.mkdtemp()
        self.db = DB(self.test_dir)
        self.trie = Trie(self.db)

    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_simple_branch_creation(self):
        """Test creation of a branch node."""
        self.trie.set(b'do', b'verb')
        self.trie.set(b'dog', b'puppy')
        
        self.assertEqual(self.trie.get(b'do'), b'verb')
        self.assertEqual(self.trie.get(b'dog'), b'puppy')

    def test_extension_node_creation(self):
        """Test creation of extension nodes."""
        self.trie.set(b'dog', b'puppy')
        self.trie.set(b'dodge', b'coin')
        
        self.assertEqual(self.trie.get(b'dog'), b'puppy')
        self.assertEqual(self.trie.get(b'dodge'), b'coin')

    def test_complex_tree_structure(self):
        """Test building a complex trie structure."""
        data = [
            (b'do', b'verb'),
            (b'dog', b'puppy'),
            (b'doge', b'coin'),
            (b'horse', b'stallion'),
        ]
        
        for key, value in data:
            self.trie.set(key, value)
        
        for key, value in data:
            self.assertEqual(self.trie.get(key), value)

    def test_prefix_keys(self):
        """Test keys that are prefixes of each other."""
        self.trie.set(b'a', b'1')
        self.trie.set(b'ab', b'2')
        self.trie.set(b'abc', b'3')
        self.trie.set(b'abcd', b'4')
        
        self.assertEqual(self.trie.get(b'a'), b'1')
        self.assertEqual(self.trie.get(b'ab'), b'2')
        self.assertEqual(self.trie.get(b'abc'), b'3')
        self.assertEqual(self.trie.get(b'abcd'), b'4')

    def test_similar_keys(self):
        """Test keys with shared prefixes."""
        keys = [
            b'apple',
            b'application',
            b'apply',
            b'approve',
        ]
        
        for i, key in enumerate(keys):
            self.trie.set(key, str(i).encode())
        
        for i, key in enumerate(keys):
            self.assertEqual(self.trie.get(key), str(i).encode())


class TestTriePersistence(unittest.TestCase):
    def setUp(self):
        """Set up test database."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test database."""
        shutil.rmtree(self.test_dir)

    def test_persistence_across_instances(self):
        """Test that trie data persists across instances."""
        # Create and populate trie
        db1 = DB(self.test_dir)
        trie1 = Trie(db1)
        
        trie1.set(b'key1', b'value1')
        trie1.set(b'key2', b'value2')
        root_hash = trie1.root_hash
        
        db1.close()
        
        # Reopen and verify
        db2 = DB(self.test_dir)
        trie2 = Trie(db2, root_hash=root_hash)
        
        self.assertEqual(trie2.get(b'key1'), b'value1')
        self.assertEqual(trie2.get(b'key2'), b'value2')
        
        db2.close()

    def test_multiple_trie_versions(self):
        """Test maintaining multiple trie versions."""
        db = DB(self.test_dir)
        
        # Create first version
        trie1 = Trie(db)
        trie1.set(b'key1', b'value1')
        root1 = trie1.root_hash
        
        # Create second version
        trie2 = Trie(db, root_hash=root1)
        trie2.set(b'key2', b'value2')
        root2 = trie2.root_hash
        
        # Verify both versions are accessible
        trie_v1 = Trie(db, root_hash=root1)
        self.assertEqual(trie_v1.get(b'key1'), b'value1')
        self.assertIsNone(trie_v1.get(b'key2'))
        
        trie_v2 = Trie(db, root_hash=root2)
        self.assertEqual(trie_v2.get(b'key1'), b'value1')
        self.assertEqual(trie_v2.get(b'key2'), b'value2')
        
        db.close()


class TestTrieRootHash(unittest.TestCase):
    def setUp(self):
        """Set up test database and trie."""
        self.test_dir = tempfile.mkdtemp()
        self.db = DB(self.test_dir)

    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_deterministic_root_hash(self):
        """Test that same data produces same root hash."""
        trie1 = Trie(self.db)
        trie1.set(b'key1', b'value1')
        trie1.set(b'key2', b'value2')
        root1 = trie1.root_hash
        
        trie2 = Trie(self.db)
        trie2.set(b'key1', b'value1')
        trie2.set(b'key2', b'value2')
        root2 = trie2.root_hash
        
        self.assertEqual(root1, root2)

    def test_insertion_order_independence(self):
        """Test that insertion order doesn't affect root hash."""
        trie1 = Trie(self.db)
        trie1.set(b'a', b'1')
        trie1.set(b'b', b'2')
        trie1.set(b'c', b'3')
        root1 = trie1.root_hash
        
        trie2 = Trie(self.db)
        trie2.set(b'c', b'3')
        trie2.set(b'a', b'1')
        trie2.set(b'b', b'2')
        root2 = trie2.root_hash
        
        self.assertEqual(root1, root2)

    def test_root_hash_changes_on_update(self):
        """Test that root hash changes when data is updated."""
        trie = Trie(self.db)
        trie.set(b'key', b'value1')
        root1 = trie.root_hash
        
        trie.set(b'key', b'value2')
        root2 = trie.root_hash
        
        self.assertNotEqual(root1, root2)

    def test_root_hash_changes_on_addition(self):
        """Test that root hash changes when keys are added."""
        trie = Trie(self.db)
        root0 = trie.root_hash
        
        trie.set(b'key1', b'value1')
        root1 = trie.root_hash
        
        trie.set(b'key2', b'value2')
        root2 = trie.root_hash
        
        self.assertNotEqual(root0, root1)
        self.assertNotEqual(root1, root2)


class TestTrieEdgeCases(unittest.TestCase):
    def setUp(self):
        """Set up test database and trie."""
        self.test_dir = tempfile.mkdtemp()
        self.db = DB(self.test_dir)
        self.trie = Trie(self.db)

    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_very_long_key(self):
        """Test with very long key."""
        long_key = b'x' * 1000
        value = b'long_key_value'
        
        self.trie.set(long_key, value)
        self.assertEqual(self.trie.get(long_key), value)

    def test_very_long_value(self):
        """Test with very long value."""
        key = b'key'
        long_value = b'y' * 10000
        
        self.trie.set(key, long_value)
        self.assertEqual(self.trie.get(key), long_value)

    def test_single_byte_keys(self):
        """Test with single byte keys (all possible values)."""
        for i in range(256):
            key = bytes([i])
            value = f'value_{i}'.encode()
            self.trie.set(key, value)
        
        for i in range(256):
            key = bytes([i])
            value = f'value_{i}'.encode()
            self.assertEqual(self.trie.get(key), value)

    def test_identical_key_different_casing(self):
        """Test keys that differ only in casing (bytes are different)."""
        self.trie.set(b'Key', b'value1')
        self.trie.set(b'key', b'value2')
        self.trie.set(b'KEY', b'value3')
        
        self.assertEqual(self.trie.get(b'Key'), b'value1')
        self.assertEqual(self.trie.get(b'key'), b'value2')
        self.assertEqual(self.trie.get(b'KEY'), b'value3')

    def test_null_byte_in_key(self):
        """Test keys containing null bytes."""
        key = b'key\x00with\x00nulls'
        value = b'value'
        
        self.trie.set(key, value)
        self.assertEqual(self.trie.get(key), value)

    def test_many_keys_with_common_prefix(self):
        """Test many keys sharing a common prefix."""
        prefix = b'common_prefix_'
        
        for i in range(100):
            key = prefix + str(i).encode()
            value = f'value_{i}'.encode()
            self.trie.set(key, value)
        
        for i in range(100):
            key = prefix + str(i).encode()
            value = f'value_{i}'.encode()
            self.assertEqual(self.trie.get(key), value)

    def test_overwrite_many_times(self):
        """Test overwriting the same key many times."""
        key = b'key'
        
        for i in range(100):
            value = f'value_{i}'.encode()
            self.trie.set(key, value)
        
        self.assertEqual(self.trie.get(key), b'value_99')


class TestTrieStateVerification(unittest.TestCase):
    def setUp(self):
        """Set up test database and trie."""
        self.test_dir = tempfile.mkdtemp()
        self.db = DB(self.test_dir)

    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_merkle_proof_concept(self):
        """Test that different states have different root hashes."""
        # State 1: Empty
        trie1 = Trie(self.db)
        root1 = trie1.root_hash
        
        # State 2: One key
        trie2 = Trie(self.db)
        trie2.set(b'key1', b'value1')
        root2 = trie2.root_hash
        
        # State 3: Two keys
        trie3 = Trie(self.db)
        trie3.set(b'key1', b'value1')
        trie3.set(b'key2', b'value2')
        root3 = trie3.root_hash
        
        # All roots should be different
        self.assertNotEqual(root1, root2)
        self.assertNotEqual(root2, root3)
        self.assertNotEqual(root1, root3)

    def test_state_rollback(self):
        """Test rolling back to a previous state."""
        trie = Trie(self.db)
        
        # Create checkpoint
        trie.set(b'key1', b'value1')
        checkpoint_root = trie.root_hash
        
        # Make more changes
        trie.set(b'key2', b'value2')
        trie.set(b'key3', b'value3')
        
        # Rollback to checkpoint
        trie_restored = Trie(self.db, root_hash=checkpoint_root)
        
        self.assertEqual(trie_restored.get(b'key1'), b'value1')
        self.assertIsNone(trie_restored.get(b'key2'))
        self.assertIsNone(trie_restored.get(b'key3'))

    def test_parallel_state_branches(self):
        """Test maintaining parallel state branches."""
        # Create base state
        base_trie = Trie(self.db)
        base_trie.set(b'base_key', b'base_value')
        base_root = base_trie.root_hash
        
        # Branch 1
        branch1 = Trie(self.db, root_hash=base_root)
        branch1.set(b'branch1_key', b'branch1_value')
        root1 = branch1.root_hash
        
        # Branch 2
        branch2 = Trie(self.db, root_hash=base_root)
        branch2.set(b'branch2_key', b'branch2_value')
        root2 = branch2.root_hash
        
        # Verify branches are independent
        self.assertNotEqual(root1, root2)
        
        # Verify branch 1
        verify1 = Trie(self.db, root_hash=root1)
        self.assertEqual(verify1.get(b'base_key'), b'base_value')
        self.assertEqual(verify1.get(b'branch1_key'), b'branch1_value')
        self.assertIsNone(verify1.get(b'branch2_key'))
        
        # Verify branch 2
        verify2 = Trie(self.db, root_hash=root2)
        self.assertEqual(verify2.get(b'base_key'), b'base_value')
        self.assertIsNone(verify2.get(b'branch1_key'))
        self.assertEqual(verify2.get(b'branch2_key'), b'branch2_value')


class TestTriePerformance(unittest.TestCase):
    def setUp(self):
        """Set up test database and trie."""
        self.test_dir = tempfile.mkdtemp()
        self.db = DB(self.test_dir)
        self.trie = Trie(self.db)

    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_large_dataset(self):
        """Test performance with large dataset."""
        num_entries = 1000
        
        # Insert many entries
        for i in range(num_entries):
            key = f'key_{i:05d}'.encode()
            value = f'value_{i}'.encode()
            self.trie.set(key, value)
        
        # Verify all entries
        for i in range(num_entries):
            key = f'key_{i:05d}'.encode()
            value = f'value_{i}'.encode()
            self.assertEqual(self.trie.get(key), value)

    def test_random_access_pattern(self):
        """Test with random access patterns."""
        import random
        
        keys = [f'key_{i:05d}'.encode() for i in range(100)]
        random.shuffle(keys)
        
        # Insert in random order
        for i, key in enumerate(keys):
            value = f'value_{i}'.encode()
            self.trie.set(key, value)
        
        # Verify in different random order
        random.shuffle(keys)
        for key in keys:
            value = self.trie.get(key)
            self.assertIsNotNone(value)


if __name__ == '__main__':
    unittest.main()