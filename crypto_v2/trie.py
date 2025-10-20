"""
A Merkle Patricia Trie implementation.
"""
import rlp
from crypto_v2.utils.encoding import hex_prefix_encode, hex_prefix_decode, bytes_to_nibbles
from crypto_v2.crypto import generate_hash

BLANK_NODE = b''
BLANK_ROOT = generate_hash(rlp.encode(BLANK_NODE))

class Trie:
    def __init__(self, db, root_hash=None):
        self.db = db
        self.root_hash = root_hash or BLANK_ROOT

    def get(self, key: bytes) -> bytes | None:
        """Get a value by key."""
        path = bytes_to_nibbles(key)
        return self._get(self.root_hash, path)

    def _get(self, node_hash: bytes, path: tuple[int, ...]) -> bytes | None:
        if node_hash == BLANK_ROOT or not node_hash:
            return None

        node_data = self.db.get(node_hash)
        if not node_data:
            return None
        
        node = rlp.decode(node_data)

        if not node:
            return None
        
        if len(node) == 2: # Leaf or Extension node
            key, value = node
            current_path, is_leaf = hex_prefix_decode(key)

            if is_leaf:
                if tuple(current_path) == path:
                    return value
                else:
                    return None
            else: # Extension node
                if path[:len(current_path)] == tuple(current_path):
                    return self._get(value, path[len(current_path):])
                else:
                    return None
        
        elif len(node) == 17: # Branch node
            if not path:
                return node[16]
            else:
                return self._get(node[path[0]], path[1:])

    def set(self, key: bytes, value: bytes):
        """Set a key-value pair."""
        path = bytes_to_nibbles(key)
        self.root_hash = self._set(self.root_hash, path, value)

    def _set(self, node_hash: bytes, path: tuple[int, ...], value: bytes) -> bytes:
        """Set a value in the trie, returning the new root hash."""
        if node_hash == BLANK_ROOT:
            # Create a new leaf node
            new_key = hex_prefix_encode(path, is_leaf=True)
            new_node = [new_key, value]
            return self._put_node(new_node)

        node_data = self.db.get(node_hash)
        if not node_data:
            # Treat as blank node
            new_key = hex_prefix_encode(path, is_leaf=True)
            new_node = [new_key, value]
            return self._put_node(new_node)
        
        node = rlp.decode(node_data)

        if len(node) == 2:  # Leaf or Extension node
            current_key, value_or_node_hash = node
            current_path, is_leaf = hex_prefix_decode(current_key)
            
            # Find common prefix
            common_prefix_len = 0
            for i in range(min(len(path), len(current_path))):
                if path[i] == current_path[i]:
                    common_prefix_len += 1
                else:
                    break
            
            # Case 1: Exact match
            if common_prefix_len == len(current_path) == len(path):
                if is_leaf:
                    # Update leaf value
                    new_leaf_key = hex_prefix_encode(path, is_leaf=True)
                    return self._put_node([new_leaf_key, value])
                else:
                    # Extension node with exact match - shouldn't happen
                    # Continue to child with empty path
                    new_child = self._set(value_or_node_hash, tuple(), value)
                    return self._put_node([current_key, new_child])
            
            # Case 2: Current path is prefix of new path
            if common_prefix_len == len(current_path) < len(path):
                if is_leaf:
                    # Need to convert leaf to branch
                    branch_node = [b''] * 17
                    branch_node[16] = value_or_node_hash  # Old leaf value
                    
                    # Add new path
                    remaining_path = path[common_prefix_len+1:]
                    new_child = self._set(BLANK_ROOT, remaining_path, value)
                    branch_node[path[common_prefix_len]] = new_child
                    
                    if common_prefix_len > 0:
                        # Create extension for common prefix
                        ext_key = hex_prefix_encode(path[:common_prefix_len], is_leaf=False)
                        return self._put_node([ext_key, self._put_node(branch_node)])
                    return self._put_node(branch_node)
                else:
                    # Extension node - continue traversal
                    remaining_path = path[common_prefix_len:]
                    new_child = self._set(value_or_node_hash, remaining_path, value)
                    return self._put_node([current_key, new_child])
            
            # Case 3: New path is prefix of current path
            if common_prefix_len == len(path) < len(current_path):
                # Create branch with new value at [16]
                branch_node = [b''] * 17
                branch_node[16] = value
                
                # Add old node as child
                remaining_current = tuple(current_path[common_prefix_len+1:])
                if is_leaf:
                    old_child = self._set(BLANK_ROOT, remaining_current, value_or_node_hash)
                else:
                    if remaining_current:
                        old_ext_key = hex_prefix_encode(remaining_current, is_leaf=False)
                        old_child = self._put_node([old_ext_key, value_or_node_hash])
                    else:
                        old_child = value_or_node_hash
                
                branch_node[current_path[common_prefix_len]] = old_child
                
                if common_prefix_len > 0:
                    ext_key = hex_prefix_encode(path[:common_prefix_len], is_leaf=False)
                    return self._put_node([ext_key, self._put_node(branch_node)])
                return self._put_node(branch_node)
            
            # Case 4: Paths diverge
            branch_node = [b''] * 17
            
            # Add current node
            remaining_current = tuple(current_path[common_prefix_len+1:])
            if is_leaf:
                old_child = self._set(BLANK_ROOT, remaining_current, value_or_node_hash)
            else:
                if remaining_current:
                    old_ext_key = hex_prefix_encode(remaining_current, is_leaf=False)
                    old_child = self._put_node([old_ext_key, value_or_node_hash])
                else:
                    old_child = value_or_node_hash
            branch_node[current_path[common_prefix_len]] = old_child
            
            # Add new value
            remaining_new = path[common_prefix_len+1:]
            new_child = self._set(BLANK_ROOT, remaining_new, value)
            branch_node[path[common_prefix_len]] = new_child
            
            branch_hash = self._put_node(branch_node)
            
            if common_prefix_len > 0:
                ext_key = hex_prefix_encode(path[:common_prefix_len], is_leaf=False)
                return self._put_node([ext_key, branch_hash])
            return branch_hash

        elif len(node) == 17:  # Branch node
            if not path:
                # Set value at this branch
                node[16] = value
                return self._put_node(node)
            else:
                # Traverse to child
                sub_node_hash = node[path[0]] if node[path[0]] else BLANK_ROOT
                new_child = self._set(sub_node_hash, path[1:], value)
                node[path[0]] = new_child
                return self._put_node(node)
        
        # Shouldn't reach here
        raise ValueError(f"Invalid node structure: {len(node)} elements")

    def _put_node(self, node) -> bytes:
        encoded_node = rlp.encode(node)
        node_hash = generate_hash(encoded_node)
        self.db.put(node_hash, encoded_node)
        return node_hash
