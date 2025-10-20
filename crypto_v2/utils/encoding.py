"""
Hex-prefix encoding for Merkle Patricia Tries.
"""

def bytes_to_nibbles(b: bytes) -> tuple[int, ...]:
    """Convert a byte string into a nibble tuple."""
    res = []
    for byte in b:
        res.append(byte >> 4)
        res.append(byte & 15)
    return tuple(res)

def nibbles_to_bytes(nibbles: tuple[int, ...]) -> bytes:
    """Convert a nibble tuple into a byte string."""
    if len(nibbles) % 2:
        raise ValueError("Nibbles must be of even length")
    res = bytearray()
    for i in range(0, len(nibbles), 2):
        res.append((nibbles[i] << 4) + nibbles[i + 1])
    return bytes(res)

def hex_prefix_encode(nibbles: tuple[int, ...], is_leaf: bool) -> bytes:
    """
    Hex-prefix encode a nibble array.
    The flag indicates if the node is a leaf (terminator) node.
    """
    flag = (2 if is_leaf else 0) + (len(nibbles) % 2)
    
    if flag % 2 == 1: # Odd number of nibbles
        prefixed_nibbles = (flag,) + nibbles
    else: # Even number of nibbles
        prefixed_nibbles = (flag, 0) + nibbles
        
    return nibbles_to_bytes(prefixed_nibbles)

def hex_prefix_decode(encoded_bytes: bytes) -> tuple[tuple[int, ...], bool]:
    """
    Decode a hex-prefix encoded byte string.
    Returns a tuple of (nibbles, is_leaf).
    """
    nibbles = bytes_to_nibbles(encoded_bytes)
    flag = nibbles[0]

    is_leaf = flag >= 2
    
    if flag % 2 == 1: # Odd number of nibbles
        return nibbles[1:], is_leaf
    else: # Even number of nibbles
        return nibbles[2:], is_leaf
