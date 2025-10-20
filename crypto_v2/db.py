"""
Improved database wrapper with batch operations and better error handling.
"""
import plyvel
import logging
from typing import Optional, Iterator
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DB:
    def __init__(self, db_path: str, create_if_missing: bool = True, 
                 write_buffer_size: int = 64 * 1024 * 1024,  # 64MB
                 max_open_files: int = 1000):
        """
        Initialize database with performance optimizations.
        
        Args:
            db_path: Path to database directory
            create_if_missing: Create database if it doesn't exist
            write_buffer_size: Size of write buffer
            max_open_files: Maximum number of open files
        """
        try:
            self._db = plyvel.DB(
                db_path,
                create_if_missing=create_if_missing,
                write_buffer_size=write_buffer_size,
                max_open_files=max_open_files,
                compression='snappy',  # Enable compression
            )
            self._closed = False
            logger.info(f"Database opened at {db_path}")
        except Exception as e:
            logger.error(f"Failed to open database at {db_path}: {e}")
            raise

    def get(self, key: bytes) -> Optional[bytes]:
        """
        Get value by key.
        
        Returns None if key doesn't exist.
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            return self._db.get(key)
        except Exception as e:
            logger.error(f"Error getting key {key.hex()[:16]}: {e}")
            raise

    def put(self, key: bytes, value: bytes):
        """Put a key-value pair."""
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            self._db.put(key, value)
        except Exception as e:
            logger.error(f"Error putting key {key.hex()[:16]}: {e}")
            raise

    def delete(self, key: bytes):
        """Delete a key."""
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            self._db.delete(key)
        except Exception as e:
            logger.error(f"Error deleting key {key.hex()[:16]}: {e}")
            raise

    def exists(self, key: bytes) -> bool:
        """Check if key exists."""
        return self.get(key) is not None

    @contextmanager
    def write_batch(self):
        """
        Context manager for batch writes.
        
        Example:
            with db.write_batch() as batch:
                batch.put(b'key1', b'value1')
                batch.put(b'key2', b'value2')
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        batch = self._db.write_batch()
        try:
            yield batch
            batch.write()
        except Exception as e:
            logger.error(f"Error in batch write: {e}")
            raise
        finally:
            batch.close()

    def iterator(self, prefix: Optional[bytes] = None, 
                 start: Optional[bytes] = None,
                 stop: Optional[bytes] = None,
                 reverse: bool = False) -> Iterator[tuple[bytes, bytes]]:
        """
        Create an iterator over the database.
        
        Args:
            prefix: Only iterate keys with this prefix
            start: Start key (inclusive)
            stop: Stop key (exclusive)
            reverse: Iterate in reverse order
        
        Yields:
            Tuple of (key, value)
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            if prefix:
                return self._db.iterator(prefix=prefix, reverse=reverse)
            else:
                return self._db.iterator(start=start, stop=stop, reverse=reverse)
        except Exception as e:
            logger.error(f"Error creating iterator: {e}")
            raise

    def get_range(self, start: bytes, stop: bytes) -> list[tuple[bytes, bytes]]:
        """
        Get all key-value pairs in a range.
        
        Args:
            start: Start key (inclusive)
            stop: Stop key (exclusive)
        
        Returns:
            List of (key, value) tuples
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        result = []
        try:
            for key, value in self._db.iterator(start=start, stop=stop):
                result.append((key, value))
            return result
        except Exception as e:
            logger.error(f"Error getting range: {e}")
            raise

    def get_prefix(self, prefix: bytes) -> list[tuple[bytes, bytes]]:
        """
        Get all key-value pairs with a given prefix.
        
        Args:
            prefix: Key prefix to search for
        
        Returns:
            List of (key, value) tuples
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        result = []
        try:
            for key, value in self._db.iterator(prefix=prefix):
                result.append((key, value))
            return result
        except Exception as e:
            logger.error(f"Error getting prefix {prefix.hex()}: {e}")
            raise

    def compact_range(self, start: Optional[bytes] = None, 
                      stop: Optional[bytes] = None):
        """
        Compact the database in a range.
        
        This can improve read performance by removing deleted keys
        and optimizing storage layout.
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            self._db.compact_range(start=start, stop=stop)
            logger.info("Database compaction completed")
        except Exception as e:
            logger.error(f"Error compacting database: {e}")
            raise

    def get_property(self, name: str) -> Optional[bytes]:
        """
        Get database property.
        
        Available properties:
        - leveldb.stats: Statistics about the database
        - leveldb.sstables: SSTable information
        - leveldb.num-files-at-level<N>: Number of files at level N
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            return self._db.get_property(name.encode())
        except Exception as e:
            logger.error(f"Error getting property {name}: {e}")
            return None

    def get_stats(self) -> dict:
        """Get database statistics."""
        stats = {}
        
        try:
            stats_raw = self.get_property('leveldb.stats')
            if stats_raw:
                stats['raw'] = stats_raw.decode('utf-8', errors='ignore')
            
            # Get approximate size
            stats['approximate_size'] = self.approximate_size()
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
        
        return stats

    def approximate_size(self, start: Optional[bytes] = None,
                         stop: Optional[bytes] = None) -> int:
        """
        Get approximate size of database or range in bytes.
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        try:
            return self._db.approximate_size(start or b'', stop or b'\xff' * 32)
        except Exception as e:
            logger.error(f"Error getting approximate size: {e}")
            return 0

    def snapshot(self):
        """
        Create a database snapshot.
        
        Returns a context manager that provides a consistent view of the database.
        
        Example:
            with db.snapshot() as snap:
                value = snap.get(b'key')
        """
        if self._closed:
            raise RuntimeError("Database is closed")
        
        return self._db.snapshot()

    def close(self):
        """Close the database."""
        if not self._closed:
            try:
                self._db.close()
                self._closed = True
                logger.info("Database closed")
            except Exception as e:
                logger.error(f"Error closing database: {e}")
                raise

    def is_closed(self) -> bool:
        """Check if database is closed."""
        return self._closed

    def __enter__(self):
        """Support context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support context manager protocol."""
        self.close()
        return False

    def __del__(self):
        """Ensure database is closed on deletion."""
        if not self._closed:
            try:
                self.close()
            except:
                pass  # Ignore errors during cleanup


class BatchWriter:
    """Helper class for efficient batch writes."""
    
    def __init__(self, db: DB, batch_size: int = 1000):
        self.db = db
        self.batch_size = batch_size
        self.current_batch = []
        self.total_written = 0
    
    def put(self, key: bytes, value: bytes):
        """Add a put operation to the batch."""
        self.current_batch.append(('put', key, value))
        
        if len(self.current_batch) >= self.batch_size:
            self.flush()
    
    def delete(self, key: bytes):
        """Add a delete operation to the batch."""
        self.current_batch.append(('delete', key, None))
        
        if len(self.current_batch) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """Write all pending operations."""
        if not self.current_batch:
            return
        
        with self.db.write_batch() as batch:
            for op, key, value in self.current_batch:
                if op == 'put':
                    batch.put(key, value)
                elif op == 'delete':
                    batch.delete(key)
        
        self.total_written += len(self.current_batch)
        self.current_batch.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()
        return False