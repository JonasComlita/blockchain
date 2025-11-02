"""
Improved P2P networking with security, rate limiting, and message deduplication.
"""
import asyncio
import msgpack
import struct
import time
import logging
from collections import defaultdict, deque
from typing import Optional
from crypto_v2.core import Block, Transaction
from crypto_v2.mempool import Mempool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Message types
MSG_HANDSHAKE = 'handshake'
MSG_GET_BLOCKS = 'get_blocks'
MSG_BLOCKS = 'blocks'
MSG_NEW_BLOCK = 'new_block'
MSG_NEW_TX = 'new_tx'
MSG_GET_CHECKPOINT = 'get_checkpoint'
MSG_CHECKPOINT = 'checkpoint'
MSG_PING = 'ping'
MSG_PONG = 'pong'

# Network configuration
MAX_MESSAGE_SIZE = 10_000_000  # 10MB
MAX_PEERS = 50
MAX_INCOMING_CONNECTIONS = 100
CONNECTION_TIMEOUT = 30
MESSAGE_TIMEOUT = 60
RATE_LIMIT_WINDOW = 60  # seconds
MAX_MESSAGES_PER_WINDOW = 1000
PING_INTERVAL = 30
PEER_DISCOVERY_INTERVAL = 300  # 5 minutes

# Deduplication
MAX_SEEN_MESSAGES = 10000
MESSAGE_EXPIRY = 300  # 5 minutes


def create_message(msg_type: str, data: any) -> bytes:
    """Creates a length-prefixed message."""
    message = {
        'type': msg_type,
        'data': data,
        'timestamp': time.time(),
    }
    packed_message = msgpack.packb(message, use_bin_type=True)
    
    if len(packed_message) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {len(packed_message)} bytes")
    
    return struct.pack('!I', len(packed_message)) + packed_message


class RateLimiter:
    """Token bucket rate limiter."""
    def __init__(self, max_rate: int, window: int):
        self.max_rate = max_rate
        self.window = window
        self.timestamps = deque()
    
    def allow(self) -> bool:
        """Check if action is allowed under rate limit."""
        now = time.time()
        
        # Remove old timestamps
        while self.timestamps and self.timestamps[0] < now - self.window:
            self.timestamps.popleft()
        
        if len(self.timestamps) < self.max_rate:
            self.timestamps.append(now)
            return True
        
        return False


class Peer:
    """Represents a connected peer."""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                 is_outbound: bool = False):
        self.reader = reader
        self.writer = writer
        self.is_outbound = is_outbound
        self.peer_addr = writer.get_extra_info('peername')
        self.peer_addr_str = f"{self.peer_addr[0]}:{self.peer_addr[1]}"
        self.score = 0
        self.rate_limiter = RateLimiter(MAX_MESSAGES_PER_WINDOW, RATE_LIMIT_WINDOW)
        self.last_seen = time.time()
        self.version = None
        self.handshake_complete = False
        self.sent_messages = 0
        self.received_messages = 0

    def update_score(self, delta: int):
        """Update peer reputation score."""
        self.score += delta
        self.score = max(-1000, min(1000, self.score))  # Clamp between -1000 and 1000

    def is_good(self) -> bool:
        """Check if peer has good reputation."""
        return self.score > -100


class P2PNode:
    def __init__(self, host: str, port: int, blockchain, 
                 initial_peers: list[tuple[str, int]] = None,
                 max_peers: int = MAX_PEERS):
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.initial_peers = initial_peers or []
        self.max_peers = max_peers
        
        # Create mempool with state validation
        self.mempool = Mempool(
            get_account_state=lambda addr: blockchain._get_account(addr, blockchain.state_trie)
        )
        
        self.peers: dict[asyncio.StreamWriter, Peer] = {}
        self.banned_peers = set()  # {ip_address}
        self.connection_counts = defaultdict(int)  # {ip -> count}
        
        # Message deduplication
        self.seen_messages = {}  # {message_hash: timestamp}
        self.seen_blocks = {}  # {block_hash: timestamp}
        self.seen_txs = {}  # {tx_id: timestamp}
        
        # Background tasks
        self.tasks = []
        self.running = False

    async def _safe_drain(self, writer):
        """Safely drain a writer, handling both real and mock objects."""
        try:
            if hasattr(writer, 'drain') and callable(writer.drain):
                result = writer.drain()
                # Only await if it's a coroutine
                if asyncio.iscoroutine(result):
                    await result
        except Exception:
            pass  # Ignore drain errors for mocks

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles incoming connection."""
        peer_addr = writer.get_extra_info('peername')
        peer_ip = peer_addr[0]
        
        # Check if IP is banned
        if peer_ip in self.banned_peers:
            logger.warning(f"Rejecting connection from banned peer {peer_ip}")
            writer.close()
            await writer.wait_closed()
            return
        
        # Check connection limits per IP
        if self.connection_counts[peer_ip] >= 3:
            logger.warning(f"Too many connections from {peer_ip}")
            writer.close()
            await writer.wait_closed()
            return
        
        # Check total peer limit
        if len(self.peers) >= MAX_INCOMING_CONNECTIONS:
            logger.warning("Max connections reached, rejecting new connection")
            writer.close()
            await writer.wait_closed()
            return
        
        peer = Peer(reader, writer, is_outbound=False)
        self.peers[writer] = peer
        self.connection_counts[peer_ip] += 1
        
        logger.info(f"Accepted connection from {peer.peer_addr_str}")
        
        try:
            await self._message_loop(peer)
        finally:
            if writer in self.peers:
                del self.peers[writer]
            self.connection_counts[peer_ip] -= 1

    async def connect_to_peer(self, host: str, port: int) -> bool:
        """Connects to a peer."""
        # Check if already connected
        for peer in self.peers.values():
            if peer.peer_addr[0] == host and peer.peer_addr[1] == port:
                logger.debug(f"Already connected to {host}:{port}")
                return False
        
        # Check if banned
        if host in self.banned_peers:
            logger.warning(f"Not connecting to banned peer {host}")
            return False
        
        # Check peer limit
        if len(self.peers) >= self.max_peers:
            logger.debug("Max peers reached")
            return False
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECTION_TIMEOUT
            )
            
            peer = Peer(reader, writer, is_outbound=True)
            self.peers[writer] = peer
            self.connection_counts[host] += 1
            
            logger.info(f"Connected to peer {peer.peer_addr_str}")
            
            # Send handshake
            handshake_msg = create_message(MSG_HANDSHAKE, {
                'version': 1,
                'port': self.port,
                'height': self.blockchain.get_latest_block().height,
            })
            writer.write(handshake_msg)
            await self._safe_drain(writer)
            
            # Start message loop
            asyncio.create_task(self._message_loop(peer))
            return True
            
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            logger.warning(f"Failed to connect to {host}:{port}: {e}")
            return False

    async def _message_loop(self, peer: Peer):
        """Main message handling loop for a peer."""
        try:
            while self.running:
                # Read message with timeout
                try:
                    len_prefix = await asyncio.wait_for(
                        peer.reader.readexactly(4),
                        timeout=MESSAGE_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Message timeout from {peer.peer_addr_str}")
                    break
                
                if not len_prefix:
                    break
                
                msg_len = struct.unpack('!I', len_prefix)[0]
                
                # Validate message size
                if msg_len > MAX_MESSAGE_SIZE:
                    logger.warning(f"Message too large from {peer.peer_addr_str}: {msg_len}")
                    peer.update_score(-50)
                    break
                
                # Read full message
                data = await asyncio.wait_for(
                    peer.reader.readexactly(msg_len),
                    timeout=MESSAGE_TIMEOUT
                )
                
                if not data:
                    break
                
                # Rate limiting
                if not peer.rate_limiter.allow():
                    logger.warning(f"Rate limit exceeded for {peer.peer_addr_str}")
                    peer.update_score(-10)
                    continue
                
                try:
                    message = msgpack.unpackb(data, raw=False)
                    peer.received_messages += 1
                    peer.last_seen = time.time()
                    
                    valid_message = await self.handle_message(message, peer)
                    
                    if valid_message:
                        peer.update_score(1)
                    else:
                        peer.update_score(-10)
                        
                        # Ban peer if score too low
                        if not peer.is_good():
                            logger.warning(f"Banning peer {peer.peer_addr_str} for misbehavior")
                            self.banned_peers.add(peer.peer_addr[0])
                            break
                            
                except Exception as e:
                    logger.error(f"Error processing message from {peer.peer_addr_str}: {e}")
                    peer.update_score(-5)
                    
        except (ConnectionResetError, asyncio.IncompleteReadError) as e:
            logger.info(f"Connection lost with {peer.peer_addr_str}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in message loop: {e}")
        finally:
            await self._disconnect_peer(peer)

    async def _disconnect_peer(self, peer: Peer):
        """Cleanly disconnect a peer."""
        try:
            if peer.writer in self.peers:
                del self.peers[peer.writer]
            await self._safe_drain(peer.writer)
            peer.writer.close()
            await peer.writer.wait_closed()
            self.connection_counts[peer.peer_addr[0]] -= 1
            logger.info(f"Disconnected from {peer.peer_addr_str}")
        except Exception as e:
            logger.error(f"Error disconnecting peer: {e}")

    async def broadcast(self, message: bytes, exclude_peer: Optional[Peer] = None):
        """Broadcasts message to all peers except one."""
        disconnected = []
        
        for writer, peer in self.peers.items():
            if peer == exclude_peer:
                continue
            
            if not peer.handshake_complete:
                continue
            
            try:
                writer.write(message)
                await self._safe_drain(writer)
                peer.sent_messages += 1
            except Exception as e:
                logger.warning(f"Failed to send to {peer.peer_addr_str}: {e}")
                disconnected.append(peer)
        
        # Clean up disconnected peers
        for peer in disconnected:
            await self._disconnect_peer(peer)

    def _is_message_seen(self, message_hash: bytes) -> bool:
        """Check if message was recently seen."""
        now = time.time()
        
        # Clean old entries BEFORE checking if message is seen
        expired_keys = [h for h, t in self.seen_messages.items() if now - t >= MESSAGE_EXPIRY]
        for key in expired_keys:
            del self.seen_messages[key]
        
        # Also enforce max size limit
        if len(self.seen_messages) > MAX_SEEN_MESSAGES:
            # Sort by timestamp and keep only newest entries
            sorted_items = sorted(self.seen_messages.items(), key=lambda x: x[1], reverse=True)
            self.seen_messages = dict(sorted_items[:MAX_SEEN_MESSAGES])
        
        if message_hash in self.seen_messages:
            return True
        
        self.seen_messages[message_hash] = now
        return False

    async def handle_message(self, message: dict, peer: Peer) -> bool:
        """
        Routes messages to handlers.
        Returns True if message was valid.
        """
        msg_type = message.get('type')
        data = message.get('data')
        timestamp = message.get('timestamp', 0)
        
        # Validate timestamp (prevent replay attacks)
        current_time = time.time()
        if abs(current_time - timestamp) > 300:  # 5 minute tolerance
            logger.warning(f"Message timestamp out of range from {peer.peer_addr_str}")
            return False
        
        # Message deduplication
        message_hash = msgpack.packb(message, use_bin_type=True)[:32]
        if msg_type in [MSG_NEW_BLOCK, MSG_NEW_TX]:
            if self._is_message_seen(message_hash):
                return True  # Already processed, but not an error
        
        try:
            if msg_type == MSG_HANDSHAKE:
                return await self._handle_handshake(data, peer)
            
            # Require handshake before other messages
            if not peer.handshake_complete:
                logger.warning(f"Peer {peer.peer_addr_str} sent {msg_type} before handshake")
                return False
            
            if msg_type == MSG_PING:
                return await self._handle_ping(peer)
            elif msg_type == MSG_PONG:
                return await self._handle_pong(peer)
            elif msg_type == MSG_GET_CHECKPOINT:
                return await self._handle_get_checkpoint(peer)
            elif msg_type == MSG_CHECKPOINT:
                return await self._handle_checkpoint(data, peer)
            elif msg_type == MSG_GET_BLOCKS:
                return await self._handle_get_blocks(data, peer)
            elif msg_type == MSG_BLOCKS:
                return await self._handle_blocks(data, peer)
            elif msg_type == MSG_NEW_BLOCK:
                return await self._handle_new_block(data, peer)
            elif msg_type == MSG_NEW_TX:
                return await self._handle_new_tx(data, peer)
            else:
                logger.warning(f"Unknown message type: {msg_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling {msg_type}: {e}")
            return False

    async def _handle_handshake(self, data: dict, peer: Peer) -> bool:
        """Handle handshake message."""
        peer.version = data.get('version')
        peer_height = data.get('height', 0)
        peer.handshake_complete = True
        
        logger.info(f"Handshake complete with {peer.peer_addr_str}, height: {peer_height}")
        
        # If peer is ahead, request blocks
        our_height = self.blockchain.get_latest_block().height
        if peer_height > our_height:
            logger.info(f"Peer is ahead ({peer_height} vs {our_height}), requesting blocks")
            msg = create_message(MSG_GET_BLOCKS, {'start_height': our_height + 1})
            peer.writer.write(msg)
            await self._safe_drain(peer.writer)
        
        return True

    async def _handle_ping(self, peer: Peer) -> bool:
        """Handle ping message."""
        msg = create_message(MSG_PONG, {})
        peer.writer.write(msg)
        await self._safe_drain(peer.writer)
        return True

    async def _handle_pong(self, peer: Peer) -> bool:
        """Handle pong message."""
        peer.last_seen = time.time()
        return True

    async def _handle_get_checkpoint(self, peer: Peer) -> bool:
        """Handle checkpoint request."""
        checkpoint = self.blockchain.get_checkpoint()
        if checkpoint:
            msg = create_message(MSG_CHECKPOINT, checkpoint)
            peer.writer.write(msg)
            await self._safe_drain(peer.writer)
        return True

    async def _handle_checkpoint(self, data: dict, peer: Peer) -> bool:
        """Handle checkpoint data."""
        logger.info(f"Received checkpoint: height={data.get('height')}")
        # TODO: Implement checkpoint sync
        return True

    async def _handle_get_blocks(self, data: dict, peer: Peer) -> bool:
        """Handle block request."""
        start_height = data.get('start_height', 0)
        max_blocks = min(data.get('max_blocks', 100), 500)
        
        blocks = []
        for height in range(start_height, start_height + max_blocks):
            block = self.blockchain.get_block_by_height(height)
            if block:
                blocks.append(block.to_dict())
            else:
                break
        
        if blocks:
            msg = create_message(MSG_BLOCKS, blocks)
            peer.writer.write(msg)
            await self._safe_drain(peer.writer)
        
        return True

    async def _handle_blocks(self, data: list, peer: Peer) -> bool:
        """Handle received blocks."""
        for block_dict in data:
            try:
                txs = [Transaction(**tx) for tx in block_dict['transactions']]
                block_dict['transactions'] = txs
                block = Block(**block_dict)
                
                if not self.blockchain.add_block(block):
                    logger.warning(f"Failed to add block {block.height}")
                    return False
                    
            except Exception as e:
                logger.error(f"Error processing block: {e}")
                return False
        
        return True

    async def _handle_new_block(self, data: dict, peer: Peer) -> bool:
        """Handle new block announcement."""
        try:
            txs = [Transaction(**tx) for tx in data['transactions']]
            data['transactions'] = txs
            block = Block(**data)
            
            # Check if already seen
            if block.hash in self.seen_blocks:
                return True
            
            self.seen_blocks[block.hash] = time.time()
            
            if self.blockchain.add_block(block):
                logger.info(f"Added new block {block.height} from network")
                # Remove included transactions from mempool
                self.mempool.remove_transactions(block.transactions)
                # Rebroadcast to other peers
                await self.broadcast(create_message(MSG_NEW_BLOCK, data), exclude_peer=peer)
                return True
            else:
                logger.warning(f"Failed to add new block {block.height}")
                return False
                
        except Exception as e:
            logger.error(f"Error processing new block: {e}")
            return False

    async def _handle_new_tx(self, data: dict, peer: Peer) -> bool:
        """Handle new transaction announcement."""
        try:
            tx = Transaction(**data)
            
            # Check if already seen
            if tx.id in self.seen_txs:
                return True
            
            self.seen_txs[tx.id] = time.time()
            
            # Try to add to mempool
            success, error = self.mempool.add_transaction(tx)
            
            if success:
                logger.debug(f"Added new transaction {tx.id.hex()[:16]} from network")
                # Rebroadcast to other peers
                await self.broadcast(create_message(MSG_NEW_TX, data), exclude_peer=peer)
                return True
            else:
                logger.debug(f"Transaction rejected: {error}")
                # Don't penalize peer for rejected transactions (might be duplicates)
                return True
                
        except Exception as e:
            logger.error(f"Error processing new transaction: {e}")
            return False

    async def _ping_peers(self):
        """Periodically ping peers to keep connections alive."""
        while self.running:
            await asyncio.sleep(PING_INTERVAL)
            
            current_time = time.time()
            disconnected = []
            
            for peer in self.peers.values():
                if not peer.handshake_complete:
                    continue
                
                # Check if peer is responsive
                if current_time - peer.last_seen > PING_INTERVAL * 3:
                    logger.warning(f"Peer {peer.peer_addr_str} unresponsive")
                    disconnected.append(peer)
                    continue
                
                # Send ping
                try:
                    msg = create_message(MSG_PING, {})
                    peer.writer.write(msg)
                    await self._safe_drain(peer.writer)
                except Exception as e:
                    logger.warning(f"Failed to ping {peer.peer_addr_str}: {e}")
                    disconnected.append(peer)
            
            # Disconnect unresponsive peers
            for peer in disconnected:
                await self._disconnect_peer(peer)

    async def _maintain_connections(self):
        """Maintain desired number of peer connections."""
        while self.running:
            await asyncio.sleep(PEER_DISCOVERY_INTERVAL)
            
            active_peers = len([p for p in self.peers.values() if p.handshake_complete])
            
            if active_peers < self.max_peers // 2:
                logger.info(f"Only {active_peers} peers, attempting to connect to more")
                
                # Try to connect to initial peers
                for host, port in self.initial_peers:
                    if active_peers >= self.max_peers:
                        break
                    
                    # Check if not already connected
                    already_connected = any(
                        p.peer_addr[0] == host and p.peer_addr[1] == port
                        for p in self.peers.values()
                    )
                    
                    if not already_connected:
                        success = await self.connect_to_peer(host, port)
                        if success:
                            active_peers += 1

    async def _cleanup_old_messages(self):
        """Periodically clean up old message hashes."""
        while self.running:
            await asyncio.sleep(60)
            
            current_time = time.time()
            
            # Clean seen messages
            self.seen_messages = {
                h: t for h, t in self.seen_messages.items()
                if current_time - t < MESSAGE_EXPIRY
            }
            
            # Clean seen blocks
            self.seen_blocks = {
                h: t for h, t in self.seen_blocks.items()
                if current_time - t < MESSAGE_EXPIRY
            }
            
            # Clean seen transactions
            self.seen_txs = {
                h: t for h, t in self.seen_txs.items()
                if current_time - t < MESSAGE_EXPIRY
            }
            
            # Clean expired transactions from mempool
            self.mempool.clean_expired()

    async def start(self):
        """Starts the P2P node."""
        self.running = True
        
        # Start server
        server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        logger.info(f'P2P node serving on {addr}')

        # Connect to initial peers
        for peer_host, peer_port in self.initial_peers:
            if peer_host != self.host or peer_port != self.port:
                asyncio.create_task(self.connect_to_peer(peer_host, peer_port))

        # Start background tasks
        self.tasks = [
            asyncio.create_task(self._ping_peers()),
            asyncio.create_task(self._maintain_connections()),
            asyncio.create_task(self._cleanup_old_messages()),
        ]

        try:
            async with server:
                await server.serve_forever()
        finally:
            await self.stop()

    async def stop(self):
        """Stops the P2P node."""
        logger.info("Stopping P2P node...")
        self.running = False
        
        # Cancel background tasks
        for task in self.tasks:
            task.cancel()
        
        # Disconnect all peers
        peers_copy = list(self.peers.values())
        for peer in peers_copy:
            await self._disconnect_peer(peer)
        
        logger.info("P2P node stopped")

    def get_peer_info(self) -> list[dict]:
        """Returns information about connected peers."""
        return [
            {
                'address': peer.peer_addr_str,
                'score': peer.score,
                'is_outbound': peer.is_outbound,
                'handshake_complete': peer.handshake_complete,
                'sent_messages': peer.sent_messages,
                'received_messages': peer.received_messages,
                'last_seen': peer.last_seen,
            }
            for peer in self.peers.values()
        ]

    def get_stats(self) -> dict:
        """Returns network statistics."""
        return {
            'connected_peers': len(self.peers),
            'banned_peers': len(self.banned_peers),
            'mempool_size': len(self.mempool),
            'mempool_stats': self.mempool.get_stats(),
            'seen_messages': len(self.seen_messages),
            'seen_blocks': len(self.seen_blocks),
            'seen_txs': len(self.seen_txs),
        }