"""
Main node entry point for running a blockchain node.
"""
import asyncio
import argparse
import logging
import signal
import sys
from pathlib import Path

from crypto_v2.chain import Blockchain
from crypto_v2.p2p import P2PNode
from crypto_v2.validator import ValidatorNode
from crypto_v2.config import Config
from crypto_v2.crypto import (
    generate_key_pair,
    generate_vrf_keypair,
    serialize_public_key,
    public_key_to_address
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BlockchainNode:
    """Main blockchain node orchestrator."""
    
    def __init__(self, config: Config, validator_mode: bool = False,
                 validator_keys: tuple = None):
        self.config = config
        self.validator_mode = validator_mode
        self.validator_keys = validator_keys
        
        # Initialize blockchain
        logger.info(f"Initializing blockchain at {config.database.path}")
        self.blockchain = Blockchain(
            db_path=config.database.path,
            chain_id=config.chain.chain_id
        )
        
        # Initialize P2P node
        logger.info(f"Initializing P2P node on {config.network.host}:{config.network.port}")
        self.p2p_node = P2PNode(
            host=config.network.host,
            port=config.network.port,
            blockchain=self.blockchain,
            initial_peers=config.network.initial_peers,
            max_peers=config.network.max_peers
        )
        
        # Initialize validator if in validator mode
        self.validator = None
        if validator_mode and validator_keys:
            priv_key, pub_key, vrf_priv, vrf_pub = validator_keys
            logger.info("Initializing validator node")
            self.validator = ValidatorNode(
                blockchain=self.blockchain,
                p2p_node=self.p2p_node,
                validator_private_key=priv_key,
                validator_public_key=pub_key,
                vrf_private_key=vrf_priv,
                config=config
            )
        
        self.running = False
    
    async def start(self):
        """Start all node components."""
        self.running = True
        
        logger.info("Starting blockchain node...")
        
        # Start P2P node
        p2p_task = asyncio.create_task(self.p2p_node.start())
        
        # Start validator if enabled
        if self.validator:
            await self.validator.start()
        
        # Start status reporter
        asyncio.create_task(self._status_reporter())
        
        try:
            await p2p_task
        except asyncio.CancelledError:
            logger.info("Node shutdown initiated")
    
    async def stop(self):
        """Stop all node components."""
        logger.info("Stopping blockchain node...")
        self.running = False
        
        if self.validator:
            await self.validator.stop()
        
        await self.p2p_node.stop()
        
        # Close blockchain database
        self.blockchain.db.close()
        
        logger.info("Node stopped successfully")
    
    async def _status_reporter(self):
        """Periodically report node status."""
        while self.running:
            await asyncio.sleep(60)  # Report every minute
            
            try:
                latest_block = self.blockchain.get_latest_block()
                stats = self.p2p_node.get_stats()
                
                logger.info(f"=== Node Status ===")
                logger.info(f"Height: {latest_block.height}")
                logger.info(f"Peers: {stats['connected_peers']}")
                logger.info(f"Mempool: {stats['mempool_size']} transactions")
                
                if self.validator:
                    validator_status = self.validator.get_status()
                    logger.info(f"Validator: {validator_status['is_validator']}")
                    if validator_status['is_validator']:
                        logger.info(f"Stake: {validator_status['stake']}")
                
                logger.info("==================")
            except Exception as e:
                logger.error(f"Error in status reporter: {e}")


def load_or_generate_keys(keys_dir: Path):
    """Load existing keys or generate new ones."""
    import pickle
    
    keys_file = keys_dir / "validator_keys.pkl"
    
    if keys_file.exists():
        logger.info(f"Loading existing keys from {keys_file}")
        with open(keys_file, 'rb') as f:
            return pickle.load(f)
    else:
        logger.info("Generating new validator keys...")
        priv_key, pub_key = generate_key_pair()
        vrf_priv, vrf_pub = generate_vrf_keypair()
        
        keys = (priv_key, pub_key, vrf_priv, vrf_pub)
        
        # Save keys
        keys_dir.mkdir(parents=True, exist_ok=True)
        with open(keys_file, 'wb') as f:
            pickle.dump(keys, f)
        
        # Print address for reference
        pub_key_pem = serialize_public_key(pub_key)
        address = public_key_to_address(pub_key_pem)
        logger.info(f"Generated new validator address: {address.hex()}")
        logger.info(f"VRF public key: {vrf_pub.encode().hex()}")
        
        return keys


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Run a blockchain node')
    parser.add_argument('--config', type=str, help='Path to config file')
    parser.add_argument('--data-dir', type=str, default='./data', 
                       help='Data directory')
    parser.add_argument('--validator', action='store_true',
                       help='Run in validator mode')
    parser.add_argument('--port', type=int, help='P2P port')
    parser.add_argument('--peer', action='append', 
                       help='Initial peer (format: host:port)')
    
    args = parser.parse_args()
    
    # Load or create config
    if args.config and Path(args.config).exists():
        config = Config.from_file(args.config)
    else:
        config = Config.default()
    
    # Override config with CLI arguments
    data_dir = Path(args.data_dir)
    config.database.path = str(data_dir / 'blockchain')
    
    if args.port:
        config.network.port = args.port
    
    if args.peer:
        config.network.initial_peers = []
        for peer in args.peer:
            host, port = peer.split(':')
            config.network.initial_peers.append((host, int(port)))
    
    # Load/generate validator keys if in validator mode
    validator_keys = None
    if args.validator:
        validator_keys = load_or_generate_keys(data_dir / 'keys')
    
    # Create node
    node = BlockchainNode(
        config=config,
        validator_mode=args.validator,
        validator_keys=validator_keys
    )
    
    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(node.stop())
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        await node.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        await node.stop()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
        sys.exit(0)