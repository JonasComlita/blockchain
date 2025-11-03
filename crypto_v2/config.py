"""
Configuration management for the blockchain.
"""
import json
import os
from typing import Optional
from dataclasses import dataclass, asdict


@dataclass
class NetworkConfig:
    """Network configuration."""
    host: str = "0.0.0.0"
    port: int = 8888
    max_peers: int = 50
    initial_peers: list = None
    
    def __post_init__(self):
        if self.initial_peers is None:
            self.initial_peers = []


@dataclass
class ChainConfig:
    """Blockchain configuration."""
    chain_id: int = 1
    checkpoint_interval: int = 100
    max_block_size: int = 1_000_000  # 1MB
    max_txs_per_block: int = 1000
    min_stake_amount: int = 100
    slash_percentage: int = 50
    block_time: int = 10  # Target seconds between blocks


@dataclass
class MempoolConfig:
    """Mempool configuration."""
    max_size: int = 10000
    max_txs_per_account: int = 100
    min_fee: int = 1
    tx_expiry_time: int = 3600  # seconds


@dataclass
class DatabaseConfig:
    """Database configuration."""
    path: str = "./blockchain_data"
    write_buffer_size: int = 64 * 1024 * 1024  # 64MB
    max_open_files: int = 1000
    compression: str = "snappy"


@dataclass
class MonitoringConfig:
    """Monitoring configuration."""
    host: str = "127.0.0.1"
    port: int = 9090


@dataclass
class Config:
    """Main configuration."""
    network: NetworkConfig
    chain: ChainConfig
    mempool: MempoolConfig
    database: DatabaseConfig
    monitoring: MonitoringConfig
    
    @classmethod
    def default(cls) -> 'Config':
        """Create default configuration."""
        return cls(
            network=NetworkConfig(),
            chain=ChainConfig(),
            mempool=MempoolConfig(),
            database=DatabaseConfig(),
            monitoring=MonitoringConfig()
        )
    
    @classmethod
    def from_file(cls, path: str) -> 'Config':
        """Load configuration from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)
        
        return cls(
            network=NetworkConfig(**data.get('network', {})),
            chain=ChainConfig(**data.get('chain', {})),
            mempool=MempoolConfig(**data.get('mempool', {})),
            database=DatabaseConfig(**data.get('database', {})),
            monitoring=MonitoringConfig(**data.get('monitoring', {}))
        )
    
    def to_file(self, path: str):
        """Save configuration to JSON file."""
        data = {
            'network': asdict(self.network),
            'chain': asdict(self.chain),
            'mempool': asdict(self.mempool),
            'database': asdict(self.database),
            'monitoring': asdict(self.monitoring)
        }
        
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'network': asdict(self.network),
            'chain': asdict(self.chain),
            'mempool': asdict(self.mempool),
            'database': asdict(self.database),
            'monitoring': asdict(self.monitoring)
        }