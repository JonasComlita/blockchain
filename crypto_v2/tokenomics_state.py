"""
Simplified tokenomics state - just tracks supply.
Price is now determined by AMM pool.
"""
from decimal import Decimal


class TokenomicsState:
    """
    Simplified tokenomics state - only tracks token supply.
    
    Price discovery moved to AMM liquidity pool.
    This class now only tracks historical metrics.
    """
    
    def __init__(self, data: dict = None):
        """
        Initialize tokenomics state.
        
        Args:
            data: Dict with supply tracking
        """
        if data is None:
            data = {
                'total_minted': 0,
                'total_burned': 0,
                'total_usd_in': '0',   # Historical: Total USD received from buys
                'total_usd_out': '0',  # Historical: Total USD paid for sells
            }
        
        self.total_minted = int(data['total_minted'])
        self.total_burned = int(data['total_burned'])
        self.total_supply = int(data.get('total_supply', 0))
        self.total_usd_in = Decimal(data['total_usd_in'])
        self.total_usd_out = Decimal(data['total_usd_out'])
    
    def to_dict(self) -> dict:
        """
        Convert to dict for storage.
        """
        return {
            'total_minted': self.total_minted,
            'total_burned': self.total_burned,
            'total_supply': self.total_supply,
            'total_usd_in': str(self.total_usd_in),
            'total_usd_out': str(self.total_usd_out),
        }
    
    @property
    def circulating_supply(self) -> int:
        """
        Calculate circulating supply in the smallest unit.
        
        Formula: Total Minted - Total Burned
        
        Note: This doesn't account for tokens locked in AMM pool,
        which is intentional - those are still "in circulation"
        from an economic perspective.
        """
        return self.total_minted - self.total_burned
    
    @property
    def net_usd_flow(self) -> Decimal:
        """
        Calculate net USD flow (historical tracking).
        
        Formula: Total USD In - Total USD Out
        
        This is now just for analytics/statistics.
        Actual price is determined by AMM pool reserves.
        """
        return self.total_usd_in - self.total_usd_out
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        from crypto_v2.chain import TOKEN_UNIT
        
        supply_tokens = Decimal(self.circulating_supply) / Decimal(TOKEN_UNIT)
        
        return (
            f"TokenomicsState("
            f"minted={self.total_minted}, "
            f"burned={self.total_burned}, "
            f"circulating={supply_tokens} tokens, "
            f"net_usd_flow=${self.net_usd_flow})"
        )