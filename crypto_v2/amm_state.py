"""
AMM (Automated Market Maker) liquidity pool state.
Implements constant product formula: x * y = k
"""
from decimal import Decimal


class LiquidityPoolState:
    """
    Represents the AMM liquidity pool state stored on-chain.
    
    Uses the constant product formula (Uniswap V2 style):
    token_reserve * usd_reserve = k (constant)
    """
    
    # Fee configuration (30 basis points = 0.30%)
    FEE_NUMERATOR = 997  # Keep 99.7% of input
    FEE_DENOMINATOR = 1000
    
    def __init__(self, data: dict = None):
        """
        Initialize liquidity pool state.
        
        Args:
            data: Dict with pool reserves and LP token supply
        """
        if data is None:
            data = {
                'token_reserve': 0,
                'usd_reserve': 0,
                'lp_token_supply': 0,
            }
        
        self.token_reserve = int(data['token_reserve'])
        self.usd_reserve = int(data['usd_reserve'])
        self.lp_token_supply = int(data['lp_token_supply'])
    
    def to_dict(self) -> dict:
        """
        Convert to dict for storage.
        """
        return {
            'token_reserve': self.token_reserve,
            'usd_reserve': self.usd_reserve,
            'lp_token_supply': self.lp_token_supply,
        }
    
    @property
    def current_price(self) -> Decimal:
        """
        Calculate current token price in USD.
        
        Price = USD Reserve / Token Reserve
        
        Returns:
            Price of 1 token in USD
        """
        if self.token_reserve == 0:
            return Decimal('1.0')  # Default initial price
        
        from crypto_v2.chain import TOKEN_UNIT
        
        # Convert to decimal for precision
        usd_in_pool = Decimal(self.usd_reserve) / Decimal(TOKEN_UNIT)
        tokens_in_pool = Decimal(self.token_reserve) / Decimal(TOKEN_UNIT)
        
        return usd_in_pool / tokens_in_pool
    
    def get_swap_output(self, input_amount: int, input_is_token: bool) -> int:
        """
        Calculate swap output using constant product formula with fees.
        
        Formula: (x + Δx * 0.997) * (y - Δy) = x * y
        Solving for Δy: Δy = (y * Δx * 0.997) / (x + Δx * 0.997)
        
        Args:
            input_amount: Amount of input asset (in smallest unit)
            input_is_token: True if swapping tokens for USD, False if USD for tokens
        
        Returns:
            Amount of output asset (in smallest unit)
        """
        if input_amount <= 0:
            return 0
        
        # Apply fee (keep 99.7% of input)
        input_with_fee = (input_amount * self.FEE_NUMERATOR) // self.FEE_DENOMINATOR
        
        if input_is_token:
            # Selling tokens for USD
            # output_usd = (usd_reserve * input_tokens * 0.997) / (token_reserve + input_tokens * 0.997)
            numerator = input_with_fee * self.usd_reserve
            denominator = self.token_reserve + input_with_fee
            
            if denominator == 0:
                return 0
            
            return numerator // denominator
        else:
            # Buying tokens with USD
            # output_tokens = (token_reserve * input_usd * 0.997) / (usd_reserve + input_usd * 0.997)
            numerator = input_with_fee * self.token_reserve
            denominator = self.usd_reserve + input_with_fee
            
            if denominator == 0:
                return 0
            
            return numerator // denominator
    
    def get_required_usd(self, token_amount: int) -> int:
        """
        Calculate USD needed to add liquidity with given tokens.
        
        Maintains pool ratio: usd_amount / token_amount = usd_reserve / token_reserve
        
        Args:
            token_amount: Amount of tokens to add
        
        Returns:
            Required USD amount
        """
        if self.token_reserve == 0:
            return token_amount  # 1:1 ratio for first LP
        
        return (token_amount * self.usd_reserve) // self.token_reserve
    
    def get_required_tokens(self, usd_amount: int) -> int:
        """
        Calculate tokens needed to add liquidity with given USD.
        
        Args:
            usd_amount: Amount of USD to add
        
        Returns:
            Required token amount
        """
        if self.usd_reserve == 0:
            return usd_amount  # 1:1 ratio for first LP
        
        return (usd_amount * self.token_reserve) // self.usd_reserve
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"LiquidityPoolState("
            f"token_reserve={self.token_reserve}, "
            f"usd_reserve={self.usd_reserve}, "
            f"lp_supply={self.lp_token_supply}, "
            f"price=${self.current_price})"
        )