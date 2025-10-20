"""
Complete tokenomics implementation for blockchain with proper price discovery.
"""
from decimal import Decimal
from typing import Optional, Dict
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class TokenomicsState:
    """Current state of the tokenomics system."""
    total_minted: Decimal
    total_burned: Decimal
    total_usd_in: Decimal
    total_usd_out: Decimal
    treasury_token_balance: Decimal
    
    @property
    def circulating_supply(self) -> Decimal:
        """Calculate circulating supply."""
        return self.total_minted - self.total_burned
    
    @property
    def net_treasury_usd(self) -> Decimal:
        """Calculate net USD in treasury."""
        return self.total_usd_in - self.total_usd_out
    
    @property
    def current_price(self) -> Decimal:
        """Calculate current token price."""
        if self.circulating_supply <= 0:
            return Decimal('1.00')  # Initial price
        
        # Price = Net Treasury USD / Circulating Supply
        price = self.net_treasury_usd / self.circulating_supply
        
        # Floor price at $0.01 to prevent division issues
        return max(price, Decimal('0.01'))
    
    @property
    def reserve_ratio(self) -> Decimal:
        """Calculate current reserve ratio."""
        if self.circulating_supply <= 0:
            return Decimal('1.0')
        
        market_cap = self.circulating_supply * self.current_price
        if market_cap <= 0:
            return Decimal('0')
        
        return self.net_treasury_usd / market_cap


class TokenomicsEngine:
    """
    Core tokenomics engine for the blockchain.
    
    Key Principles:
    1. Price = Net Treasury USD / Circulating Supply
    2. Tokens only minted when treasury inventory is depleted
    3. Redemptions can lower price (USD leaves system)
    4. Burns reduce supply (increases price)
    5. Reserve ratio prevents insolvency
    """
    
    # Configuration
    INITIAL_PRICE = Decimal('1.00')
    MIN_RESERVE_RATIO = Decimal('0.30')  # 30% reserve requirement
    GAME_FEE_SPLIT = {
        'treasury': Decimal('0.70'),  # 70%
        'leader': Decimal('0.20'),    # 20%
        'burn': Decimal('0.10')       # 10%
    }
    
    def __init__(self, blockchain):
        """Initialize with blockchain reference."""
        self.blockchain = blockchain
        self.state = self._load_state()
    
    def _load_state(self) -> TokenomicsState:
        """Load current tokenomics state from blockchain."""
        # This would query the blockchain state trie
        # For now, return initial state
        return TokenomicsState(
            total_minted=Decimal('0'),
            total_burned=Decimal('0'),
            total_usd_in=Decimal('0'),
            total_usd_out=Decimal('0'),
            treasury_token_balance=Decimal('0')
        )
    
    def get_token_price(self) -> Decimal:
        """Get current token price in USD."""
        return self.state.current_price
    
    def calculate_token_cost(self, usd_amount: Decimal) -> Decimal:
        """
        Convert USD amount to token amount at current price.
        
        Args:
            usd_amount: USD value (e.g., $0.25 for a game)
        
        Returns:
            Number of tokens required
        """
        price = self.get_token_price()
        return usd_amount / price
    
    def purchase_tokens(self, buyer_address: bytes, usd_amount: Decimal) -> Dict:
        """
        Process token purchase with smart inventory management.
        
        Flow:
        1. Calculate tokens to buy at current price
        2. Check treasury token inventory
        3. Transfer from treasury if available (secondary market)
        4. Mint new tokens if treasury depleted (primary market)
        5. Update price after transaction
        
        Args:
            buyer_address: Blockchain address of buyer
            usd_amount: USD amount paid via Stripe
        
        Returns:
            Dict with transaction details
        """
        current_price = self.get_token_price()
        tokens_to_buy = usd_amount / current_price
        
        logger.info(f"Purchase request: {usd_amount} USD = {tokens_to_buy} tokens @ ${current_price}")
        
        # Check treasury inventory
        if self.state.treasury_token_balance >= tokens_to_buy:
            # SECONDARY MARKET: Transfer from treasury
            return self._transfer_from_treasury(
                buyer_address, tokens_to_buy, usd_amount
            )
        else:
            # MIXED: Transfer what treasury has, mint the rest
            treasury_tokens = self.state.treasury_token_balance
            tokens_to_mint = tokens_to_buy - treasury_tokens
            
            result = {'success': True, 'breakdown': []}
            
            if treasury_tokens > 0:
                # Transfer available treasury tokens
                transfer_usd = treasury_tokens * current_price
                result['breakdown'].append(
                    self._transfer_from_treasury(
                        buyer_address, treasury_tokens, transfer_usd
                    )
                )
            
            # Mint remaining tokens
            mint_usd = tokens_to_mint * current_price
            result['breakdown'].append(
                self._mint_new_tokens(
                    buyer_address, tokens_to_mint, mint_usd
                )
            )
            
            result['total_tokens'] = tokens_to_buy
            result['total_usd'] = usd_amount
            result['new_price'] = self.get_token_price()
            
            return result
    
    def _transfer_from_treasury(self, buyer: bytes, tokens: Decimal, 
                                usd: Decimal) -> Dict:
        """
        Transfer tokens from treasury (secondary market).
        
        This is treasury revenue - converting tokens back to USD.
        """
        # Get treasury address
        treasury_address = self._get_treasury_address()
        
        # Transfer tokens on blockchain
        self.blockchain.transfer_tokens(
            from_address=treasury_address,
            to_address=buyer,
            amount=tokens
        )
        
        # Update tokenomics state
        self.state.treasury_token_balance -= tokens
        self.state.total_usd_in += usd  # USD enters system
        
        logger.info(f"Secondary sale: {tokens} tokens for ${usd}")
        
        return {
            'type': 'SECONDARY_MARKET',
            'tokens': tokens,
            'usd': usd,
            'source': 'treasury_inventory'
        }
    
    def _mint_new_tokens(self, buyer: bytes, tokens: Decimal, 
                        usd: Decimal) -> Dict:
        """
        Mint new tokens (primary market).
        
        Only happens when treasury inventory is depleted.
        """
        # Mint tokens on blockchain
        self.blockchain.mint_tokens(
            to_address=buyer,
            amount=tokens
        )
        
        # Update tokenomics state
        self.state.total_minted += tokens
        self.state.total_usd_in += usd
        
        logger.info(f"Minted: {tokens} tokens for ${usd}")
        
        return {
            'type': 'PRIMARY_MARKET',
            'tokens': tokens,
            'usd': usd,
            'source': 'new_mint'
        }
    
    def process_game_fee(self, player: bytes, game_id: str, 
                        usd_price: Decimal, leader: Optional[bytes] = None) -> Dict:
        """
        Process game fee with 3-way split.
        
        Split: 70% Treasury, 20% Leader, 10% Burn
        
        Args:
            player: Player's blockchain address
            game_id: Game identifier
            usd_price: USD price of game (e.g., $0.25)
            leader: Current leaderboard leader address (optional)
        
        Returns:
            Transaction details
        """
        # Calculate token cost at current price
        token_cost = self.calculate_token_cost(usd_price)
        
        # Check player balance
        player_balance = self.blockchain.get_balance(player)
        if player_balance < token_cost:
            return {
                'success': False,
                'error': 'Insufficient balance',
                'required': token_cost,
                'available': player_balance
            }
        
        # Calculate splits
        treasury_amount = token_cost * self.GAME_FEE_SPLIT['treasury']
        leader_amount = token_cost * self.GAME_FEE_SPLIT['leader']
        burn_amount = token_cost * self.GAME_FEE_SPLIT['burn']
        
        treasury_address = self._get_treasury_address()
        
        # Execute transfers
        # 1. Treasury share (70%)
        self.blockchain.transfer_tokens(player, treasury_address, treasury_amount)
        self.state.treasury_token_balance += treasury_amount
        
        # 2. Leader share (20%)
        if leader:
            self.blockchain.transfer_tokens(player, leader, leader_amount)
        else:
            # No leader yet, give to treasury
            self.blockchain.transfer_tokens(player, treasury_address, leader_amount)
            self.state.treasury_token_balance += leader_amount
        
        # 3. Burn (10%)
        self.blockchain.burn_tokens(player, burn_amount)
        self.state.total_burned += burn_amount
        
        logger.info(
            f"Game fee processed: {token_cost} tokens "
            f"(T:{treasury_amount}, L:{leader_amount}, B:{burn_amount})"
        )
        
        return {
            'success': True,
            'tokens_spent': token_cost,
            'usd_equivalent': usd_price,
            'treasury_share': treasury_amount,
            'leader_share': leader_amount,
            'burned': burn_amount,
            'new_price': self.get_token_price()
        }
    
    def redeem_tokens(self, user: bytes, token_amount: Decimal, 
                     crypto_type: str) -> Dict:
        """
        Redeem tokens for crypto (BTC/ETH).
        
        This is critical: USD leaves the system, which can lower price.
        
        Args:
            user: User's blockchain address
            token_amount: Tokens to redeem
            crypto_type: 'BTC' or 'ETH'
        
        Returns:
            Redemption details or error
        """
        # Check user balance
        user_balance = self.blockchain.get_balance(user)
        if user_balance < token_amount:
            return {
                'success': False,
                'error': 'Insufficient balance'
            }
        
        # Calculate USD value at current price
        current_price = self.get_token_price()
        usd_value = token_amount * current_price
        
        # Check if redemption violates reserve ratio
        if not self._can_allow_redemption(token_amount, usd_value):
            return {
                'success': False,
                'error': 'Insufficient treasury reserves',
                'max_redemption': self._calculate_max_redemption(user)
            }
        
        # Burn tokens
        self.blockchain.burn_tokens(user, token_amount)
        self.state.total_burned += token_amount
        
        # Record USD outflow
        self.state.total_usd_out += usd_value
        
        logger.info(
            f"Redemption: {token_amount} tokens for ${usd_value} "
            f"({crypto_type})"
        )
        
        return {
            'success': True,
            'tokens_burned': token_amount,
            'usd_value': usd_value,
            'crypto_type': crypto_type,
            'new_price': self.get_token_price(),
            'new_reserve_ratio': self.state.reserve_ratio
        }
    
    def _can_allow_redemption(self, token_amount: Decimal, 
                             usd_value: Decimal) -> bool:
        """
        Check if redemption maintains minimum reserve ratio.
        
        Reserve Ratio = Treasury USD / (Circulating Supply × Price)
        """
        new_usd_balance = self.state.net_treasury_usd - usd_value
        new_circulating = self.state.circulating_supply - token_amount
        
        if new_circulating <= 0:
            return True  # Last token can always be redeemed
        
        # Calculate new price after redemption
        new_price = new_usd_balance / new_circulating
        
        # Calculate new market cap
        new_market_cap = new_circulating * new_price
        
        if new_market_cap <= 0:
            return False
        
        # Calculate new reserve ratio
        new_reserve_ratio = new_usd_balance / new_market_cap
        
        return new_reserve_ratio >= self.MIN_RESERVE_RATIO
    
    def _calculate_max_redemption(self, user: bytes) -> Decimal:
        """
        Calculate maximum tokens user can redeem while maintaining reserves.
        
        Uses binary search to find maximum amount.
        """
        user_balance = self.blockchain.get_balance(user)
        
        # Binary search for max redeemable amount
        left, right = Decimal('0'), user_balance
        max_redeemable = Decimal('0')
        
        for _ in range(100):  # Max iterations
            mid = (left + right) / 2
            usd_value = mid * self.get_token_price()
            
            if self._can_allow_redemption(mid, usd_value):
                max_redeemable = mid
                left = mid
            else:
                right = mid
            
            if right - left < Decimal('0.000001'):
                break
        
        return max_redeemable
    
    def _get_treasury_address(self) -> bytes:
        """Get treasury address from blockchain."""
        # This would be a reserved address in your blockchain
        return b'\x00' * 19 + b'\xFF'  # Example treasury address
    
    def get_stats(self) -> Dict:
        """Get comprehensive tokenomics statistics."""
        return {
            'current_price': self.state.current_price,
            'circulating_supply': self.state.circulating_supply,
            'total_minted': self.state.total_minted,
            'total_burned': self.state.total_burned,
            'net_treasury_usd': self.state.net_treasury_usd,
            'treasury_token_balance': self.state.treasury_token_balance,
            'reserve_ratio': self.state.reserve_ratio,
            'min_reserve_ratio': self.MIN_RESERVE_RATIO,
            'total_usd_in': self.state.total_usd_in,
            'total_usd_out': self.state.total_usd_out,
        }
