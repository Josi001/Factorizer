# ============================================================================
#  PRIME NUMBER UTILITIES (utils/prime_utils.py)
# ============================================================================

import random
from typing import Tuple


class PrimeUtils:
    """Utilities for generating and working with prime numbers."""

    @staticmethod
    def is_prime(n: int, k: int = 5) -> bool:
        """Miller-Rabin primality test."""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits: int) -> int:
        """Generate a prime number with specified bit length."""
        while True:
            n = random.getrandbits(bits) | (1 << bits - 1) | 1
            if PrimeUtils.is_prime(n):
                return n

    @staticmethod
    def generate_prime_in_range(min_val: int, max_val: int) -> int:
        """Generate a prime within a specific range."""
        while True:
            n = random.randint(min_val, max_val)
            if n % 2 == 0:
                n += 1
            if PrimeUtils.is_prime(n):
                return n

    @staticmethod
    def generate_close_primes(bits: int, max_distance: int = 1000) -> Tuple[int, int]:
        """Generate two primes that are close to each other."""
        p = PrimeUtils.generate_prime(bits)
        q = PrimeUtils.generate_prime_in_range(p + 2, p + max_distance)
        return p, q

    @staticmethod
    def generate_widely_spaced_primes(bits: int) -> Tuple[int, int]:
        """Generate two primes with significant difference."""
        p = PrimeUtils.generate_prime(bits)
        min_distance = 2 ** (bits - 2)
        q = PrimeUtils.generate_prime_in_range(p + min_distance, p + 2 * min_distance)
        return p, q
