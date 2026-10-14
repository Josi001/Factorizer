# ============================================================================
#  RSA KEY GENERATION (utils/rsa_utils.py)
# ============================================================================
from typing import Tuple
from .prime_utils import PrimeUtils


class RSAKeyGenerator:
    """RSA key generation with different prime characteristics."""

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Calculate the greatest common divisor."""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean algorithm."""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSAKeyGenerator.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    @staticmethod
    def mod_inverse(e: int, phi: int) -> int:
        """Calculate modular multiplicative inverse."""
        gcd, x, _ = RSAKeyGenerator.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    @staticmethod
    def generate_keys(p: int, q: int, e: int = 65537) -> dict:
        """
        Generate RSA key pair from primes p and q.
        Returns dict with public and private keys plus metadata.
        """
        if p == q:
            raise ValueError("p and q must be different primes")

        n = p * q
        phi = (p - 1) * (q - 1)

        # Ensure e is coprime to phi
        if RSAKeyGenerator.gcd(e, phi) != 1:
            e = 65537
            while RSAKeyGenerator.gcd(e, phi) != 1:
                e += 2

        d = RSAKeyGenerator.mod_inverse(e, phi)

        return {
            'public_key': {'n': n, 'e': e},
            'private_key': {'n': n, 'd': d},
            'primes': {'p': p, 'q': q},
            'metadata': {
                'bit_length': n.bit_length(),
                'p_bit_length': p.bit_length(),
                'q_bit_length': q.bit_length(),
                'prime_difference': abs(p - q),
                'phi': phi
            }
        }

    @staticmethod
    def generate_by_type(prime_type: str, bits: int = 512) -> dict:
        """
        Generate RSA keys based on prime characteristics.

        Types:
        - 'standard': Normal random primes
        - 'small': Small bit-length primes (weaker)
        - 'large': Large bit-length primes (stronger)
        - 'close': Primes close to each other (weaker)
        - 'widely_spaced': Primes far apart (stronger)
        - 'equal': p = q (completely broken, for demonstration)
        """
        if prime_type == 'standard':
            p = PrimeUtils.generate_prime(bits)
            q = PrimeUtils.generate_prime(bits)

        elif prime_type == 'small':
            p = PrimeUtils.generate_prime(bits // 2)
            q = PrimeUtils.generate_prime(bits // 2)

        elif prime_type == 'large':
            p = PrimeUtils.generate_prime(bits * 2)
            q = PrimeUtils.generate_prime(bits * 2)

        elif prime_type == 'close':
            p, q = PrimeUtils.generate_close_primes(bits)

        elif prime_type == 'widely_spaced':
            p, q = PrimeUtils.generate_widely_spaced_primes(bits)

        elif prime_type == 'equal':
            p = PrimeUtils.generate_prime(bits)
            q = p  # Intentionally broken

        else:
            raise ValueError(f"Unknown prime type: {prime_type}")

        return RSAKeyGenerator.generate_keys(p, q)

