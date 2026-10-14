# ============================================================================
#  STRENGTH ANALYSIS (utils/strength_analyzer.py)
# ============================================================================
import math
import time
from typing import List

from .rsa_crypto import RSACrypto


class StrengthAnalyzer:
    """Analyze RSA key strength using various methods."""

    @staticmethod
    def trial_division(n: int, max_attempts: int = 10000) -> dict:
        """Try to factor n using trial division."""
        start = time.time()

        if n % 2 == 0:
            elapsed = time.time() - start
            return {
                'method': 'trial_division',
                'success': True,
                'factor': 2,
                'time_taken': elapsed,
                'attempts': 1
            }

        for i in range(3, min(int(math.sqrt(n)) + 1, max_attempts), 2):
            if n % i == 0:
                elapsed = time.time() - start
                return {
                    'method': 'trial_division',
                    'success': True,
                    'factor': i,
                    'time_taken': elapsed,
                    'attempts': (i - 3) // 2 + 1
                }

        elapsed = time.time() - start
        return {
            'method': 'trial_division',
            'success': False,
            'time_taken': elapsed,
            'attempts': max_attempts
        }

    @staticmethod
    def fermat_factorization(n: int, max_attempts: int = 100000) -> dict:
        """Try to factor n using Fermat's factorization (good for close primes)."""
        start = time.time()

        a = math.isqrt(n) + 1
        b2 = a * a - n

        for attempt in range(max_attempts):
            b = math.isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                elapsed = time.time() - start
                return {
                    'method': 'fermat_factorization',
                    'success': True,
                    'factors': [p, q],
                    'time_taken': elapsed,
                    'attempts': attempt + 1
                }
            a += 1
            b2 = a * a - n

        elapsed = time.time() - start
        return {
            'method': 'fermat_factorization',
            'success': False,
            'time_taken': elapsed,
            'attempts': max_attempts
        }

    @staticmethod
    def pollard_rho(n: int, max_attempts: int = 100000) -> dict:
        """Pollard's rho algorithm for factorization."""
        start = time.time()

        if n % 2 == 0:
            elapsed = time.time() - start
            return {
                'method': 'pollard_rho',
                'success': True,
                'factor': 2,
                'time_taken': elapsed,
                'attempts': 1
            }

        x, y, d = 2, 2, 1
        f = lambda x: (x * x + 1) % n

        for attempt in range(max_attempts):
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)

            if 1 < d < n:
                elapsed = time.time() - start
                return {
                    'method': 'pollard_rho',
                    'success': True,
                    'factor': d,
                    'time_taken': elapsed,
                    'attempts': attempt + 1
                }

            if d == n:
                break

        elapsed = time.time() - start
        return {
            'method': 'pollard_rho',
            'success': False,
            'time_taken': elapsed,
            'attempts': max_attempts
        }

    @staticmethod
    def estimate_crack_time(n: int, factorization_results: List[dict]) -> dict:
        """
        Estimate time to crack based on actual attempts and extrapolation.
        """
        bit_length = n.bit_length()

        # Empirical estimates based on bit length
        # These are rough estimates based on current computing power
        estimates = {
            'trial_division': {
                'operations': 2 ** (bit_length / 2),
                'ops_per_second': 10 ** 9  # 1 billion ops/sec
            },
            'pollard_rho': {
                'operations': 2 ** (bit_length / 4),
                'ops_per_second': 10 ** 8
            },
            'quadratic_sieve': {
                'operations': math.exp(math.sqrt(bit_length * math.log(2) * math.log(bit_length * math.log(2)))),
                'ops_per_second': 10 ** 7
            },
            'number_field_sieve': {
                'operations': math.exp(((64 / 9) ** (1 / 3)) * (bit_length * math.log(2)) ** (1 / 3) *
                                       (math.log(bit_length * math.log(2))) ** (2 / 3)),
                'ops_per_second': 10 ** 6
            }
        }

        results = {}
        for method, params in estimates.items():
            seconds = params['operations'] / params['ops_per_second']
            results[method] = {
                'estimated_seconds': seconds,
                'estimated_years': seconds / (365.25 * 24 * 3600),
                'estimated_operations': params['operations']
            }

        # Check if any factorization succeeded
        cracked = any(r.get('success', False) for r in factorization_results)

        return {
            'bit_length': bit_length,
            'cracked': cracked,
            'factorization_attempts': factorization_results,
            'time_estimates': results,
            'security_assessment': StrengthAnalyzer._assess_security(bit_length, cracked)
        }

    @staticmethod
    def _assess_security(bit_length: int, cracked: bool) -> str:
        """Provide security assessment."""
        if cracked:
            return "CRITICALLY WEAK - Factorization succeeded"
        elif bit_length < 512:
            return "VERY WEAK - Factorizable with moderate resources"
        elif bit_length < 1024:
            return "WEAK - Not recommended for security"
        elif bit_length < 2048:
            return "MODERATE - Minimum acceptable for non-critical use"
        elif bit_length < 4096:
            return "STRONG - Suitable for most applications"
        else:
            return "VERY STRONG - High security"

    @staticmethod
    def analyze_key_strength(keys: dict, test_message: str = "Test") -> dict:
        """
        Comprehensive strength analysis of RSA keys.
        """
        n = keys['public_key']['n']
        p = keys['primes']['p']
        q = keys['primes']['q']

        # Try various factorization methods
        factorization_results = []

        # Trial division (quick check)
        factorization_results.append(StrengthAnalyzer.trial_division(n, max_attempts=10000))

        # Fermat's method (good for close primes)
        factorization_results.append(StrengthAnalyzer.fermat_factorization(n, max_attempts=100000))

        # Pollard's rho
        factorization_results.append(StrengthAnalyzer.pollard_rho(n, max_attempts=100000))

        # Get time estimates
        crack_estimate = StrengthAnalyzer.estimate_crack_time(n, factorization_results)

        # Analyze prime characteristics
        prime_analysis = {
            'p_q_ratio': max(p, q) / min(p, q),
            'difference': abs(p - q),
            'difference_percentage': (abs(p - q) / max(p, q)) * 100,
            'are_close': abs(p - q) < math.sqrt(n) / 1000,
            'p_equals_q': p == q
        }

        # Encrypt and verify decryption works
        try:
            ciphertext = RSACrypto.encrypt(test_message, keys['public_key'])
            decrypted = RSACrypto.decrypt(ciphertext, keys['private_key'])
            encryption_works = decrypted == test_message
        except Exception as e:
            encryption_works = False
            ciphertext = None

        return {
            'key_metadata': keys['metadata'],
            'prime_analysis': prime_analysis,
            'encryption_test': {
                'works': encryption_works,
                'test_message': test_message,
                'ciphertext': str(ciphertext) if ciphertext else None
            },
            'strength_analysis': crack_estimate,
            'vulnerabilities': StrengthAnalyzer._identify_vulnerabilities(prime_analysis, crack_estimate)
        }

    @staticmethod
    def _identify_vulnerabilities(prime_analysis: dict, crack_estimate: dict) -> List[str]:
        """Identify specific vulnerabilities."""
        vulnerabilities = []

        if prime_analysis['p_equals_q']:
            vulnerabilities.append("CRITICAL: p equals q - trivial to crack")

        if prime_analysis['are_close']:
            vulnerabilities.append("HIGH: Primes are too close - vulnerable to Fermat's factorization")

        if prime_analysis['difference_percentage'] < 1:
            vulnerabilities.append("MEDIUM: Small prime difference increases factorization risk")

        if crack_estimate['bit_length'] < 1024:
            vulnerabilities.append("HIGH: Key size too small for modern standards")

        if crack_estimate['cracked']:
            vulnerabilities.append("CRITICAL: Successfully factored with basic algorithms")

        if not vulnerabilities:
            vulnerabilities.append("No major vulnerabilities detected")

        return vulnerabilities
