# ============================================================================
# RSA ENCRYPTION/DECRYPTION (utils/rsa_crypto.py)
# ============================================================================

class RSACrypto:
    """RSA encryption and decryption operations."""

    @staticmethod
    def text_to_number(text: str) -> int:
        """Convert text to integer."""
        return int.from_bytes(text.encode('utf-8'), byteorder='big')

    @staticmethod
    def number_to_text(number: int) -> str:
        """Convert integer back to text."""
        byte_length = (number.bit_length() + 7) // 8
        return number.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')

    @staticmethod
    def encrypt(message: str, public_key: dict) -> int:
        """Encrypt message using public key."""
        m = RSACrypto.text_to_number(message)
        n, e = public_key['n'], public_key['e']

        if m >= n:
            raise ValueError("Message too long for key size")

        return pow(m, e, n)

    @staticmethod
    def decrypt(ciphertext: int, private_key: dict) -> str:
        """Decrypt ciphertext using private key."""
        n, d = private_key['n'], private_key['d']
        m = pow(ciphertext, d, n)
        return RSACrypto.number_to_text(m)

