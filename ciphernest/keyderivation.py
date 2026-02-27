import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


class KeyDerivation:
    """
    Provides password-based key derivation using PBKDF2.
    """

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        """
        Derives a secure key from a password.
        Returns derived key and salt.
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
