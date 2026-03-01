"""
Key Management Module for Digital Vault.

Handles password-based key derivation using PBKDF2-HMAC-SHA256,
salt generation, and salt file persistence.
"""

import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC

# OWASP-recommended iteration count for PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32  # 256 bits
SALT_LENGTH = 32  # 256 bits


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The user's password string.
        salt: A random salt (should be unique per encryption).

    Returns:
        A 32-byte (256-bit) derived key.
    """
    key = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest(),
    )
    return key


def save_salt(salt: bytes, path: str) -> None:
    """
    Save the salt to a file for later use during decryption.

    Args:
        salt: The salt bytes to persist.
        path: File path to write the salt to.
    """
    with open(path, "wb") as f:
        f.write(salt)


def load_salt(path: str) -> bytes:
    """
    Load a previously saved salt from a file.

    Args:
        path: File path to read the salt from.

    Returns:
        The salt bytes.

    Raises:
        FileNotFoundError: If the salt file does not exist.
        ValueError: If the salt file has an unexpected size.
    """
    with open(path, "rb") as f:
        salt = f.read()

    if len(salt) != SALT_LENGTH:
        raise ValueError(
            f"Invalid salt file: expected {SALT_LENGTH} bytes, got {len(salt)}."
        )

    return salt
