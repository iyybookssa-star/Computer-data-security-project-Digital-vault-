from Crypto.Cipher import AES

NONCE_SIZE = 16  # AES-GCM recommended nonce size
TAG_SIZE = 16    # GCM authentication tag size


def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Encrypt a file using AES-256-GCM.

    Reads the entire plaintext file, encrypts it, and writes the
    nonce + tag + ciphertext to the output file.

    Args:
        input_path: Path to the plaintext file.
        output_path: Path to write the encrypted output.
        key: 32-byte (256-bit) encryption key.

    Raises:
        FileNotFoundError: If the input file does not exist.
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(output_path, "wb") as f:
        f.write(cipher.nonce)  # 16 bytes
        f.write(tag)           # 16 bytes
        f.write(ciphertext)    # variable length


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Decrypt a file that was encrypted with AES-256-GCM.

    Reads the nonce + tag + ciphertext from the input file, decrypts
    and verifies the authentication tag, then writes the plaintext.

    Args:
        input_path: Path to the encrypted file.
        output_path: Path to write the decrypted output.
        key: 32-byte (256-bit) encryption key.

    Raises:
        FileNotFoundError: If the input file does not exist.
        ValueError: If the encrypted file is too small to be valid.
        ValueError: If decryption fails (wrong key or tampered data).
    """
    with open(input_path, "rb") as f:
        data = f.read()

    min_size = NONCE_SIZE + TAG_SIZE
    if len(data) < min_size:
        raise ValueError(
            f"Encrypted file is too small ({len(data)} bytes). "
            f"Minimum expected size is {min_size} bytes."
        )

    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE :]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError):
        raise ValueError(
            "Decryption failed! Wrong password or the file has been tampered with."
        )

    with open(output_path, "wb") as f:
        f.write(plaintext)
