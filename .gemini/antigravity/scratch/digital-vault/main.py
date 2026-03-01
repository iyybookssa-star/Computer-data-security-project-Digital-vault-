"""
Digital Vault — CLI Entry Point

Encrypt and decrypt local files using AES-256-GCM with
password-based key derivation (PBKDF2-HMAC-SHA256).

Usage:
    python main.py encrypt <file>
    python main.py decrypt <file>.vault
"""

import sys
import os
import getpass
import argparse

from key_manager import generate_salt, derive_key, save_salt, load_salt
from vault_crypto import encrypt_file, decrypt_file

# ── ANSI colours for terminal output ──────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

VAULT_EXT = ".vault"
SALT_EXT = ".salt"

BANNER = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════╗
║           🔐  DIGITAL VAULT  🔐          ║
║   AES-256-GCM File Encryption Utility    ║
╚══════════════════════════════════════════╝{RESET}
"""


def print_status(message: str, color: str = GREEN) -> None:
    """Print a colour-coded status message."""
    print(f"  {color}▸{RESET} {message}")


def print_error(message: str) -> None:
    """Print an error message in red."""
    print(f"\n  {RED}{BOLD}✗ ERROR:{RESET} {message}")


def print_success(message: str) -> None:
    """Print a success message in green."""
    print(f"\n  {GREEN}{BOLD}✓ SUCCESS:{RESET} {message}")


def get_password(confirm: bool = False) -> str:
    """
    Securely prompt the user for a password.

    Args:
        confirm: If True, ask the user to confirm the password.

    Returns:
        The password string.
    """
    password = getpass.getpass(f"  {YELLOW}🔑 Enter password:{RESET} ")

    if not password:
        print_error("Password cannot be empty.")
        sys.exit(1)

    if confirm:
        password2 = getpass.getpass(f"  {YELLOW}🔑 Confirm password:{RESET} ")
        if password != password2:
            print_error("Passwords do not match.")
            sys.exit(1)

    return password


def handle_encrypt(file_path: str) -> None:
    """Encrypt a file and save the vault + salt files."""

    if not os.path.isfile(file_path):
        print_error(f"File not found: {file_path}")
        sys.exit(1)

    vault_path = file_path + VAULT_EXT
    salt_path = file_path + SALT_EXT

    if os.path.exists(vault_path):
        print_error(f"Vault file already exists: {vault_path}")
        print_status("Delete or rename it before encrypting again.", YELLOW)
        sys.exit(1)

    print(BANNER)
    print_status(f"Encrypting: {BOLD}{file_path}{RESET}")
    print()

    password = get_password(confirm=True)

    print()
    print_status("Generating salt…")
    salt = generate_salt()
    save_salt(salt, salt_path)

    print_status("Deriving encryption key (PBKDF2, 600k iterations)…")
    key = derive_key(password, salt)

    print_status("Encrypting file with AES-256-GCM…")
    encrypt_file(file_path, vault_path, key)

    file_size = os.path.getsize(file_path)
    vault_size = os.path.getsize(vault_path)

    print_success("File encrypted successfully!")
    print()
    print(f"  {CYAN}📄 Original :{RESET} {file_path} ({file_size:,} bytes)")
    print(f"  {CYAN}🔒 Encrypted:{RESET} {vault_path} ({vault_size:,} bytes)")
    print(f"  {CYAN}🧂 Salt file :{RESET} {salt_path}")
    print()
    print(f"  {YELLOW}⚠  Keep the salt file — you need it to decrypt!{RESET}")
    print()


def handle_decrypt(file_path: str) -> None:
    """Decrypt a vault file back to its original content."""

    if not os.path.isfile(file_path):
        print_error(f"File not found: {file_path}")
        sys.exit(1)

    if not file_path.endswith(VAULT_EXT):
        print_error(f"Expected a '{VAULT_EXT}' file, got: {file_path}")
        sys.exit(1)

    # Derive the salt file path from the vault file name
    # e.g. "photo.jpg.vault" → "photo.jpg.salt"
    base_path = file_path[: -len(VAULT_EXT)]
    salt_path = base_path + SALT_EXT
    output_path = base_path + ".decrypted"

    if not os.path.isfile(salt_path):
        print_error(f"Salt file not found: {salt_path}")
        print_status(
            "The salt file is required for decryption. "
            "It was created alongside the vault file during encryption.",
            YELLOW,
        )
        sys.exit(1)

    print(BANNER)
    print_status(f"Decrypting: {BOLD}{file_path}{RESET}")
    print()

    password = get_password(confirm=False)

    print()
    print_status("Loading salt…")
    salt = load_salt(salt_path)

    print_status("Deriving decryption key (PBKDF2, 600k iterations)…")
    key = derive_key(password, salt)

    print_status("Decrypting and verifying integrity (AES-256-GCM)…")
    try:
        decrypt_file(file_path, output_path, key)
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    output_size = os.path.getsize(output_path)

    print_success("File decrypted successfully!")
    print()
    print(f"  {CYAN}🔒 Encrypted:{RESET} {file_path}")
    print(f"  {CYAN}📄 Decrypted:{RESET} {output_path} ({output_size:,} bytes)")
    print()


def main() -> None:
    """Parse arguments and dispatch to encrypt/decrypt handlers."""

    parser = argparse.ArgumentParser(
        prog="Digital Vault",
        description="Encrypt and decrypt files using AES-256-GCM.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # encrypt subcommand
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("file", help="Path to the file to encrypt")

    # decrypt subcommand
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a .vault file")
    dec_parser.add_argument("file", help="Path to the .vault file to decrypt")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "encrypt":
        handle_encrypt(args.file)
    elif args.command == "decrypt":
        handle_decrypt(args.file)


if __name__ == "__main__":
    main()
