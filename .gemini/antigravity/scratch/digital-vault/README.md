# 🔐 Digital Vault

AES-256-GCM file encryption & decryption CLI, with password-based key derivation.

## Quick Start

```bash
pip install -r requirements.txt
```

### Encrypt a file

```bash
python main.py encrypt secret_notes.txt
# → creates secret_notes.txt.vault + secret_notes.txt.salt
```

### Decrypt a file

```bash
python main.py decrypt secret_notes.txt.vault
# → creates secret_notes.txt.decrypted
```

## How It Works

| Step               | Detail                                 |
| ------------------ | -------------------------------------- |
| **Key derivation** | PBKDF2-HMAC-SHA256, 600 000 iterations |
| **Encryption**     | AES-256 in GCM mode (authenticated)    |
| **File format**    | `[nonce 16B][tag 16B][ciphertext]`     |
| **Salt**           | 32 random bytes, saved to `.salt` file |

> ⚠️ **Keep the `.salt` file** — without it, decryption is impossible.
