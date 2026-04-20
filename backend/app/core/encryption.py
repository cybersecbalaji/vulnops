"""
Application-layer field encryption using Fernet (symmetric encryption).

Key hierarchy:
    Master Key (env / secrets manager)
        │
        └── Organization DEK (one per org, Fernet key, stored encrypted in DB)
                │
                └── Encrypted column values in PostgreSQL

The Master Key is a Fernet key (URL-safe base64-encoded 32-byte key).
The DEK is also a Fernet key, generated randomly per organization and
stored as an encrypted blob in organizations.encrypted_dek.

No PBKDF2 stretching is needed because both keys are already high-entropy
random values — PBKDF2 is only useful when deriving a key from a low-entropy
passphrase. If the master key is ever passphrase-derived (e.g., manual entry),
apply PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2024) before use.

EncryptedString TypeDecorator
──────────────────────────────
Columns declared with EncryptedString are transparently encrypted on write
and decrypted on read.  The active FieldEncryption instance (scoped to the
current org's DEK) is stored in an asyncio ContextVar so that concurrent
requests never share state.

Usage in request handlers:

    with encryption_context(field_enc):          # set before any DB I/O
        db.add(MyModel(enc_col="plaintext"))
        await db.flush()                         # TypeDecorator encrypts here
        result = await db.execute(select(MyModel))
        obj = result.scalar_one()                # TypeDecorator decrypts here

The encryption_context() context manager is automatically entered by the
get_org_encryption FastAPI dependency, so route handlers that Depend on it
don't need to set it manually.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Generator

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Text
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

# ── Per-request encryption context ───────────────────────────────────────────

_encryption_ctx: contextvars.ContextVar[FieldEncryption | None] = (
    contextvars.ContextVar("field_encryption_ctx", default=None)
)


@contextmanager
def encryption_context(enc: FieldEncryption) -> Generator[None, None, None]:
    """
    Context manager that installs a FieldEncryption for the current async task.

    The ContextVar is task-local in asyncio, so concurrent requests never
    share state even when the context manager is used simultaneously.
    """
    token = _encryption_ctx.set(enc)
    try:
        yield
    finally:
        _encryption_ctx.reset(token)


# ── EncryptedString SQLAlchemy type ───────────────────────────────────────────

class EncryptedString(TypeDecorator):
    """
    SQLAlchemy TypeDecorator: stores column values as Fernet ciphertext.

    - process_bind_param: plaintext → ciphertext (called on INSERT / UPDATE)
    - process_result_value: ciphertext → plaintext (called on SELECT)

    Both directions require an active encryption_context().  If none is set,
    a RuntimeError is raised immediately so the bug is obvious rather than
    silently storing plaintext.

    cache_ok = False because Fernet output is non-deterministic (random IV),
    so SQLAlchemy must never cache the processor output.
    """

    impl = Text
    cache_ok = False

    def process_bind_param(
        self, value: str | None, dialect: Dialect
    ) -> str | None:
        """Encrypt plaintext before binding to a SQL parameter."""
        if value is None:
            return None
        enc = _encryption_ctx.get()
        if enc is None:
            raise RuntimeError(
                "EncryptedString.process_bind_param: no FieldEncryption in "
                "context.  Wrap the DB operation with encryption_context()."
            )
        return enc.encrypt(value)

    def process_result_value(
        self, value: str | None, dialect: Dialect
    ) -> str | None:
        """Decrypt ciphertext after loading a row from the DB."""
        if value is None:
            return None
        enc = _encryption_ctx.get()
        if enc is None:
            raise RuntimeError(
                "EncryptedString.process_result_value: no FieldEncryption in "
                "context.  Wrap the DB operation with encryption_context()."
            )
        return enc.decrypt(value)


class MasterKeyEncryption:
    """Wraps / unwraps Organization DEKs using the application master key."""

    def __init__(self, master_key: str) -> None:
        # master_key is a URL-safe base64-encoded Fernet key string
        self._fernet = Fernet(master_key.encode() if isinstance(master_key, str) else master_key)

    # ── DEK lifecycle ──────────────────────────────────────────────────────

    @staticmethod
    def generate_dek() -> bytes:
        """Generate a new random 256-bit Fernet key to use as an org DEK."""
        return Fernet.generate_key()

    def encrypt_dek(self, dek: bytes) -> str:
        """Encrypt a raw DEK with the master key. Returns a string safe for DB storage."""
        return self._fernet.encrypt(dek).decode()

    def decrypt_dek(self, encrypted_dek: str) -> bytes:
        """Decrypt an encrypted DEK blob. Raises InvalidToken on tampering."""
        return self._fernet.decrypt(
            encrypted_dek.encode() if isinstance(encrypted_dek, str) else encrypted_dek
        )


class FieldEncryption:
    """
    Encrypt / decrypt individual column values using an org-specific DEK.

    Usage:
        enc = FieldEncryption(dek_bytes)
        stored = enc.encrypt("sensitive text")   # store this in DB
        plain  = enc.decrypt(stored)              # retrieve for use
    """

    def __init__(self, dek: bytes) -> None:
        self._fernet = Fernet(dek)

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, token: str | None) -> str | None:
        if token is None:
            return None
        try:
            return self._fernet.decrypt(
                token.encode() if isinstance(token, str) else token
            ).decode()
        except InvalidToken:
            # Log and surface as a controlled error — never swallow silently
            raise ValueError("Field decryption failed: token is invalid or was tampered with")
