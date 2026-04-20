"""
Developer utility — generate RSA key pair and Fernet master key for .env setup.
Run: python -m app.core.keygen
"""

from __future__ import annotations


def generate_and_print_keys() -> None:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # ── RSA 4096 key pair ──────────────────────────────────────────────────
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = private_key.public_key().private_bytes if False else (
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    )

    # ── Fernet master key ──────────────────────────────────────────────────
    master_key = Fernet.generate_key().decode()

    print("=" * 70)
    print("Paste the following into your backend/.env file")
    print("=" * 70)
    print()
    print("JWT_PRIVATE_KEY=\"" + private_pem.replace("\n", "\\n") + "\"")
    print()
    print("JWT_PUBLIC_KEY=\"" + public_pem.replace("\n", "\\n") + "\"")
    print()
    print(f"MASTER_ENCRYPTION_KEY={master_key}")
    print()
    print("⚠ Store these in a secrets manager (AWS SSM, Vault, etc.) in production.")


if __name__ == "__main__":
    generate_and_print_keys()
