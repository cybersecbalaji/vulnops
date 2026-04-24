#!/usr/bin/env python3
"""
VulnOps Triage Console — first-time setup script.

Generates cryptographic secrets and writes a ready-to-use backend/.env file.
Run from the project root:

    python scripts/setup.py [--non-interactive]

Python 3.11+ required (same as the backend).
"""

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
ENV_EXAMPLE = ROOT / "backend" / ".env.example"
ENV_OUT = ROOT / "backend" / ".env"


def generate_secrets() -> dict[str, str]:
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("ERROR: 'cryptography' package not found.")
        print("Install it with: pip install cryptography")
        sys.exit(1)

    print("Generating RSA 4096-bit key pair for JWT signing...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print("Generating Fernet master encryption key...")
    master_key = Fernet.generate_key().decode()

    return {
        "JWT_PRIVATE_KEY": private_pem.replace("\n", "\\n"),
        "JWT_PUBLIC_KEY": public_pem.replace("\n", "\\n"),
        "MASTER_ENCRYPTION_KEY": master_key,
    }


def write_env(secrets: dict[str, str], non_interactive: bool = False) -> None:
    if not ENV_EXAMPLE.exists():
        print(f"ERROR: {ENV_EXAMPLE} not found.")
        sys.exit(1)

    if ENV_OUT.exists() and not non_interactive:
        print(f"\nWARNING: {ENV_OUT} already exists.")
        answer = input("Overwrite it? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted. Existing .env was not changed.")
            sys.exit(0)
    elif ENV_OUT.exists() and non_interactive:
        print(f"Non-interactive mode: keeping existing {ENV_OUT}.")
        return

    import re

    content = ENV_EXAMPLE.read_text(encoding="utf-8")

    priv = secrets["JWT_PRIVATE_KEY"]
    pub  = secrets["JWT_PUBLIC_KEY"]
    content = re.sub(
        r'^JWT_PRIVATE_KEY=.*$',
        lambda _: f'JWT_PRIVATE_KEY="{priv}"',
        content,
        flags=re.MULTILINE,
    )
    content = re.sub(
        r'^JWT_PUBLIC_KEY=.*$',
        lambda _: f'JWT_PUBLIC_KEY="{pub}"',
        content,
        flags=re.MULTILINE,
    )
    content = content.replace("PASTE_YOUR_FERNET_KEY_HERE", secrets["MASTER_ENCRYPTION_KEY"])

    ENV_OUT.write_text(content, encoding="utf-8")
    print(f"\nWrote {ENV_OUT}")


def check_docker() -> bool:
    return shutil.which("docker") is not None


def main() -> None:
    non_interactive = "--non-interactive" in sys.argv

    print("=" * 60)
    print("  VulnOps Triage Console — Setup")
    print("=" * 60)

    secrets = generate_secrets()
    write_env(secrets, non_interactive=non_interactive)

    print("\n" + "=" * 60)
    print("  Setup complete!")
    print("=" * 60)
    print("""
Next steps:
  1. Review backend/.env — crypto secrets are already filled in.
     Add your NVD_API_KEY for faster CVE enrichment (optional).

  2. Copy .env.example → .env and set POSTGRES_PASSWORD + DOMAIN:
       cp .env.example .env

  3. Start the stack (development):
       docker compose up -d

     Or production:
       docker compose -f docker-compose.prod.yml up -d

  4. Run database migrations (first time only):
       docker compose exec backend alembic upgrade head

  5. Open the app:
       Frontend → http://localhost:3000
       API docs  → http://localhost:8000/api/docs  (DEBUG=true only)

  6. Register your first user at http://localhost:3000
     (the first registered user becomes the org admin)
""")
    if not check_docker():
        print("WARNING: 'docker' not found on PATH. Install Docker Desktop first.")
        print("  https://docs.docker.com/get-docker/\n")


if __name__ == "__main__":
    main()
