"""Atelier 1 — Fernet avec clé stockée dans un GitHub Repository Secret.

La clé n'est jamais générée ni écrite dans le code source ; elle est lue
depuis la variable d'environnement ``FERNET_KEY``. Dans un workflow GitHub
Actions, cette variable est alimentée par un secret de repository portant
le même nom :

    env:
      FERNET_KEY: ${{ secrets.FERNET_KEY }}

En local, on l'exporte manuellement :

    export FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


FERNET_KEY_ENV = "FERNET_KEY"


def load_key_from_env() -> bytes:
    key = os.environ.get(FERNET_KEY_ENV)
    if not key:
        sys.exit(
            f"❌ Variable d'environnement {FERNET_KEY_ENV} absente.\n"
            "   En local : export FERNET_KEY='<clé Fernet base64>'\n"
            "   En CI    : déclarer un GitHub Repository Secret nommé FERNET_KEY\n"
            "              et l'exposer via `env: FERNET_KEY: ${{ secrets.FERNET_KEY }}`."
        )
    return key.encode("utf-8")


def get_fernet() -> Fernet:
    try:
        return Fernet(load_key_from_env())
    except ValueError as err:
        sys.exit(f"❌ Clé Fernet invalide : {err}")


def encrypt_file(input_path: Path, output_path: Path) -> None:
    f = get_fernet()
    token = f.encrypt(input_path.read_bytes())
    output_path.write_bytes(token)
    print(f"✅ Chiffré : {input_path} -> {output_path}")


def decrypt_file(input_path: Path, output_path: Path) -> None:
    f = get_fernet()
    try:
        data = f.decrypt(input_path.read_bytes())
    except InvalidToken:
        sys.exit(
            "❌ Token invalide : la clé ne correspond pas, ou le fichier a été altéré "
            "(le HMAC du token ne valide plus le contenu)."
        )
    output_path.write_bytes(data)
    print(f"✅ Déchiffré : {input_path} -> {output_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Atelier 1 — Chiffrement Fernet avec clé issue d'un GitHub Repository "
            "Secret (variable d'environnement FERNET_KEY)."
        )
    )
    sub = p.add_subparsers(dest="mode", required=True)

    enc = sub.add_parser("encrypt", help="Chiffrer un fichier")
    enc.add_argument("input", help="Fichier en clair à chiffrer")
    enc.add_argument("output", help="Fichier chiffré de sortie")

    dec = sub.add_parser("decrypt", help="Déchiffrer un fichier")
    dec.add_argument("input", help="Fichier chiffré à déchiffrer")
    dec.add_argument("output", help="Fichier en clair de sortie")

    return p


def main() -> None:
    args = build_parser().parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        sys.exit(f"❌ Fichier introuvable : {in_path}")

    if args.mode == "encrypt":
        encrypt_file(in_path, out_path)
    else:
        decrypt_file(in_path, out_path)


if __name__ == "__main__":
    main()
