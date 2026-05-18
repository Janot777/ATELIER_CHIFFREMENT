"""Atelier 2 — Chiffrement/déchiffrement de fichiers avec PyNaCl SecretBox.

SecretBox = XSalsa20 (chiffrement) + Poly1305 (authentification).

- Clé : 32 octets (256 bits), stockée en variable d'environnement NACL_KEY
  encodée en Base64 (au même titre qu'un GitHub Repository Secret).
- Nonce : 24 octets aléatoires générés à chaque chiffrement et préfixés au
  ciphertext de sortie. Réutiliser un nonce avec la même clé casse la
  sécurité, d'où le tirage aléatoire (24 octets ⇒ collision négligeable).
- Le tag Poly1305 (16 octets) est ajouté automatiquement par SecretBox et
  vérifié au déchiffrement : toute altération lève ``nacl.exceptions.CryptoError``.

Format du fichier chiffré :

    [ nonce (24 octets) ][ ciphertext + tag Poly1305 (16 octets) ]

Usage :

    python app/secretbox_crypto.py generate-key            # imprime une clé Base64
    export NACL_KEY="<clé Base64>"
    python app/secretbox_crypto.py encrypt clair.txt out.enc
    python app/secretbox_crypto.py decrypt out.enc clair.dec.txt
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

import nacl.exceptions
import nacl.utils
from nacl.secret import SecretBox


NACL_KEY_ENV = "NACL_KEY"


def generate_key_b64() -> str:
    """Génère une clé SecretBox de 32 octets et la renvoie en Base64."""
    raw = nacl.utils.random(SecretBox.KEY_SIZE)
    return base64.b64encode(raw).decode("ascii")


def load_key_from_env() -> bytes:
    encoded = os.environ.get(NACL_KEY_ENV)
    if not encoded:
        sys.exit(
            f"❌ Variable d'environnement {NACL_KEY_ENV} absente.\n"
            "   Génère une clé : python app/secretbox_crypto.py generate-key\n"
            "   Puis : export NACL_KEY='<clé Base64>'\n"
            "   En CI : déclarer un Repository Secret NACL_KEY et l'exposer via\n"
            "          env: NACL_KEY: ${{ secrets.NACL_KEY }}"
        )
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as err:
        sys.exit(f"❌ {NACL_KEY_ENV} n'est pas du Base64 valide : {err}")

    if len(raw) != SecretBox.KEY_SIZE:
        sys.exit(
            f"❌ {NACL_KEY_ENV} doit faire {SecretBox.KEY_SIZE} octets une fois "
            f"décodé (taille obtenue : {len(raw)})."
        )
    return raw


def get_box() -> SecretBox:
    return SecretBox(load_key_from_env())


def encrypt_file(input_path: Path, output_path: Path) -> None:
    box = get_box()
    nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(input_path.read_bytes(), nonce)
    # `encrypted` est un EncryptedMessage qui sérialise nonce || ciphertext.
    output_path.write_bytes(bytes(encrypted))
    print(f"✅ Chiffré (SecretBox) : {input_path} -> {output_path}")


def decrypt_file(input_path: Path, output_path: Path) -> None:
    box = get_box()
    try:
        data = box.decrypt(input_path.read_bytes())
    except nacl.exceptions.CryptoError as err:
        sys.exit(
            "❌ Déchiffrement impossible : tag Poly1305 invalide. "
            "La clé ne correspond pas ou le fichier a été altéré "
            f"({err.__class__.__name__})."
        )
    output_path.write_bytes(data)
    print(f"✅ Déchiffré (SecretBox) : {input_path} -> {output_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Atelier 2 — Chiffrement/déchiffrement de fichiers avec PyNaCl SecretBox "
            "(XSalsa20-Poly1305). La clé est lue depuis la variable d'environnement "
            "NACL_KEY (au même titre qu'un GitHub Repository Secret)."
        )
    )
    sub = p.add_subparsers(dest="mode", required=True)

    sub.add_parser("generate-key", help="Génère une clé SecretBox de 32 octets en Base64")

    enc = sub.add_parser("encrypt", help="Chiffrer un fichier")
    enc.add_argument("input", help="Fichier en clair à chiffrer")
    enc.add_argument("output", help="Fichier chiffré de sortie")

    dec = sub.add_parser("decrypt", help="Déchiffrer un fichier")
    dec.add_argument("input", help="Fichier chiffré à déchiffrer")
    dec.add_argument("output", help="Fichier en clair de sortie")

    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.mode == "generate-key":
        print(generate_key_b64())
        return

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
