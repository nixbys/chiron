#!/usr/bin/env python3
"""decrypt_export.py — open a passphrase-protected Chiron export.

routes/export_routes.py encrypts a whole export .zip with a passphrase
you supply at export time (PBKDF2-HMAC-SHA256 + Fernet, via the
`cryptography` package — see that module's own comments for why this
isn't a standard AES-zip a file manager can open directly). This script
reverses that: given the encrypted `.chiron-export` file and its
passphrase, it writes back out the original, plain-openable .zip.

Usage:
    python3 scripts/decrypt_export.py chiron_export_<id>_<timestamp>.chiron-export
    python3 scripts/decrypt_export.py <file> -o output.zip

Prompts for the passphrase interactively (getpass — never on the command
line, where it would land in shell history and process listings).
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("encrypted_file", help="The .chiron-export file to decrypt")
    parser.add_argument("-o", "--output", help="Output .zip path (default: same name, .zip extension)")
    args = parser.parse_args()

    src = Path(args.encrypted_file)
    if not src.is_file():
        print(f"error: {src} not found", file=sys.stderr)
        return 1

    out = Path(args.output) if args.output else src.with_suffix(".zip")

    passphrase = getpass.getpass("Export passphrase: ")
    if not passphrase:
        print("error: empty passphrase", file=sys.stderr)
        return 1

    from routes.export_routes import decrypt_export_bytes

    try:
        plaintext = decrypt_export_bytes(src.read_bytes(), passphrase)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    out.write_bytes(plaintext)
    print(f"Decrypted -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
