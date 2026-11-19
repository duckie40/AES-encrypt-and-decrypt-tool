#!/usr/bin/env python3
"""Decrypt text and files made by the AES-256 Encrypt & Decrypt page (format A256 v1).

Usage:
    python a256_decrypt.py message.aes.txt               # asks for the passphrase
    python a256_decrypt.py report.pdf.aes.txt            # writes report.pdf
    python a256_decrypt.py message.aes.txt --key 3f9c... # 256-bit key, hex or base64
    python a256_decrypt.py report.pdf.aes.txt -o out.pdf --force

Requires: pip install cryptography
"""
import argparse
import base64
import getpass
import hashlib
import os
import struct
import sys
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FLAG_PASS = 1  # key was derived from a passphrase with PBKDF2
FLAG_FILE = 2  # payload is a file: 2-byte name length, name, contents


def _blob(data):
    """Return the raw envelope bytes from armored/base64 text or raw bytes."""
    if isinstance(data, (bytes, bytearray)):
        if data[:4] == b"A256":
            return bytes(data)
        data = data.decode("utf-8")
    b64 = "".join(l.strip() for l in data.splitlines() if not l.strip().startswith("-----"))
    b64 = b64.replace("-", "+").replace("_", "/")
    blob = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    if len(blob) < 6 or blob[:4] != b"A256" or blob[4] != 1:
        raise ValueError("not an A256 v1 message")
    return blob


def needs_passphrase(data):
    """True if the message was locked with a passphrase, False if with a 256-bit key."""
    return bool(_blob(data)[5] & FLAG_PASS)


def a256_open(data, passphrase=None, key=None):
    """Decrypt an A256 message. Text in, text out; files return (name, bytes).

    data: armored/base64 text (str) or the raw envelope (bytes)
    passphrase: str, for passphrase-locked messages
    key: 32 bytes, for key-locked messages, e.g. bytes.fromhex("...")
    Raises cryptography.exceptions.InvalidTag for a wrong key or altered data.
    """
    blob = _blob(data)
    flags, p = blob[5], 6
    if flags & FLAG_PASS:
        if passphrase is None:
            raise ValueError("this message is locked with a passphrase")
        iters = struct.unpack(">I", blob[p:p + 4])[0]
        if not 1 <= iters <= 10_000_000:
            raise ValueError("iteration count out of range")
        salt = blob[p + 4:p + 20]
        p += 20
        pw = unicodedata.normalize("NFC", passphrase).encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", pw, salt, iters, 32)
    elif key is None:
        raise ValueError("this message is locked with a 256-bit key")
    iv = blob[p:p + 12]
    p += 12
    # Everything before the ciphertext is authenticated as GCM additional data.
    plain = AESGCM(key).decrypt(iv, blob[p:], blob[:p])
    if flags & FLAG_FILE:
        n = struct.unpack(">H", plain[:2])[0]
        return plain[2:2 + n].decode("utf-8"), plain[2 + n:]
    return plain.decode("utf-8")


def parse_key(text):
    """Accept a 256-bit key as 64 hex characters or base64."""
    s = "".join(text.split())
    try:
        k = bytes.fromhex(s)
    except ValueError:
        s = s.replace("-", "+").replace("_", "/")
        k = base64.b64decode(s + "=" * (-len(s) % 4))
    if len(k) != 32:
        raise ValueError(f"key is {len(k)} bytes; a 256-bit key is 32 bytes")
    return k


def main(argv=None):
    ap = argparse.ArgumentParser(description="Decrypt A256 (AES-256-GCM) text or files.")
    ap.add_argument("input", help="encrypted .aes.txt file, or - to read stdin")
    ap.add_argument("--key", help="256-bit key (hex or base64) for key-locked messages")
    ap.add_argument("-o", "--output", help="where to write a decrypted file (default: its original name)")
    ap.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.buffer.read() if args.input == "-" else open(args.input, "rb").read()
        if needs_passphrase(raw):
            result = a256_open(raw, passphrase=getpass.getpass("Passphrase: "))
        else:
            if not args.key:
                ap.error("this message is locked with a 256-bit key; pass it with --key")
            result = a256_open(raw, key=parse_key(args.key))
    except InvalidTag:
        sys.exit("Wrong passphrase or key, or the data was changed. Nothing was decrypted.")
    except (ValueError, OSError) as e:
        sys.exit(f"Error: {e}")

    if isinstance(result, str):
        sys.stdout.write(result)
        if not result.endswith("\n"):
            sys.stdout.write("\n")
        return
    name, contents = result
    out = args.output or os.path.basename(name) or "decrypted-file"
    if os.path.exists(out) and not args.force:
        sys.exit(f"{out} already exists. Use -o to choose another name, or --force to overwrite.")
    with open(out, "wb") as f:
        f.write(contents)
    print(f"Wrote {out} ({len(contents):,} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
