# AES-256 Encrypt & Decrypt

A single-page web app that encrypts and decrypts text and files with **AES-256-GCM**, entirely in the browser. It uses the browser's built-in Web Crypto API. There's no server, no build step and no third-party crypto code.

## Features

- **Two ways to lock data:** a passphrase (turned into a key with PBKDF2-HMAC-SHA256, 600,000 iterations, random salt per message) or a raw 256-bit key (generated on the page, or pasted as hex or base64).
- **Text and files.** Encrypted text comes out as base64 you can copy. Files are saved as `.aes.txt`, with the original file name encrypted inside.
- **Tamper detection.** AES-GCM checks integrity, so a wrong key or any changed byte fails cleanly instead of producing garbage.
- **Nothing leaves the browser.** Text, files and keys are never uploaded or stored.
- **Envelope view.** Shows each part of the encrypted output, byte by byte.
- **Python decryptor** for opening data without the website.

## Use it

**Locally:** download `index.html` and open it in Chrome, Edge, Firefox or Safari.

**On GitHub Pages:**
1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, then `main` and `/ (root)`, and save.
4. After a minute the site is live at `https://<your-username>.github.io/<repo-name>/`.

## Security notes

- Lose the passphrase or key and the data can't be recovered by anyone.
- Every message gets a fresh random 12-byte nonce, plus a fresh 16-byte salt when a passphrase is used. Encrypting the same input twice gives different output.
- Passphrases are Unicode-normalized (NFC) before key derivation, so accented text (for example Vietnamese) typed on different keyboards gives the same key.
- The strength meter is a rough estimate. Four or more random words is a good passphrase.
- The page's only outside request is the Google Fonts stylesheet. For a page that is fully offline, delete the three `<link>` tags for fonts in `<head>`; the page falls back to system fonts.
- This code has not had an independent security audit. For regulated or high-value data, use audited tools as well.

## Format: A256 v1

The encrypted output is base64 of this byte layout:

| Bytes | Field | Notes |
|---:|---|---|
| 4 | Magic | `A256` (`41 32 35 36`) |
| 1 | Version | `0x01` |
| 1 | Flags | bit 0: passphrase-derived key · bit 1: file payload |
| 4 | Iterations | PBKDF2 count, big-endian uint32 (passphrase only) |
| 16 | Salt | Random (passphrase only) |
| 12 | Nonce (IV) | Random for each message |
| n | Ciphertext | AES-256-GCM |
| 16 | Auth tag | GCM tag |

- Every byte before the ciphertext is passed to GCM as **additional authenticated data**, so the header can't be edited without decryption failing.
- **Text payload:** UTF-8 text.
- **File payload:** 2-byte big-endian name length, the UTF-8 file name (at most 255 bytes), then the file contents.
- **Saved files** wrap the base64 in `-----BEGIN AES-256-GCM ENCRYPTED FILE-----` / `-----END …-----` lines, at 76 characters per line.

## Decrypt with Python

```bash
pip install cryptography

python python/a256_decrypt.py message.aes.txt              # asks for the passphrase, prints the text
python python/a256_decrypt.py report.pdf.aes.txt           # writes report.pdf
python python/a256_decrypt.py message.aes.txt --key 3f9c…  # key-locked message (hex or base64 key)
```

Or call it from your own code:

```python
from a256_decrypt import a256_open

text = a256_open(open("message.aes.txt").read(), passphrase="your passphrase")
name, data = a256_open(open("report.pdf.aes.txt").read(), passphrase="your passphrase")
```

## Run the tests

Needs Node.js 18+ and Python 3 with `cryptography`:

```bash
node tests/core.test.mjs        # 23 checks: round trips, wrong keys, tampering, base64 edge cases
python3 tests/interop_test.py   # Python decrypts the browser's output
```

## Repository layout

```
index.html               The web app (HTML, CSS and JavaScript in one file)
python/a256_decrypt.py   Python decryptor: command line and importable function
tests/core.test.mjs      Tests for the page's crypto code (runs it in Node)
tests/interop_test.py    Checks Python can decrypt the browser's output
```
