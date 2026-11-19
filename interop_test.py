"""Check that Python decrypts what the browser code encrypted.

Run from the repo root, after the Node tests have written tests/out/:
    node tests/core.test.mjs && python3 tests/interop_test.py
"""
import html
import pathlib
import re
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "out"
sys.path.insert(0, str(ROOT / "python"))
from a256_decrypt import a256_open, needs_passphrase  # noqa: E402

TEXT = "Wire instructions for invoice #2041. Xin chào, Tuấn! 🔐"
CLI = [sys.executable, str(ROOT / "python" / "a256_decrypt.py")]


def check(name, cond):
    assert cond, name
    print("ok -", name)


# 1. Module decrypts browser output
check("passphrase text", a256_open((OUT / "text_pass.txt").read_text(), passphrase="correct horse battery staple") == TEXT)
key_hex = (OUT / "text_raw.key").read_text()
check("raw-key text", a256_open((OUT / "text_raw.txt").read_text(), key=bytes.fromhex(key_hex)) == "raw key message")
name, data = a256_open((OUT / "file_pass.aes.txt").read_text(), passphrase="file pass")
check("armored 3 MB file, name preserved",
      name == "Báo cáo Q3 — final.pdf" and data == (OUT / "file_plain.bin").read_bytes())
check("needs_passphrase reads the flags", needs_passphrase((OUT / "text_pass.txt").read_text())
      and not needs_passphrase((OUT / "text_raw.txt").read_text()))

# 2. The short snippet shown on the web page also works
page = (ROOT / "index.html").read_text()
snippet = html.unescape(re.search(r'<pre id="py"><code>(.*?)</code></pre>', page, re.S).group(1))
ns = {}
exec(snippet, ns)
check("page snippet decrypts", ns["a256_open"]((OUT / "text_pass.txt").read_text(),
                                               passphrase="correct horse battery staple") == TEXT)

# 3. Command line: key-locked text to stdout, file written to disk, wrong key refused
r = subprocess.run(CLI + [str(OUT / "text_raw.txt"), "--key", key_hex], capture_output=True, text=True)
check("CLI prints key-locked text", r.returncode == 0 and r.stdout == "raw key message\n")
r = subprocess.run(CLI + [str(OUT / "text_raw.txt"), "--key", "00" * 32], capture_output=True, text=True)
check("CLI refuses a wrong key", r.returncode != 0 and "Wrong passphrase or key" in r.stderr)

# 4. Zip wrapper used when the claude.ai viewer can't save a file type directly
with zipfile.ZipFile(OUT / "wrapped.zip") as z:
    info = z.infolist()[0]
    check("zip opens with UTF-8 name and valid CRC",
          z.testzip() is None and info.filename == "tài liệu.kdbx" and z.read(info) == bytes([9, 8, 7, 6]))

print("\nall interop checks passed")
