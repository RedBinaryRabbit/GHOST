#!/usr/bin/env python3
"""
GHOST - Guarded Hashed Obfuscated Secret Transcript
====================================================
A cyberpunk-themed binary file format for time-limited secret documents.

File structure:
  SIGNAL  - Magic bytes (identifier)
  CORTEX  - Header (version, flags, chunk count)
  EXPIRY  - Time-lock (created, TTL, expiry timestamp)
  KEYHOLE - Key derivation params (salt, iterations, algo)
  INDEX   - Chunk map (chunk ID, offset, size, flags)
  VAULT   - Encrypted payload (MEMO, GRID, TAG, BLOB chunks)
  HASH    - SHA-256 integrity seal over entire file

Security:
  The expiry timestamp is mixed into the key derivation salt, so
  modifying the EXPIRY field in the binary file will produce a
  different AES key and decryption will fail. This prevents both
  file-level tampering of the expiry AND provides an additional
  layer on top of the SHA-256 integrity seal.

Usage:
  ghost.py encode  -o <file> [options]     Create a .gho file
  ghost.py decode  <file>                  Decrypt and display
  ghost.py info    <file>                  Show structure (no password)
  ghost.py hexdump <file>                  Raw binary hex dump
  ghost.py verify  <file>                  Check integrity + expiry

Examples:
  python ghost.py encode -o secret.gho --memo "Meet at the docks" --ttl 1h
  python ghost.py decode secret.gho
  python ghost.py info secret.gho
  python ghost.py verify secret.gho
"""

import argparse
import csv
import getpass
import hashlib
import io
import json
import os
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum, IntFlag
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ======================================================================
#  PART 1: FORMAT CORE
# ======================================================================

# ── Constants ─────────────────────────────────────────────────────────

# Magic: 89 47 48 53 54 00  (0x89 = non-ASCII guard, then "GHST\0")
GHOST_MAGIC = bytes([0x89, 0x47, 0x48, 0x53, 0x54, 0x00])

GHOST_VERSION = 1
KEYHOLE_ALGO_PBKDF2 = 0x01
KEYHOLE_ITERATIONS = 600_000  # OWASP 2023 recommendation


class ChunkType(IntEnum):
    MEMO = 0x01  # Secret text (UTF-8)
    GRID = 0x02  # Table / structured data (JSON)
    TAG  = 0x03  # Classification labels
    BLOB = 0x04  # Arbitrary binary data


class ChunkFlags(IntFlag):
    NONE       = 0x00
    COMPRESSED = 0x01


# ── Data Classes ──────────────────────────────────────────────────────

@dataclass
class GhostDocument:
    """In-memory representation of a GHOST document."""
    password: str = ""
    created_at: float = field(default_factory=lambda: time.time())
    ttl_seconds: int = 86400
    expiry_at: float = 0.0
    memo: Optional[str] = None
    grid: Optional[list] = None
    tags: Optional[list] = None
    blob: Optional[bytes] = None
    compress: bool = True

    def __post_init__(self):
        if self.expiry_at == 0.0:
            self.expiry_at = self.created_at + self.ttl_seconds

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expiry_at

    @property
    def time_remaining(self) -> timedelta:
        return timedelta(seconds=max(0, self.expiry_at - time.time()))


# ── Exceptions ────────────────────────────────────────────────────────

class GhostExpiredError(Exception):
    """Document's expiry has passed."""

class GhostIntegrityError(Exception):
    """File hash doesn't match."""

class GhostDecryptError(Exception):
    """Decryption failed (wrong password or tampered)."""


# ── KEYHOLE - Key Derivation (expiry-bound) ──────────────────────────

def derive_key(
    password: str,
    salt: bytes,
    expiry_at: float,
    iterations: int = KEYHOLE_ITERATIONS,
) -> bytes:
    """
    Derive a 256-bit AES key from password using PBKDF2-SHA256.

    The expiry timestamp is appended to the salt so that the derived
    key is cryptographically bound to the expiry time. If an attacker
    modifies the EXPIRY field in the binary file to extend the
    document's lifetime, the key derivation will produce a different
    key and AES-256-GCM decryption will fail -- even if the SHA-256
    hash check is somehow bypassed.
    """
    expiry_bytes = struct.pack("<d", expiry_at)
    effective_salt = salt + expiry_bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=effective_salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ── VAULT - Encryption / Decryption ──────────────────────────────────

def encrypt_payload(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    return nonce, aesgcm.encrypt(nonce, plaintext, None)


def decrypt_payload(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Chunk Serialization ──────────────────────────────────────────────

def _serialize_chunk(ctype, data, compress):
    flags = ChunkFlags.NONE
    payload = data
    if compress:
        compressed = zlib.compress(data, level=6)
        if len(compressed) < len(data):
            payload = compressed
            flags |= ChunkFlags.COMPRESSED
    return payload, flags


def _deserialize_chunk(data, flags):
    if flags & ChunkFlags.COMPRESSED:
        return zlib.decompress(data)
    return data


# ── Writer ────────────────────────────────────────────────────────────

def write_ghost(doc: GhostDocument) -> bytes:
    """Encode a GhostDocument into the GHOST binary format."""
    if not doc.password:
        raise ValueError("GHOST documents require a password")

    raw_chunks = []
    if doc.memo is not None:
        raw_chunks.append((ChunkType.MEMO, doc.memo.encode("utf-8")))
    if doc.grid is not None:
        raw_chunks.append((ChunkType.GRID, json.dumps(doc.grid, ensure_ascii=False).encode("utf-8")))
    if doc.tags is not None:
        raw_chunks.append((ChunkType.TAG, json.dumps(doc.tags, ensure_ascii=False).encode("utf-8")))
    if doc.blob is not None:
        raw_chunks.append((ChunkType.BLOB, doc.blob))
    if not raw_chunks:
        raise ValueError("GHOST document must contain at least one chunk")

    inner_parts, index_entries, offset = [], [], 0
    for ctype, raw_data in raw_chunks:
        payload, flags = _serialize_chunk(ctype, raw_data, doc.compress)
        chunk_bytes = struct.pack("<BBL", ctype, flags, len(payload)) + payload
        inner_parts.append(chunk_bytes)
        index_entries.append(struct.pack("<BBLL", ctype, flags, offset, len(payload)))
        offset += len(chunk_bytes)

    vault_plaintext = b"".join(inner_parts)
    salt = os.urandom(32)
    key = derive_key(doc.password, salt, doc.expiry_at, KEYHOLE_ITERATIONS)
    nonce, vault_ciphertext = encrypt_payload(vault_plaintext, key)

    buf = bytearray()
    buf.extend(GHOST_MAGIC)                                                      # SIGNAL  (6B)
    buf.extend(struct.pack("<HHL", GHOST_VERSION,                                # CORTEX  (8B)
               0x0001 if doc.compress else 0x0000, len(raw_chunks)))
    buf.extend(struct.pack("<dLd4x", doc.created_at, doc.ttl_seconds,            # EXPIRY  (24B)
               doc.expiry_at))
    buf.extend(struct.pack("<B3xL", KEYHOLE_ALGO_PBKDF2, KEYHOLE_ITERATIONS))    # KEYHOLE (40B)
    buf.extend(salt)
    for entry in index_entries:                                                   # INDEX   (10B * N)
        buf.extend(entry)
    buf.extend(nonce)                                                            # VAULT
    buf.extend(struct.pack("<L", len(vault_ciphertext)))
    buf.extend(vault_ciphertext)
    buf.extend(hashlib.sha256(bytes(buf)).digest())                              # HASH    (32B)
    return bytes(buf)


# ── Reader ────────────────────────────────────────────────────────────

def read_ghost(data: bytes, password: str) -> GhostDocument:
    """Decode a GHOST binary file. Raises on error."""
    pos = 0

    # SIGNAL
    if data[pos:pos + 6] != GHOST_MAGIC:
        raise ValueError(f"Not a GHOST file (bad magic: {data[:6].hex()})")
    pos += 6

    # CORTEX
    version, _, chunk_count = struct.unpack_from("<HHL", data, pos); pos += 8
    if version > GHOST_VERSION:
        raise ValueError(f"Unsupported GHOST version: {version}")

    # EXPIRY
    created_at, ttl_seconds, expiry_at = struct.unpack_from("<dLd", data, pos); pos += 24
    if time.time() > expiry_at:
        expiry_str = datetime.fromtimestamp(expiry_at, tz=timezone.utc).isoformat()
        raise GhostExpiredError(
            f"[ACCESS DENIED] Document expired at {expiry_str}. The ghost has vanished.")

    # KEYHOLE
    algo, iterations = struct.unpack_from("<B3xL", data, pos); pos += 8
    salt = data[pos:pos + 32]; pos += 32

    # INDEX
    index_entries = []
    for _ in range(chunk_count):
        ctype, flags, off, size = struct.unpack_from("<BBLL", data, pos); pos += 10
        index_entries.append((ChunkType(ctype), ChunkFlags(flags), off, size))

    # VAULT
    nonce = data[pos:pos + 12]; pos += 12
    ct_size = struct.unpack_from("<L", data, pos)[0]; pos += 4
    ciphertext = data[pos:pos + ct_size]; pos += ct_size

    # HASH
    stored_hash = data[pos:pos + 32]
    if stored_hash != hashlib.sha256(data[:pos]).digest():
        raise GhostIntegrityError(
            "[INTEGRITY BREACH] File hash mismatch. The document may have been tampered with.")

    # Derive key (expiry-bound) and decrypt
    key = derive_key(password, salt, expiry_at, iterations)
    try:
        vault_plaintext = decrypt_payload(nonce, ciphertext, key)
    except Exception:
        raise GhostDecryptError(
            "[DECRYPTION FAILED] Wrong password or corrupted vault. Access denied.")

    # Parse inner chunks
    doc = GhostDocument(password=password, created_at=created_at,
                        ttl_seconds=ttl_seconds, expiry_at=expiry_at)
    inner_pos = 0
    while inner_pos < len(vault_plaintext):
        ctype, flags, data_size = struct.unpack_from("<BBL", vault_plaintext, inner_pos); inner_pos += 6
        chunk_data = vault_plaintext[inner_pos:inner_pos + data_size]; inner_pos += data_size
        raw = _deserialize_chunk(chunk_data, ChunkFlags(flags))
        if   ctype == ChunkType.MEMO: doc.memo = raw.decode("utf-8")
        elif ctype == ChunkType.GRID: doc.grid = json.loads(raw.decode("utf-8"))
        elif ctype == ChunkType.TAG:  doc.tags = json.loads(raw.decode("utf-8"))
        elif ctype == ChunkType.BLOB: doc.blob = raw
    return doc


# ── Utilities ─────────────────────────────────────────────────────────

def hexdump(data: bytes, width: int = 16, max_lines: int = 40) -> str:
    lines = [f"\u250c\u2500\u2500\u2500 GHOST Binary Dump \u2500\u2500\u2500 {len(data)} bytes \u2500\u2500\u2500\u2510"]
    for i in range(0, min(len(data), width * max_lines), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "\u00b7" for b in chunk)
        lines.append(f"\u2502 {i:08X}  {hx:<{width*3-1}}  {asc} \u2502")
    if len(data) > width * max_lines:
        lines.append(f"\u2502 ... truncated ({len(data) - width*max_lines} more bytes) ...\u2502")
    lines.append(f"\u2514{'\u2500'*58}\u2518")
    return "\n".join(lines)


def ghost_info(data: bytes) -> str:
    pos = 0; lines = []
    magic = data[pos:pos+6]; pos += 6
    lines.append("\u2554" + "\u2550"*50 + "\u2557")
    lines.append("\u2551          G H O S T   F I L E   I N F O          \u2551")
    lines.append("\u2560" + "\u2550"*50 + "\u2563")
    lines.append(f"\u2551  SIGNAL  : {magic.hex(' ')}                    \u2551")

    version, flags, chunk_count = struct.unpack_from("<HHL", data, pos); pos += 8
    lines.append(f"\u2551  CORTEX  : v{version}  flags=0x{flags:04X}  chunks={chunk_count}      \u2551")

    created_at, ttl, expiry_at = struct.unpack_from("<dLd", data, pos); pos += 24
    cr = datetime.fromtimestamp(created_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ex = datetime.fromtimestamp(expiry_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    st = "EXPIRED \u2717" if time.time() > expiry_at else "ACTIVE  \u2713"
    lines.append(f"\u2551  EXPIRY  : {st}                       \u2551")
    lines.append(f"\u2551    Created : {cr} UTC          \u2551")
    lines.append(f"\u2551    TTL     : {ttl}s ({ttl//3600}h {(ttl%3600)//60}m)                     \u2551")
    lines.append(f"\u2551    Expires : {ex} UTC          \u2551")
    lines.append(f"\u2551    KeyBind : expiry \u2713 (tamper = wrong key)     \u2551")

    algo, iterations = struct.unpack_from("<B3xL", data, pos); pos += 8
    salt = data[pos:pos+32]; pos += 32
    aname = "PBKDF2-SHA256" if algo == KEYHOLE_ALGO_PBKDF2 else f"UNKNOWN(0x{algo:02X})"
    lines.append(f"\u2551  KEYHOLE : {aname}  iter={iterations}    \u2551")
    lines.append(f"\u2551    Salt    : {salt[:8].hex()}...                \u2551")

    ctypes = {1:"MEMO", 2:"GRID", 3:"TAG ", 4:"BLOB"}
    lines.append(f"\u2551  INDEX   : {chunk_count} chunk(s)                          \u2551")
    for i in range(chunk_count):
        ct, cf, off, sz = struct.unpack_from("<BBLL", data, pos); pos += 10
        nm = ctypes.get(ct, f"0x{ct:02X}"); cp = "zlib" if cf & 0x01 else "raw "
        lines.append(f"\u2551    [{i}] {nm}  {cp}  offset={off:<6} size={sz:<6} \u2551")

    pos += 12  # nonce
    ct_size = struct.unpack_from("<L", data, pos)[0]; pos += 4 + ct_size
    lines.append(f"\u2551  VAULT   : {ct_size} bytes (encrypted)              \u2551")

    sh = data[pos:pos+32]
    lines.append(f"\u2551  HASH    : {sh[:12].hex()}...        \u2551")
    lines.append(f"\u2551  TOTAL   : {len(data)} bytes                            \u2551")
    lines.append("\u255a" + "\u2550"*50 + "\u255d")
    return "\n".join(lines)


# ======================================================================
#  PART 2: CLI INTERFACE
# ======================================================================

class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    CYAN="\033[96m"; MAGENTA="\033[95m"; GREEN="\033[92m"
    RED="\033[91m"; YELLOW="\033[93m"; BLUE="\033[94m"
    WHITE="\033[97m"; GRAY="\033[90m"
    @staticmethod
    def disable():
        for a in ["RESET","BOLD","DIM","CYAN","MAGENTA","GREEN","RED","YELLOW","BLUE","WHITE","GRAY"]:
            setattr(C, a, "")

BANNER = r"""
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
  Guarded Hashed Obfuscated Secret Transcript
"""

def print_banner(): print(f"{C.MAGENTA}{BANNER}{C.RESET}")
def cli_status(icon, msg, color=None): print(f"  {color or C.CYAN}{icon}{C.RESET} {msg}")
def cli_error(msg): print(f"\n  {C.RED}[ERROR]{C.RESET} {msg}")

def ask_password(confirm=False):
    print()
    pw = getpass.getpass(f"  {C.YELLOW}\U0001f511 Password:{C.RESET} ")
    if not pw: cli_error("Password cannot be empty."); sys.exit(1)
    if confirm:
        pw2 = getpass.getpass(f"  {C.YELLOW}\U0001f511 Confirm :{C.RESET} ")
        if pw != pw2: cli_error("Passwords do not match."); sys.exit(1)
    return pw

def parse_ttl(s):
    s = s.strip().lower()
    m = {"s":1,"m":60,"h":3600,"d":86400,"w":604800}
    return int(s[:-1]) * m[s[-1]] if s[-1] in m else int(s)

def format_ttl(sec):
    if sec >= 86400: return f"{sec//86400}d {(sec%86400)//3600}h"
    if sec >= 3600:  return f"{sec//3600}h {(sec%3600)//60}m"
    if sec >= 60:    return f"{sec//60}m {sec%60}s"
    return f"{sec}s"

def parse_csv_string(text):
    return [row for row in csv.reader(io.StringIO(text))]


# ── Commands ──────────────────────────────────────────────────────────

def cmd_encode(args):
    print_banner()
    cli_status("\u25b6", f"{C.BOLD}ENCODE{C.RESET} \u2014 Creating new GHOST document"); print()

    memo = args.memo
    if not memo and args.memo_file:
        p = Path(args.memo_file)
        if not p.exists(): cli_error(f"File not found: {args.memo_file}"); sys.exit(1)
        memo = p.read_text(encoding="utf-8")
        cli_status("\U0001f4c4", f"Loaded memo from {C.WHITE}{args.memo_file}{C.RESET} ({len(memo)} chars)")

    tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
    if tags: cli_status("\U0001f3f7", f"Tags: {C.WHITE}{', '.join(tags)}{C.RESET}")

    grid = None
    if args.grid_file:
        p = Path(args.grid_file)
        if not p.exists(): cli_error(f"File not found: {args.grid_file}"); sys.exit(1)
        grid = parse_csv_string(p.read_text(encoding="utf-8"))
        cli_status("\U0001f4ca", f"Loaded grid from {C.WHITE}{args.grid_file}{C.RESET} ({len(grid)}\u00d7{len(grid[0])})")
    elif args.grid: grid = parse_csv_string(args.grid)

    blob = None
    if args.blob_file:
        p = Path(args.blob_file)
        if not p.exists(): cli_error(f"File not found: {args.blob_file}"); sys.exit(1)
        blob = p.read_bytes()
        cli_status("\U0001f4e6", f"Loaded blob from {C.WHITE}{args.blob_file}{C.RESET} ({len(blob)} bytes)")

    if not any([memo, tags, grid, blob]):
        cli_error("No content provided. Use --memo, --tags, --grid-file, or --blob-file."); sys.exit(1)

    ttl = parse_ttl(args.ttl)
    cli_status("\u23f1", f"TTL: {C.WHITE}{format_ttl(ttl)}{C.RESET} ({ttl}s)")
    password = ask_password(confirm=True)

    doc = GhostDocument(password=password, ttl_seconds=ttl, memo=memo,
                        grid=grid, tags=tags, blob=blob, compress=not args.no_compress)
    print()
    cli_status("\U0001f510", "Deriving encryption key (PBKDF2-SHA256 + expiry-bound)...")
    binary_data = write_ghost(doc)

    out_path = Path(args.output)
    if not out_path.suffix: out_path = out_path.with_suffix(".gho")
    out_path.write_bytes(binary_data)

    print()
    print(f"  {C.GREEN}{'\u2500'*50}{C.RESET}")
    cli_status("\u2713", f"{C.GREEN}{C.BOLD}Document written:{C.RESET} {C.WHITE}{out_path}{C.RESET}")
    cli_status("\u2713", f"{C.GREEN}Size:{C.RESET} {len(binary_data)} bytes")
    cli_status("\u2713", f"{C.GREEN}Chunks:{C.RESET} {sum(1 for x in [memo,grid,tags,blob] if x)}")
    cli_status("\u2713", f"{C.GREEN}Compression:{C.RESET} {'ON' if not args.no_compress else 'OFF'}")
    cli_status("\u2713", f"{C.GREEN}Encryption:{C.RESET} AES-256-GCM (expiry-bound key)")
    exp_dt = datetime.fromtimestamp(doc.expiry_at, tz=timezone.utc)
    cli_status("\u2713", f"{C.GREEN}Expires:{C.RESET} {exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {C.GREEN}{'\u2500'*50}{C.RESET}\n")


def cmd_decode(args):
    print_banner()
    cli_status("\u25b6", f"{C.BOLD}DECODE{C.RESET} \u2014 Decrypting {C.WHITE}{args.file}{C.RESET}")
    p = Path(args.file)
    if not p.exists(): cli_error(f"File not found: {args.file}"); sys.exit(1)
    data = p.read_bytes()
    password = ask_password()
    print(); cli_status("\U0001f510", "Deriving key and decrypting vault..."); print()

    try:
        doc = read_ghost(data, password)
    except GhostExpiredError as e:
        print(f"\n  {C.RED}{'\u2501'*50}\n  \u26d4  DOCUMENT EXPIRED\n  {'\u2501'*50}{C.RESET}")
        print(f"  {C.DIM}{e}{C.RESET}\n"); sys.exit(1)
    except GhostIntegrityError as e:
        print(f"\n  {C.RED}{'\u2501'*50}\n  \u26a0\ufe0f  INTEGRITY BREACH\n  {'\u2501'*50}{C.RESET}")
        print(f"  {C.DIM}{e}{C.RESET}\n"); sys.exit(1)
    except GhostDecryptError as e:
        print(f"\n  {C.RED}{'\u2501'*50}\n  \U0001f6ab  ACCESS DENIED\n  {'\u2501'*50}{C.RESET}")
        print(f"  {C.DIM}{e}{C.RESET}\n"); sys.exit(1)

    print(f"  {C.GREEN}{'\u2501'*50}\n  \u2713  DECRYPTION SUCCESSFUL\n  {'\u2501'*50}{C.RESET}")
    print(f"  {C.DIM}Time remaining: {doc.time_remaining}{C.RESET}\n")

    if doc.tags:
        print(f"  {C.MAGENTA}\u2500\u2500 TAGS \u2500\u2500{C.RESET}")
        print(f"  {' '.join(f'{C.CYAN}[{t}]{C.RESET}' for t in doc.tags)}\n")
    if doc.memo:
        print(f"  {C.MAGENTA}\u2500\u2500 MEMO \u2500\u2500{C.RESET}")
        for line in doc.memo.split("\n"): print(f"  {C.WHITE}{line}{C.RESET}")
        print()
    if doc.grid:
        print(f"  {C.MAGENTA}\u2500\u2500 GRID \u2500\u2500{C.RESET}")
        cw = [max(len(str(row[i])) for row in doc.grid) for i in range(len(doc.grid[0]))]
        for j, row in enumerate(doc.grid):
            print(f"  {C.WHITE}{'  '.join(str(c).ljust(cw[i]) for i,c in enumerate(row))}{C.RESET}")
            if j == 0: print(f"  {C.DIM}{'\u2500\u2500'.join('\u2500'*w for w in cw)}{C.RESET}")
        print()
    if doc.blob:
        print(f"  {C.MAGENTA}\u2500\u2500 BLOB \u2500\u2500{C.RESET}")
        print(f"  {C.DIM}{len(doc.blob)} bytes of binary data{C.RESET}")
        if args.blob_out:
            Path(args.blob_out).write_bytes(doc.blob)
            cli_status("\U0001f4be", f"Blob saved to {C.WHITE}{args.blob_out}{C.RESET}")
        else: print(f"  {C.DIM}(use --blob-out <path> to extract){C.RESET}")
        print()
    if args.memo_out and doc.memo:
        Path(args.memo_out).write_text(doc.memo, encoding="utf-8")
        cli_status("\U0001f4be", f"Memo saved to {C.WHITE}{args.memo_out}{C.RESET}")
    if args.grid_out and doc.grid:
        with open(args.grid_out, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(doc.grid)
        cli_status("\U0001f4be", f"Grid saved to {C.WHITE}{args.grid_out}{C.RESET}")


def cmd_info(args):
    print_banner()
    cli_status("\u25b6", f"{C.BOLD}INFO{C.RESET} \u2014 Scanning {C.WHITE}{args.file}{C.RESET}"); print()
    p = Path(args.file)
    if not p.exists(): cli_error(f"File not found: {args.file}"); sys.exit(1)
    print(f"{C.CYAN}{ghost_info(p.read_bytes())}{C.RESET}\n")


def cmd_hexdump(args):
    print_banner()
    cli_status("\u25b6", f"{C.BOLD}HEXDUMP{C.RESET} \u2014 {C.WHITE}{args.file}{C.RESET}"); print()
    p = Path(args.file)
    if not p.exists(): cli_error(f"File not found: {args.file}"); sys.exit(1)
    print(f"{C.GREEN}{hexdump(p.read_bytes(), max_lines=args.lines or 40)}{C.RESET}\n")


def cmd_verify(args):
    print_banner()
    cli_status("\u25b6", f"{C.BOLD}VERIFY{C.RESET} \u2014 Checking {C.WHITE}{args.file}{C.RESET}"); print()
    p = Path(args.file)
    if not p.exists(): cli_error(f"File not found: {args.file}"); sys.exit(1)
    data = p.read_bytes()

    if data[:6] != GHOST_MAGIC:
        cli_status("\u2717", f"{C.RED}Invalid GHOST file (bad magic bytes){C.RESET}"); sys.exit(1)
    cli_status("\u2713", f"{C.GREEN}Valid GHOST magic bytes{C.RESET}")

    if data[-32:] == hashlib.sha256(data[:-32]).digest():
        cli_status("\u2713", f"{C.GREEN}Integrity check passed (SHA-256){C.RESET}")
    else:
        cli_status("\u2717", f"{C.RED}INTEGRITY BREACH \u2014 hash mismatch!{C.RESET}"); sys.exit(1)

    _, ttl, expiry_at = struct.unpack_from("<dLd", data, 14)
    exp_dt = datetime.fromtimestamp(expiry_at, tz=timezone.utc)
    if time.time() > expiry_at:
        cli_status("\u2717", f"{C.RED}EXPIRED at {exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}{C.RESET}")
        cli_status("\u26d4", f"{C.RED}The ghost has vanished. Document is unrecoverable.{C.RESET}")
    else:
        rem = timedelta(seconds=expiry_at - time.time())
        cli_status("\u2713", f"{C.GREEN}Active \u2014 expires {exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}{C.RESET}")
        cli_status("\u23f1", f"{C.YELLOW}Time remaining: {rem}{C.RESET}")
    cli_status("\U0001f511", f"{C.BLUE}Key derivation is expiry-bound (tamper-resistant){C.RESET}\n")


# ── Argument Parser ───────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(prog="ghost",
        description="GHOST \u2014 Guarded Hashed Obfuscated Secret Transcript",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
examples:
  python ghost.py encode -o secret.gho --memo "Top secret" --ttl 1h
  python ghost.py decode secret.gho
  python ghost.py info secret.gho
  python ghost.py verify secret.gho""")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    sub = p.add_subparsers(dest="command", help="Available commands")

    e = sub.add_parser("encode", help="Create a new .gho file")
    e.add_argument("-o","--output", required=True, help="Output file path")
    e.add_argument("--memo", help="Secret text content (inline)")
    e.add_argument("--memo-file", help="Read memo from a text file")
    e.add_argument("--tags", help="Comma-separated tags")
    e.add_argument("--grid", help="Inline CSV data for grid")
    e.add_argument("--grid-file", help="Read grid from a CSV file")
    e.add_argument("--blob-file", help="Binary file to embed")
    e.add_argument("--ttl", default="24h", help="Time-to-live [default: 24h]")
    e.add_argument("--no-compress", action="store_true", help="Disable compression")

    d = sub.add_parser("decode", help="Decrypt and display a .gho file")
    d.add_argument("file"); d.add_argument("--memo-out")
    d.add_argument("--grid-out"); d.add_argument("--blob-out")

    sub.add_parser("info", help="Show structure (no password)").add_argument("file")
    h = sub.add_parser("hexdump", help="Raw binary hex dump")
    h.add_argument("file"); h.add_argument("--lines", type=int)
    sub.add_parser("verify", help="Check integrity + expiry").add_argument("file")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "no_color") and args.no_color: C.disable()
    if not args.command: print_banner(); parser.print_help(); sys.exit(0)
    {"encode":cmd_encode, "decode":cmd_decode, "info":cmd_info,
     "hexdump":cmd_hexdump, "verify":cmd_verify}[args.command](args)


if __name__ == "__main__":
    main()
