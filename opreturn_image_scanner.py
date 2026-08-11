#!/usr/bin/env python3
"""
Bitcoin OP_RETURN Image Scanner

Purpose
-------
Scan Bitcoin blocks from the Bitcoin Core 30.0 release era forward, using public
Esplora-compatible APIs. Each block is downloaded as ONE raw binary block and
parsed locally.

Strict image rule
-----------------
An image is saved ONLY if the complete image bytes are contained within ONE
OP_RETURN output's pushed-data payload.

This program never:
- joins separate OP_RETURN outputs,
- joins separate transactions,
- joins separate blocks,
- treats individual pushes as separate files,
- reconstructs multipart images.

Images are validated by fully decoding them with Pillow (or parsing SVG XML).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_START_DATE = "2025-10-10"
DEFAULT_PROVIDERS = [
    "https://mempool.space/api",
    "https://blockstream.info/api",
]


# -------------------- HTTP / Esplora --------------------

class APIError(RuntimeError):
    pass


class Esplora:
    def __init__(self, bases, delay=0.05, timeout=120):
        self.bases = [b.rstrip("/") for b in bases]
        self.active = 0
        self.delay = delay
        self.timeout = timeout

    @property
    def provider(self):
        return self.bases[self.active]

    def _request(self, path, binary=False, retries=5):
        last_error = None
        for provider_offset in range(len(self.bases)):
            idx = (self.active + provider_offset) % len(self.bases)
            base = self.bases[idx]

            for attempt in range(retries):
                url = base + path
                req = Request(url, headers={"User-Agent": "OPReturnImageScanner/Final"})
                try:
                    with urlopen(req, timeout=self.timeout) as r:
                        data = r.read()
                    self.active = idx
                    if self.delay:
                        time.sleep(self.delay)
                    return data if binary else data.decode("utf-8")
                except HTTPError as e:
                    last_error = e
                    if e.code == 429:
                        time.sleep(min(2 ** attempt, 20))
                        continue
                    if 500 <= e.code < 600:
                        time.sleep(min(2 ** attempt, 10))
                        continue
                    break
                except (URLError, TimeoutError, ConnectionError) as e:
                    last_error = e
                    time.sleep(min(2 ** attempt, 10))

        raise APIError(f"All public providers failed for {path}: {last_error}")

    def tip_height(self) -> int:
        return int(self._request("/blocks/tip/height").strip())

    def block_hash(self, height: int) -> str:
        return self._request(f"/block-height/{height}").strip()

    def block_info(self, block_hash: str) -> dict:
        return json.loads(self._request(f"/block/{block_hash}"))

    def raw_block(self, block_hash: str) -> bytes:
        return self._request(f"/block/{block_hash}/raw", binary=True)


# -------------------- Bitcoin binary parsing --------------------

class ParseError(RuntimeError):
    pass


def read_varint(buf: bytes, pos: int):
    if pos >= len(buf):
        raise ParseError("Unexpected end while reading varint")
    first = buf[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    if first == 0xFD:
        if pos + 2 > len(buf):
            raise ParseError("Unexpected end reading varint16")
        return struct.unpack_from("<H", buf, pos)[0], pos + 2
    if first == 0xFE:
        if pos + 4 > len(buf):
            raise ParseError("Unexpected end reading varint32")
        return struct.unpack_from("<I", buf, pos)[0], pos + 4
    if pos + 8 > len(buf):
        raise ParseError("Unexpected end reading varint64")
    return struct.unpack_from("<Q", buf, pos)[0], pos + 8


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_transaction(buf: bytes, pos: int):
    """
    Parse one transaction from raw block bytes.
    Returns (new_pos, txid, outputs), where outputs is list of scriptPubKey bytes.
    Correctly computes legacy txid by omitting witness serialization.
    """
    start = pos
    if pos + 4 > len(buf):
        raise ParseError("Truncated transaction version")
    version = buf[pos:pos+4]
    pos += 4

    segwit = False
    if pos + 2 <= len(buf) and buf[pos] == 0x00 and buf[pos+1] != 0x00:
        segwit = True
        pos += 2  # marker + flag

    vin_count, pos = read_varint(buf, pos)
    vin_serialized = bytearray()
    vin_serialized += encode_varint(vin_count)

    for _ in range(vin_count):
        if pos + 36 > len(buf):
            raise ParseError("Truncated input outpoint")
        outpoint = buf[pos:pos+36]
        pos += 36

        script_len, pos2 = read_varint(buf, pos)
        script_len_encoded = buf[pos:pos2]
        pos = pos2

        if pos + script_len + 4 > len(buf):
            raise ParseError("Truncated input script/sequence")
        script = buf[pos:pos+script_len]
        pos += script_len
        sequence = buf[pos:pos+4]
        pos += 4

        vin_serialized += outpoint
        vin_serialized += script_len_encoded
        vin_serialized += script
        vin_serialized += sequence

    vout_count, pos = read_varint(buf, pos)
    vout_serialized = bytearray()
    vout_serialized += encode_varint(vout_count)
    outputs = []

    for _ in range(vout_count):
        if pos + 8 > len(buf):
            raise ParseError("Truncated output value")
        value = buf[pos:pos+8]
        pos += 8

        script_len, pos2 = read_varint(buf, pos)
        script_len_encoded = buf[pos:pos2]
        pos = pos2

        if pos + script_len > len(buf):
            raise ParseError("Truncated output script")
        script = buf[pos:pos+script_len]
        pos += script_len

        outputs.append(script)
        vout_serialized += value
        vout_serialized += script_len_encoded
        vout_serialized += script

    if segwit:
        for _ in range(vin_count):
            item_count, pos = read_varint(buf, pos)
            for _ in range(item_count):
                item_len, pos = read_varint(buf, pos)
                if pos + item_len > len(buf):
                    raise ParseError("Truncated witness item")
                pos += item_len

    if pos + 4 > len(buf):
        raise ParseError("Truncated locktime")
    locktime = buf[pos:pos+4]
    pos += 4

    stripped = version + bytes(vin_serialized) + bytes(vout_serialized) + locktime
    txid = dsha256(stripped)[::-1].hex()

    return pos, txid, outputs


def parse_raw_block(raw: bytes):
    if len(raw) < 81:
        raise ParseError("Raw block is too small")

    header = raw[:80]
    block_time = struct.unpack_from("<I", header, 68)[0]

    pos = 80
    tx_count, pos = read_varint(raw, pos)

    txs = []
    for _ in range(tx_count):
        pos, txid, outputs = parse_transaction(raw, pos)
        txs.append((txid, outputs))

    if pos != len(raw):
        # Extra bytes should not normally exist; don't fail the whole scan.
        pass

    return block_time, txs


# -------------------- OP_RETURN parsing --------------------

@dataclass
class Push:
    data: bytes


def parse_op_return(script: bytes) -> list[Push]:
    if not script or script[0] != 0x6A:
        return []

    pushes = []
    i = 1
    n = len(script)

    while i < n:
        op = script[i]
        i += 1

        if op == 0x00:
            pushes.append(Push(b""))
            continue
        elif 1 <= op <= 75:
            size = op
        elif op == 0x4C:  # PUSHDATA1
            if i + 1 > n:
                return []
            size = script[i]
            i += 1
        elif op == 0x4D:  # PUSHDATA2
            if i + 2 > n:
                return []
            size = struct.unpack_from("<H", script, i)[0]
            i += 2
        elif op == 0x4E:  # PUSHDATA4
            if i + 4 > n:
                return []
            size = struct.unpack_from("<I", script, i)[0]
            i += 4
        else:
            # Non-push opcode: this is not a pure data payload we want to treat as a file.
            return []

        if i + size > n:
            return []
        pushes.append(Push(script[i:i+size]))
        i += size

    return pushes


# -------------------- Strict image validation --------------------

def validate_image(data: bytes):
    """
    Return image metadata only if the complete payload is a valid, fully decodable image.
    """
    if not data or len(data) < 8:
        return None

    # SVG
    sample = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if sample.startswith(b"<svg") or sample.startswith(b"<?xml"):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(data.decode("utf-8"))
            if root.tag.split("}")[-1].lower() == "svg":
                return {
                    "format": "SVG",
                    "ext": "svg",
                    "width": None,
                    "height": None,
                    "frames": 1,
                    "previewable": False,
                }
        except Exception:
            pass

    try:
        from PIL import Image
    except ImportError as e:
        raise RuntimeError(
            "Pillow is required. Run INSTALL_AND_RUN.bat or: python -m pip install Pillow"
        ) from e

    try:
        # Structural integrity.
        with Image.open(io.BytesIO(data)) as im:
            fmt = (im.format or "").upper()
            width, height = im.size
            if width <= 0 or height <= 0:
                return None
            im.verify()

        # Full decode, every frame.
        with Image.open(io.BytesIO(data)) as im:
            fmt = (im.format or fmt).upper()
            width, height = im.size
            frames = int(getattr(im, "n_frames", 1) or 1)
            for frame in range(frames):
                im.seek(frame)
                im.load()

        ext_map = {
            "JPEG": "jpg",
            "PNG": "png",
            "GIF": "gif",
            "WEBP": "webp",
            "BMP": "bmp",
            "TIFF": "tif",
            "ICO": "ico",
            "PPM": "pnm",
            "PBM": "pnm",
            "PGM": "pnm",
            "JPEG2000": "jp2",
            "J2K": "j2k",
            "TGA": "tga",
            "PCX": "pcx",
            "DDS": "dds",
            "SGI": "sgi",
            "QOI": "qoi",
            "AVIF": "avif",
        }
        return {
            "format": fmt,
            "ext": ext_map.get(fmt, fmt.lower() if fmt else "img"),
            "width": width,
            "height": height,
            "frames": frames,
            "previewable": True,
        }

    except Exception:
        return None


# -------------------- SQLite --------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def init_db(path: Path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")

    db.execute("""
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS opreturns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_height INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            block_time INTEGER NOT NULL,
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            payload_len INTEGER NOT NULL,
            payload_sha256 TEXT NOT NULL,
            UNIQUE(txid, vout)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_height INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            block_time INTEGER NOT NULL,
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            image_type TEXT NOT NULL,
            width INTEGER,
            height INTEGER,
            frames INTEGER NOT NULL,
            byte_len INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            original_path TEXT NOT NULL,
            preview_path TEXT,
            UNIQUE(txid, vout, sha256)
        )
    """)

    db.commit()
    return db


def get_state(db, key, default=None):
    row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_state(db, key, value):
    db.execute(
        "INSERT INTO state(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


# -------------------- Saving --------------------

def save_image(db, outdir: Path, *, height, block_hash, block_time, txid, vout, data, meta):
    digest = sha256(data)
    subdir = outdir / str(height)
    subdir.mkdir(parents=True, exist_ok=True)

    stem = f"{txid}_vout{vout}_{digest[:12]}"
    original = subdir / f"{stem}.{meta['ext']}"
    original.write_bytes(data)

    preview = None
    if meta.get("previewable"):
        try:
            from PIL import Image
            with Image.open(io.BytesIO(data)) as im:
                im.seek(0)
                if im.mode not in ("RGB", "RGBA"):
                    if "transparency" in im.info:
                        im = im.convert("RGBA")
                    else:
                        im = im.convert("RGB")
                preview = subdir / f"{stem}_preview.png"
                im.save(preview, "PNG")
        except Exception:
            preview = None

    db.execute("""
        INSERT OR IGNORE INTO images
        (block_height,block_hash,block_time,txid,vout,image_type,width,height,
         frames,byte_len,sha256,original_path,preview_path)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        height, block_hash, block_time, txid, vout, meta["format"],
        meta.get("width"), meta.get("height"), meta.get("frames", 1),
        len(data), digest, str(original), str(preview) if preview else None
    ))

    print(
        f"*** IMAGE FOUND *** block={height} txid={txid} vout={vout} "
        f"format={meta['format']} bytes={len(data)} "
        f"dimensions={meta.get('width')}x{meta.get('height')} "
        f"frames={meta.get('frames',1)}",
        flush=True,
    )
    if preview:
        print(f"    preview={preview}", flush=True)


# -------------------- Start-height lookup --------------------

def date_to_timestamp(date_str: str) -> int:
    dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def first_height_at_or_after(api: Esplora, target_ts: int) -> int:
    lo, hi = 0, api.tip_height()
    answer = hi

    while lo <= hi:
        mid = (lo + hi) // 2
        h = api.block_hash(mid)
        info = api.block_info(h)
        ts = int(info["timestamp"])

        if ts >= target_ts:
            answer = mid
            hi = mid - 1
        else:
            lo = mid + 1

    return answer


# -------------------- Block processing --------------------

def process_block(api: Esplora, db, outdir: Path, height: int):
    block_hash = api.block_hash(height)
    raw = api.raw_block(block_hash)

    block_time, txs = parse_raw_block(raw)

    op_count = 0
    image_count = 0

    for txid, outputs in txs:
        for vout, script in enumerate(outputs):
            if not script or script[0] != 0x6A:
                continue

            pushes = parse_op_return(script)
            if not pushes:
                continue

            # Complete data payload of THIS SINGLE OP_RETURN output only.
            payload = b"".join(p.data for p in pushes)
            op_count += 1

            db.execute("""
                INSERT OR IGNORE INTO opreturns
                (block_height,block_hash,block_time,txid,vout,payload_len,payload_sha256)
                VALUES(?,?,?,?,?,?,?)
            """, (
                height, block_hash, block_time, txid, vout,
                len(payload), sha256(payload)
            ))

            meta = validate_image(payload)
            if meta:
                save_image(
                    db, outdir,
                    height=height,
                    block_hash=block_hash,
                    block_time=block_time,
                    txid=txid,
                    vout=vout,
                    data=payload,
                    meta=meta,
                )
                image_count += 1

    set_state(db, "last_height", height)
    set_state(db, "last_hash", block_hash)
    set_state(db, "provider", api.provider)
    db.commit()

    return len(txs), op_count, image_count, len(raw)


# -------------------- Main --------------------

def main():
    ap = argparse.ArgumentParser(
        description="Fast raw-block Bitcoin OP_RETURN complete-image scanner"
    )
    ap.add_argument("--start-date", default=DEFAULT_START_DATE)
    ap.add_argument("--start-height", type=int)
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--poll-seconds", type=int, default=20)
    ap.add_argument("--request-delay", type=float, default=0.05)
    ap.add_argument("--output", default="opreturn_images")
    ap.add_argument("--db", default="opreturn_images.sqlite3")
    ap.add_argument(
        "--provider",
        action="append",
        help="Custom Esplora API base URL; may be given multiple times"
    )
    args = ap.parse_args()

    providers = args.provider if args.provider else DEFAULT_PROVIDERS
    api = Esplora(providers, delay=args.request_delay)
    db = init_db(Path(args.db))
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    saved = get_state(db, "last_height")
    if saved is not None:
        height = int(saved) + 1
        print(f"Resuming at block {height}", flush=True)
    elif args.start_height is not None:
        height = args.start_height
        print(f"Starting at requested block {height}", flush=True)
    else:
        print(
            f"Locating first block on/after {args.start_date} UTC...",
            flush=True,
        )
        height = first_height_at_or_after(api, date_to_timestamp(args.start_date))
        print(f"Starting at block {height}", flush=True)

    while True:
        tip = api.tip_height()

        while height <= tip:
            started = time.monotonic()
            try:
                txs, ops, imgs, raw_bytes = process_block(api, db, outdir, height)
                elapsed = max(time.monotonic() - started, 0.001)
                mb = raw_bytes / (1024 * 1024)
                print(
                    f"{height}/{tip}: txs={txs}, OP_RETURN={ops}, "
                    f"images_saved={imgs}, raw={mb:.2f} MB, "
                    f"time={elapsed:.1f}s, provider={api.provider}",
                    flush=True,
                )
                height += 1
            except KeyboardInterrupt:
                print("\nStopped by user. Progress through the previous completed block is saved.")
                return
            except Exception as e:
                print(f"Error at block {height}: {e}", file=sys.stderr, flush=True)
                time.sleep(args.poll_seconds)
                break

        if not args.follow:
            print("Caught up.", flush=True)
            return

        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
