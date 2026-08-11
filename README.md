# Bitcoin OP_RETURN Image Scanner

A Windows-friendly Python scanner that searches Bitcoin blocks for **complete image files stored entirely inside a single `OP_RETURN` output**.

It downloads each raw Bitcoin block from a public Esplora-compatible API, parses the block locally, inspects every transaction output, and validates candidate images before saving them.

No Bitcoin Core node is required.

## What it does

For every block, the scanner:

1. downloads the entire raw block,
2. parses all transactions locally,
3. inspects every output beginning with `OP_RETURN`,
4. extracts the pushed-data payload from that one output,
5. tests whether the payload is a complete, valid image,
6. fully decodes the image to reject truncated or malformed files,
7. saves both:
   - the **exact original bytes** recovered from Bitcoin, and
   - a **Windows-friendly PNG preview** beside it.

The original and preview intentionally appear side by side. This makes it easy to browse the discoveries while still preserving the exact byte-for-byte blockchain artifact.

## Strict scope

This project deliberately does **not** reconstruct fragmented files.

It never joins:

- multiple `OP_RETURN` outputs,
- multiple transactions,
- multiple blocks.

It also does not treat separate push operations inside the same script as unrelated images. The pushed data in one `OP_RETURN` output is treated as that output's single payload.

The goal is simple:

> Find image files that are already complete inside one Bitcoin `OP_RETURN` output.

## Image validation

Raster/container images are validated with [Pillow](https://python-pillow.org/).

A candidate must successfully pass structural verification and full pixel decoding. For multi-frame images, every frame is decoded.

SVG is handled separately and must parse as complete XML with an `<svg>` root element.

Depending on Pillow support on the installed system, formats can include:

- JPEG
- PNG
- GIF
- WebP
- BMP
- TIFF
- ICO
- PNM/PPM/PBM/PGM
- JPEG 2000
- TGA
- PCX
- DDS
- SGI
- AVIF
- QOI
- SVG

## Why raw blocks?

Public Esplora APIs normally return decoded block transactions in small pages. For a busy Bitcoin block this can require a large number of HTTP requests.

This scanner instead downloads:

```text
/block/<block-hash>/raw
```

and parses all transactions locally.

That reduces API traffic dramatically and makes historical scanning much faster.

## Public data sources

By default the scanner uses:

1. `https://mempool.space/api`
2. `https://blockstream.info/api`

If the first provider fails, the scanner can fall back to the second.

No API key is required for the default configuration.

Please use public endpoints responsibly. For large or repeated historical scans, consider operating your own Esplora instance or Bitcoin infrastructure.

## Default starting point

By default the scanner begins with the first Bitcoin block on or after:

```text
2025-10-10 UTC
```

You can choose another date or an explicit block height from the command line.

## Windows installation

### Easiest method

Install a current 64-bit version of Python for Windows and make sure Python is added to `PATH`.

Then:

1. Download or clone this repository.
2. Open the repository folder.
3. Double-click:

```text
INSTALL_AND_RUN.bat
```

The launcher will install or update Pillow and start the scanner.

### Manual method

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

Then run:

```bash
python opreturn_image_scanner.py --follow
```

## Output

Progress is stored in:

```text
opreturn_images.sqlite3
```

Recovered images are stored by block height:

```text
opreturn_images/
└── 920736/
    ├── <txid>_vout1_<hash>.jpg
    ├── <txid>_vout1_<hash>_preview.png
    ├── <txid>_vout2_<hash>.png
    └── <txid>_vout2_<hash>_preview.png
```

The first file in each pair is the exact original payload recovered from the blockchain.

The `_preview.png` file is generated for convenient viewing in Windows.

For images whose original format is already PNG, the two files may look identical. They are still intentionally separate: one is the exact blockchain artifact and one is the generated preview.

## Status output

While running, the scanner prints lines similar to:

```text
920736/961951: txs=3421, OP_RETURN=87, images_saved=2, raw=1.63 MB, time=4.2s, provider=https://mempool.space/api
```

When a valid image is found, the scanner prints:

```text
*** IMAGE FOUND ***
```

along with the block, transaction ID, output number, image format, size, and dimensions.

## Resume behavior

The scanner commits progress after each completed block.

If it is stopped and restarted in the same folder, it reads `opreturn_images.sqlite3` and resumes from the next block.

To stop it cleanly:

```text
Ctrl+C
```

## Command-line options

Start from a particular block height:

```bash
python opreturn_image_scanner.py --start-height 920000 --follow
```

Start from a particular UTC date:

```bash
python opreturn_image_scanner.py --start-date 2025-10-10 --follow
```

Use a custom Esplora endpoint:

```bash
python opreturn_image_scanner.py --provider https://your-esplora.example/api --follow
```

Multiple `--provider` arguments may be supplied for fallback.

## Security note

Blockchain data is untrusted data.

Recovered files should be treated as potentially hostile, especially SVG and unusual image formats. The scanner validates files but does not make arbitrary blockchain content safe.

For casual browsing, use the generated PNG previews rather than opening unfamiliar original file formats.

## Database contents

The SQLite database records:

- last completed block,
- block hash and timestamp,
- transaction ID,
- output number,
- `OP_RETURN` payload length,
- payload SHA-256,
- detected image format,
- dimensions,
- frame count,
- original file path,
- preview path.

This makes discoveries reproducible and traceable back to the exact Bitcoin transaction.

## Project philosophy

This scanner is intentionally narrow.

It is **not** an Ordinals indexer and it is **not** a general arbitrary-data reconstruction engine. It answers a specific question:

> Which complete image files have been placed directly into individual Bitcoin `OP_RETURN` outputs?

## Requirements

- Windows, macOS, or Linux
- Python 3.10+
- Internet connection
- Pillow

The included `.bat` launcher is for Windows. The Python scanner itself is cross-platform.

## Contributing

Bug reports and pull requests are welcome, especially for:

- image validation improvements,
- parser edge cases,
- performance improvements,
- additional public/private Esplora backends,
- gallery/indexing tools.

Please preserve the project's strict rule: **do not reconstruct images across multiple `OP_RETURN` outputs or transactions.**

## Disclaimer

This software is provided for research and educational use. Public blockchain data may contain offensive, copyrighted, illegal, malformed, or malicious content. Users are responsible for how they store, view, distribute, or otherwise handle recovered data.
