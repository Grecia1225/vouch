"""Generates the stego test fixtures (run: python3 make_fixtures.py). Fixed seed, so output is reproducible."""
import io, struct, zlib, zipfile, wave
import numpy as np
from PIL import Image

rng = np.random.default_rng(1234)
OUT = "."

def cover_pixels(w=96, h=96):
    small = rng.integers(0, 256, (12, 12, 3), dtype=np.uint8)
    im = Image.fromarray(small).resize((w, h), Image.BICUBIC)
    a = np.asarray(im).astype(float) + rng.normal(0, 2, (h, w, 3))
    a = np.clip((a - 128) * 1.6 + 128, 0, 255)          # contrast stretch: leaves gaps in the histogram, like real processed photos
    return a.astype(np.uint8)

def embed_lsb(arr, payload: bytes):
    flat = arr.reshape(-1).copy()
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))   # MSB first
    flat[: len(bits)] = (flat[: len(bits)] & 0xFE) | bits
    return flat.reshape(arr.shape)

def png_bytes(arr, **kw):
    b = io.BytesIO(); Image.fromarray(arr).save(b, "PNG", **kw); return b.getvalue()

cover = cover_pixels()
open(f"{OUT}/cover.png", "wb").write(png_bytes(cover))

# short sequential LSB text message (the kind many simple tools and CTFs produce)
msg = b"VOUCH-SECRET: meet at 9pm near the old bridge\x00"
open(f"{OUT}/stego_text.png", "wb").write(png_bytes(embed_lsb(cover, msg)))

# full-capacity random LSB embedding (statistical test target)
rand_bits = rng.integers(0, 256, cover.size // 8, dtype=np.uint8).tobytes()
open(f"{OUT}/stego_full.png", "wb").write(png_bytes(embed_lsb(cover, rand_bits)))

# partial random LSB embedding: first 40% of samples
part = rng.integers(0, 256, int(cover.size * 0.4) // 8, dtype=np.uint8).tobytes()
open(f"{OUT}/stego_partial.png", "wb").write(png_bytes(embed_lsb(cover, part)))

# BMP with the same text message
Image.fromarray(embed_lsb(cover, msg)).save(f"{OUT}/stego_text.bmp", "BMP")

# data appended after IEND
open(f"{OUT}/trailing.png", "wb").write(png_bytes(cover) + b"SECRET-NOTE: the vault code is 4821")

# private PNG chunk
def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
p = png_bytes(cover); iend = p.rfind(b"\x00\x00\x00\x00IEND")
open(f"{OUT}/private_chunk.png", "wb").write(p[:iend] + chunk(b"stEg", b"hidden in a private chunk " * 4) + p[iend:])

# JPEG: clean baseline, clean progressive, and one with a ZIP appended
def jpeg_bytes(**kw):
    b = io.BytesIO(); Image.fromarray(cover).save(b, "JPEG", quality=85, **kw); return b.getvalue()
open(f"{OUT}/clean.jpg", "wb").write(jpeg_bytes())
open(f"{OUT}/clean_progressive.jpg", "wb").write(jpeg_bytes(progressive=True))
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z: z.writestr("secret.txt", "classified plans")
open(f"{OUT}/appended_zip.jpg", "wb").write(jpeg_bytes() + zb.getvalue())

# GIF with appended text
g = io.BytesIO(); Image.fromarray(cover).convert("P").save(g, "GIF")
open(f"{OUT}/clean.gif", "wb").write(g.getvalue())
open(f"{OUT}/trailing.gif", "wb").write(g.getvalue() + b"HIDDEN AFTER GIF TRAILER")

# WAV 16-bit: tone + noise, clean and with LSB message
t = np.arange(24000)
audio = (np.sin(t / 20.0) * 6000 + rng.normal(0, 300, t.size)).astype(np.int16)
def wav_bytes(samples):
    b = io.BytesIO()
    with wave.open(b, "wb") as w: w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000); w.writeframes(samples.astype("<i2").tobytes())
    return b.getvalue()
open(f"{OUT}/clean.wav", "wb").write(wav_bytes(audio))
bits = np.unpackbits(np.frombuffer(msg, dtype=np.uint8))
stego = audio.copy(); stego[: len(bits)] = (stego[: len(bits)] & ~1) | bits
open(f"{OUT}/stego_text.wav", "wb").write(wav_bytes(stego))
print("fixtures written")
