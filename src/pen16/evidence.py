import gzip
import io
import os
from collections.abc import AsyncIterator
from pathlib import Path

MAX_COMPRESSED = 50 * 1024 * 1024
MAX_EXPANDED = 250 * 1024 * 1024


class TooLargeError(ValueError):
    """An upload past MAX_COMPRESSED, refused before the rest of it arrived."""


async def receive(chunks: AsyncIterator[bytes]) -> bytes:
    """Read an upload as it arrives, refusing it as soon as it passes MAX_COMPRESSED."""
    received = bytearray()
    async for chunk in chunks:
        received += chunk
        if len(received) > MAX_COMPRESSED:
            raise TooLargeError(f"upload is larger than {MAX_COMPRESSED} bytes")
    return bytes(received)


def expand(compressed: bytes) -> bytes:
    """Gunzip an upload, refusing anything over the upload limits."""
    if len(compressed) > MAX_COMPRESSED:
        raise TooLargeError(f"upload is larger than {MAX_COMPRESSED} bytes")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as file:
        raw = file.read(MAX_EXPANDED + 1)
    if len(raw) > MAX_EXPANDED:
        raise ValueError(f"upload expands past {MAX_EXPANDED} bytes")
    return raw


def store(directory: Path, digest: str, compressed: bytes, suffix: str = ".xml.gz") -> Path:
    """Write raw evidence durably, named by `digest`, the SHA-256 of its uncompressed content, which the parser
    already computed. Rewriting is a no-op."""
    path = directory / f"{digest}{suffix}"
    if path.exists():
        return path
    partial = path.with_suffix(".partial")
    with partial.open("wb") as file:
        file.write(compressed)
        file.flush()
        os.fsync(file.fileno())
    partial.rename(path)
    return path


def read(directory: Path, digest: str, suffix: str = ".xml.gz") -> bytes:
    """Read back stored evidence, uncompressed. Digests come from the database, never from a request."""
    with gzip.open(directory / f"{digest}{suffix}") as file:
        return file.read()
