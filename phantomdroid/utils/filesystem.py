"""PhantomDroid X - Safe file system operations."""

from __future__ import annotations

import hashlib
import os
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path


def safe_extract_zip(
    zip_path: str | Path,
    extract_to: str | Path,
    max_size: int = 500 * 1024 * 1024,
    allowed_extensions: set[str] | None = None,
) -> list[str]:
    """Safely extract a ZIP file, preventing path traversal and zip bombs.

    Args:
        zip_path: Path to the ZIP file.
        extract_to: Directory to extract to.
        max_size: Maximum total extracted size in bytes.
        allowed_extensions: If set, only extract files with these extensions.

    Returns:
        List of extracted file paths.

    Raises:
        ValueError: If extraction would be unsafe.
    """
    zip_path = Path(zip_path)
    extract_to = Path(extract_to)
    extract_to.mkdir(parents=True, exist_ok=True)

    if not zip_path.exists():
        raise ValueError(f"ZIP file not found: {zip_path}")

    extracted: list[str] = []
    total_size = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # Prevent path traversal
            target_path = extract_to / info.filename
            try:
                target_path.relative_to(extract_to)
            except ValueError as err:
                raise ValueError(
                    f"Path traversal detected in ZIP entry: {info.filename}"
                ) from err

            # Check for symlinks
            if info.is_dir():
                continue

            # Check extension if restricted
            if allowed_extensions:
                ext = Path(info.filename).suffix.lower()
                if ext not in allowed_extensions:
                    continue

            # Check size limit
            total_size += info.file_size
            if total_size > max_size:
                raise ValueError(
                    f"ZIP extraction exceeds max size ({max_size} bytes)"
                )

            # Extract
            zf.extract(info, extract_to)
            extracted.append(str(target_path))

    return extracted


def compute_file_hash(file_path: str | Path, algorithms: list[str] | None = None) -> dict[str, str]:
    """Compute file hashes.

    Args:
        file_path: Path to the file.
        algorithms: Hash algorithms to use (default: md5, sha1, sha256).

    Returns:
        Dictionary of algorithm -> hash.
    """
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256"]

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    hashes: dict[str, str] = {}
    for algo in algorithms:
        h = hashlib.new(algo)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        hashes[algo.upper()] = h.hexdigest()

    return hashes


def safe_write(file_path: str | Path, content: str | bytes, encoding: str = "utf-8") -> None:
    """Write content to a file safely using atomic write.

    Args:
        file_path: Path to write to.
        content: Content to write.
        encoding: Encoding for text content.
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write via temp file
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=file_path.parent, prefix=file_path.name + ".tmp."
    )
    try:
        with os.fdopen(tmp_fd, "wb" if isinstance(content, bytes) else "w", encoding=encoding if isinstance(content, str) else None) as f:
            f.write(content)
        os.replace(tmp_path, file_path)
    except Exception:
        os.unlink(tmp_path)
        raise


def iter_zip_entries(zip_path: str | Path) -> Iterator[str]:
    """Iterate over ZIP file entries without extracting.

    Args:
        zip_path: Path to the ZIP file.

    Yields:
        Entry names.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        yield from zf.namelist()


def read_zip_entry(zip_path: str | Path, entry_name: str) -> bytes:
    """Read a single entry from a ZIP file.

    Args:
        zip_path: Path to the ZIP file.
        entry_name: Name of the entry to read.

    Returns:
        Entry content as bytes.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        return zf.read(entry_name)


def get_file_size(file_path: str | Path) -> int:
    """Get file size in bytes."""
    return Path(file_path).stat().st_size


def ensure_directory(path: str | Path) -> Path:
    """Ensure a directory exists and return its Path."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
