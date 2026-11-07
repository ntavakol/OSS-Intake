"""Report writes that never follow a link and never leave half a file.

Each file is written to a new temporary file beside it (created exclusively, so not a link someone placed there)
and then moved over the target with os.replace, which replaces a symbolic or hard link at that name rather than
writing through it. A reader sees the old file or the new one, never a partial one. External audit SEC-01/11:
the folder is checked for links once, at the start (cli.prepare_out); this closes the gap after that check.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import IO

_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def _tmp_for(path: Path) -> Path:
    return path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")


@contextmanager
def _replacing(path: str | Path, binary: bool, newline: str | None = None) -> Iterator[IO]:
    target = Path(path)
    tmp = _tmp_for(target)
    fd = os.open(tmp, _FLAGS, 0o644)
    try:
        with (os.fdopen(fd, "wb") if binary else os.fdopen(fd, "w", encoding="utf-8", newline=newline)) as fh:
            yield fh
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def text_file(path: str | Path, newline: str | None = None) -> AbstractContextManager[IO]:
    """A text file to write, put in place when the block ends (for the csv writers)."""
    return _replacing(path, False, newline)


def write_text(path: str | Path, text: str) -> None:
    with _replacing(path, False) as fh:
        fh.write(text)


def write_bytes(path: str | Path, data: bytes) -> None:
    with _replacing(path, True) as fh:
        fh.write(data)
