"""Turning lines of text into the addresses to look up (files, stdin, the web form)."""

from __future__ import annotations

import codecs


def read_lines(lines) -> list[str]:
    """One address per line; "#" starts a comment; blank lines are skipped."""
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def decode_text(data: bytes) -> str:
    """UTF-8 (with or without BOM) or UTF-16 with BOM, e.g. from Windows PowerShell."""
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")
