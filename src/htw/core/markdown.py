"""Markdown escaping for text that originates in scanned content.

File names, package names and scanner messages are attacker-influenced when the
scanned repository is. Reports are read by people and may be pasted into trackers, so
such text must not be able to inject links, images or HTML.
"""

from __future__ import annotations

import re

_SPECIAL_RE = re.compile(r"([\\`*_\[\]|#!~])")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9\-._~:/?#@!$&'()*+,;=%]+$")


def md(text: object) -> str:
    """Escape text for use in Markdown prose and table cells."""
    flat = " ".join(str(text if text is not None else "").split())
    # Entities rather than backslashes for HTML: every renderer honours them.
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _SPECIAL_RE.sub(r"\\\1", flat)


def code(text: object) -> str:
    """Render text as an inline code span that cannot be broken out of."""
    flat = " ".join(str(text if text is not None else "").split())
    flat = flat.replace("`", "'").replace("|", "\\|")
    return f"`{flat}`" if flat else ""


def link(url: str) -> str | None:
    """Render a reference as an autolink, or None if it is not a plain http(s) URL."""
    if len(url) > 300 or not _URL_RE.match(url):
        return None
    return f"<{url}>"
