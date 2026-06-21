"""Structured logging configuration.

Provides a single :func:`configure_logging` entry point and a :func:`get_logger`
helper so every module logs in a consistent format. Safe to call multiple times.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

_CONFIGURED = False
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def configure_logging(level: Optional[str] = None) -> None:
    """Configure the root logger once.

    Parameters
    ----------
    level:
        Logging level name (e.g. ``"INFO"``). Falls back to the value from
        settings, then ``INFO``.
    """
    global _CONFIGURED
    if _CONFIGURED:
        if level:
            logging.getLogger().setLevel(level.upper())
        return

    if level is None:
        try:
            from .settings import get_settings

            level = get_settings().csai_log_level
        except Exception:
            level = "INFO"

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Quiet noisy third-party loggers.
    for noisy in ("httpx", "urllib3", "openai", "faiss"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for ``name``."""
    configure_logging()
    return logging.getLogger(name)
