"""Logging for NXray itself."""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Send application logs to stdout so `docker compose logs` shows them."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))

    # Reconfiguring (in tests, or on reload) must not stack handlers.
    for existing in list(root.handlers):
        root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root.addHandler(handler)
    return logging.getLogger("nxray")
