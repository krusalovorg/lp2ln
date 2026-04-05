"""Настройка logging для CLI."""

from __future__ import annotations

import logging
import sys


def setup_logging(*, level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for h in root.handlers[:]:
        root.removeHandler(h)
    h = logging.StreamHandler(sys.stderr)
    h.setLevel(level)
    h.setFormatter(
        logging.Formatter(
            "%(levelname)s %(name)s: %(message)s",
        )
    )
    root.addHandler(h)
    # шум matplotlib при DEBUG
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
