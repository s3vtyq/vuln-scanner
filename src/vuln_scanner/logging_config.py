"""Centralized logging configuration for vuln-scanner."""

import logging
import os
import sys
from typing import Optional


_loggers: dict[str, logging.Logger] = {}


def setup_logging(
    level: Optional[str] = None,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Configure logging for vuln-scanner.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               Defaults to VULN_SCANNER_LOG_LEVEL env var or "INFO".
        format_string: Custom format string. Defaults to structured format.

    Returns:
        Root logger for vuln_scanner.
    """
    log_level = level or os.getenv("VULN_SCANNER_LOG_LEVEL", "INFO").upper()

    if format_string is None:
        format_string = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format=format_string,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout
    )

    logger = logging.getLogger("vuln_scanner")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Module name (e.g., "nvd.client", "core.enricher")

    Returns:
        Logger instance.
    """
    full_name = f"vuln_scanner.{name}"

    if full_name not in _loggers:
        _loggers[full_name] = logging.getLogger(full_name)

    return _loggers[full_name]
