"""Base scanner protocol and registry."""

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable
from dataclasses import dataclass


@dataclass
class Package:
    """Represents a software package."""
    name: str
    version: str
    ecosystem: str  # npm, pypi, maven, etc.
    cpe: str | None = None  # Constructed CPE if known


@runtime_checkable
class Scanner(Protocol):
    """Protocol for scanner adapters."""

    name: str

    def scan(self, input_path: str) -> list[Package]:
        """Scan input and return list of packages."""
        ...

    def supports(self, input_path: str) -> bool:
        """Check if this scanner supports the given input."""
        ...


class BaseScanner(ABC):
    """Abstract base class for scanner adapters."""

    name: str = "base"

    @abstractmethod
    def scan(self, input_path: str) -> list[Package]:
        """Scan input and return list of packages."""
        pass

    @abstractmethod
    def supports(self, input_path: str) -> bool:
        """Check if this scanner supports the given input."""
        pass


class ScannerRegistry:
    """Registry for scanner adapters."""

    def __init__(self):
        self._scanners: list[Scanner] = []

    def register(self, scanner: Scanner) -> None:
        """Register a scanner."""
        self._scanners.append(scanner)

    def get_scanner(self, input_path: str) -> Scanner | None:
        """Get the best scanner for the given input."""
        for scanner in self._scanners:
            if scanner.supports(input_path):
                return scanner
        return None

    def all_scanners(self) -> list[Scanner]:
        """Get all registered scanners."""
        return self._scanners.copy()


# Global registry
_registry = ScannerRegistry()


def get_registry() -> ScannerRegistry:
    """Get the global scanner registry."""
    return _registry


def register_scanner(scanner: Scanner) -> None:
    """Register a scanner with the global registry."""
    _registry.register(scanner)
