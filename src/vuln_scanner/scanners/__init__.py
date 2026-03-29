"""Scanner adapters module."""

from .base import ScannerRegistry, get_registry, register_scanner, Scanner, Package, BaseScanner
from .requirements import RequirementsScanner
from .package_json import PackageJsonScanner
from .sbom import SBOMScanner
from .trivy import TrivyScanner


def register_all_scanners():
    """Register all built-in scanners."""
    registry = get_registry()
    registry.register(RequirementsScanner())
    registry.register(PackageJsonScanner())
    registry.register(SBOMScanner())
    registry.register(TrivyScanner())


__all__ = [
    "ScannerRegistry",
    "get_registry",
    "register_scanner",
    "register_all_scanners",
    "Scanner",
    "Package",
    "BaseScanner",
    "RequirementsScanner",
    "PackageJsonScanner",
    "SBOMScanner",
    "TrivyScanner",
]
