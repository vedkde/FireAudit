"""
Abstract parser interface. Every vendor-specific parser implements parse().

Keeping this as an ABC means adding a new vendor (Check Point, etc.) later
only requires a new class here, nothing else in the codebase changes.
"""

from abc import ABC, abstractmethod
from fireaudit.models import RuleSet


class BaseParser(ABC):
    vendor_name: str = "unknown"

    @abstractmethod
    def parse(self, filepath: str) -> RuleSet:
        raise NotImplementedError
