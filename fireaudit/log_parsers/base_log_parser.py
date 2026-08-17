"""
Abstract interface for traffic log parsers, same pattern as BaseParser for
firewall configs. Every log format parser implements parse() and returns a
list of LogEvent objects.
"""

from abc import ABC, abstractmethod

from fireaudit.models import LogEvent


class BaseLogParser(ABC):
    format_name: str = "unknown"

    @abstractmethod
    def parse(self, filepath: str) -> list[LogEvent]:
        raise NotImplementedError
