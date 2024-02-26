"""Filter module
"""
import typing as t
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from .logging import LOGGER


class FilterMode(Enum):
    """Filter mode"""

    NONE = 'none'
    DENY = 'deny'
    ALLOW = 'allow'


DEFAULT_FILTER_MODE = FilterMode.NONE


def _items_from_list(lst: t.List[str]):
    for item in lst:
        yield item.strip().lower()


def _items_from_filepath(filepath: Path):
    if not filepath.is_file():
        LOGGER.warning("ignored, file not found: %s", filepath)
        return
    with filepath.open('r') as fobj:
        for line in fobj:
            yield line.strip().lower()


@dataclass
class Filter:
    """Filter object"""

    mode: FilterMode = DEFAULT_FILTER_MODE
    values: t.Set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, dct):
        """Build instance from dict"""
        values = set()
        if 'values' in dct and dct['values']:
            values.update(list(_items_from_list(dct['values'])))
        if 'filepath' in dct and dct['filepath']:
            values.update(list(_items_from_filepath(Path(dct['filepath']))))
        return cls(mode=FilterMode(dct['mode']), values=values)

    def is_allowed(self, candidate: str, port: t.Optional[int] = None):
        """Determine if candidate is filtered based on filter mode and values"""
        if self.mode == FilterMode.NONE:
            return True
        candidate = candidate.lower()
        candidate_port = f'{candidate}:{port}'
        if candidate in self.values or candidate_port in self.values:
            return self.mode == FilterMode.ALLOW
        return self.mode == FilterMode.DENY
