"""Configuration module
"""
from json import JSONDecodeError, loads
from pathlib import Path
from dataclasses import dataclass, field
from .filter import Filter
from .logging import LOGGER
from .authenticator import Authenticator

FILENAME = 'procksy.json'
DEFAULT_LOCATIONS = [
    Path(FILENAME),
    Path.home() / '.config' / 'procksy' / FILENAME,
    Path('/etc') / 'procksy' / FILENAME,
]
DEFAULT_BIND_ADDR = '127.0.0.1'
DEFAULT_BIND_PORT = 9050
DEFAULT_BUFFER_SIZE = 2048
DEFAULT_MAX_THREADS = 200
DEFAULT_SOCK_TIMEOUT = 5


@dataclass
class ProcksyConfig:
    """Procksy configuration"""

    client_filter: Filter = field(default_factory=Filter)
    target_filter: Filter = field(default_factory=Filter)
    authenticator: Authenticator = field(default_factory=Authenticator)
    bind_addr: str = DEFAULT_BIND_ADDR
    bind_port: int = DEFAULT_BIND_PORT
    buffer_size: int = DEFAULT_BUFFER_SIZE
    max_threads: int = DEFAULT_MAX_THREADS
    sock_timeout: int = DEFAULT_SOCK_TIMEOUT

    @classmethod
    def from_dict(cls, dct) -> 'ProcksyConfig':
        """Build instance from dict"""
        return cls(
            client_filter=Filter.from_dict(dct.get('client_filter', {})),
            target_filter=Filter.from_dict(dct.get('target_filter', {})),
            authenticator=Authenticator.from_dict(
                dct.get('authenticator', {})
            ),
            bind_addr=dct.get('bind_addr', DEFAULT_BIND_ADDR),
            bind_port=dct.get('bind_port', DEFAULT_BIND_PORT),
            buffer_size=dct.get('buffer_size', DEFAULT_BUFFER_SIZE),
            max_threads=dct.get('max_threads', DEFAULT_MAX_THREADS),
            sock_timeout=dct.get('sock_timeout', DEFAULT_SOCK_TIMEOUT),
        )

    @classmethod
    def from_filepath(cls, filepath: Path) -> 'ProcksyConfig':
        """Build instance from filepath"""
        LOGGER.info("loading configuration from %s", filepath)
        try:
            txt = filepath.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            LOGGER.exception("error while loading configuration data")
            return cls()
        try:
            dct = loads(txt)
        except JSONDecodeError:
            LOGGER.exception("error while decoding configuration data")
            return cls()
        return cls.from_dict(dct)

    @classmethod
    def from_default_locations(cls) -> 'ProcksyConfig':
        """Build instance from default locations"""
        for filepath in DEFAULT_LOCATIONS:
            if not filepath.is_file():
                LOGGER.warning("configuration file not found: %s", filepath)
                continue
            return cls.from_filepath(filepath)
        LOGGER.warning("using default configuration")
        return cls()

    def override(self, args):
        """Override configuration with command line arguments"""
        client_filter = None
        if args.client_filter:
            mode, values = args.client_filter.split(':', 1)
            values = values.split(',')
            client_filter = Filter.from_dict({'mode': mode, 'values': values})
        target_filter = None
        if args.target_filter:
            mode, values = args.target_filter.split(':', 1)
            values = values.split(',')
            target_filter = Filter.from_dict({'mode': mode, 'values': values})
        authenticator = None
        if args.users:
            users = {}
            for user in args.users:
                user, digest = user.split(':', 1)
                users[user] = digest
            authenticator = Authenticator.from_dict(
                {'enabled': True, 'users': users}
            )
        self.client_filter = client_filter or self.client_filter
        self.target_filter = target_filter or self.target_filter
        self.authenticator = authenticator or self.authenticator
        self.bind_addr = args.bind_addr or self.bind_addr
        self.bind_port = args.bind_port or self.bind_port
        self.buffer_size = args.buffer_size or self.buffer_size
        self.max_threads = args.max_threads or self.max_threads
        self.sock_timeout = args.sock_timeout or self.sock_timeout
