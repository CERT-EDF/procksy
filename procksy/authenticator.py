"""Authenticator module
"""
import typing as t
from dataclasses import dataclass, field
from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from .logging import LOGGER


PASSWORD_HASHER = PasswordHasher()


@dataclass
class Authenticator:
    """Filter object"""

    enabled: bool = False
    users: t.Mapping[bytes, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, dct):
        """Build instance from dict"""
        return cls(
            enabled=dct['enabled'],
            users={
                user.encode('utf-8'): digest
                for user, digest in dct['users'].items()
            },
        )

    def is_allowed(self, user: bytes, secret: bytes) -> bool:
        """Determine if candidate is filtered based on filter mode and values"""
        digest = self.users.get(user)
        if digest is None:
            LOGGER.warning("unknown user %s", user)
            return False
        try:
            status = PASSWORD_HASHER.verify(digest, secret)
            if status:
                LOGGER.info("authentication success for %s", user)
            return status
        except VerifyMismatchError:
            LOGGER.warning("authentication failure for %s", user)
        except VerificationError:
            LOGGER.error("verification error for user %s", user)
        except InvalidHashError:
            LOGGER.error("invalid hash for user %s", user)
        return False
