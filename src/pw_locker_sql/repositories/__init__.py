"""Encrypted repository contracts and test doubles."""

from pw_locker_sql.repositories.memory import InMemoryCredentialRepository
from pw_locker_sql.repositories.protocol import CredentialRepository

__all__ = ["CredentialRepository", "InMemoryCredentialRepository"]
