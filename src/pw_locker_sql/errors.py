"""Safe application exceptions.

Messages are deliberately fixed so callers cannot accidentally include secrets.
"""


class PasswordLockerError(Exception):
    """Base class for expected Password Locker failures."""

    default_message = "The password locker operation failed."

    def __init__(self) -> None:
        super().__init__(self.default_message)


class ConfigurationError(PasswordLockerError):
    """Raised when supplied configuration is incomplete or inconsistent."""

    default_message = "The supplied configuration is invalid."


class ValidationError(PasswordLockerError):
    """Raised when domain input is malformed."""

    default_message = "The supplied value is invalid."


class CredentialNotFoundError(PasswordLockerError):
    """Raised when a requested credential is absent."""

    default_message = "The requested credential was not found."


class CredentialAlreadyExistsError(PasswordLockerError):
    """Raised when a normalized account identifier already exists."""

    default_message = "A credential with that account identifier already exists."


class RepositoryError(PasswordLockerError):
    """Raised when encrypted persistence is unavailable or invalid."""

    default_message = "The credential repository operation failed."


class VaultLockedError(PasswordLockerError):
    """Raised when an operation requires an unlocked vault."""

    default_message = "The vault is locked."


class UnsupportedFormatError(PasswordLockerError):
    """Raised for unsupported encrypted data formats."""

    default_message = "The encrypted data format is not supported."


class CryptographicProviderUnavailableError(PasswordLockerError):
    """Raised while cryptographic implementation is intentionally deferred."""

    default_message = (
        "This operation is not available until a cryptographic provider is configured."
    )
