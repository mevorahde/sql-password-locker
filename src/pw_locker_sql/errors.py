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


class InvalidMasterPasswordError(PasswordLockerError):
    """Raised when vault-key authentication cannot be completed."""

    default_message = "Vault authentication failed."


class AuthenticationError(PasswordLockerError):
    """Raised when encrypted credential authentication cannot be completed."""

    default_message = "Encrypted data authentication failed."


class CryptographicOperationError(PasswordLockerError):
    """Raised for safe translation of lower-level cryptographic failures."""

    default_message = "The cryptographic operation failed."


class VaultNotInitializedError(RepositoryError):
    """Raised when encrypted vault metadata does not exist."""

    default_message = "The vault is not initialized."


class VaultAlreadyInitializedError(RepositoryError):
    """Raised when initialization would replace vault metadata."""

    default_message = "The vault is already initialized."


class SchemaMigrationError(RepositoryError):
    """Raised when schema state or migration execution is invalid."""

    default_message = "The database schema operation failed."


class UnsupportedSchemaVersionError(RepositoryError):
    """Raised when a database schema is newer than this application."""

    default_message = "The database schema version is not supported."


class ClipboardError(PasswordLockerError):
    """Raised when clipboard access cannot be completed safely."""

    default_message = "The clipboard operation failed."


class SecurePromptError(PasswordLockerError):
    """Raised when a secret cannot be collected from an interactive terminal."""

    default_message = "Secure interactive input is required."


class PasswordConfirmationError(PasswordLockerError):
    """Raised when two secret prompt results do not match."""

    default_message = "Password confirmation did not match."
