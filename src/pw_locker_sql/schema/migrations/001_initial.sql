CREATE TABLE dbo.PasswordLockerSchemaVersion (
    singleton_id TINYINT NOT NULL,
    schema_version INT NOT NULL,
    applied_at DATETIMEOFFSET(7) NOT NULL
        CONSTRAINT DF_PasswordLockerSchemaVersion_AppliedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_PasswordLockerSchemaVersion PRIMARY KEY (singleton_id),
    CONSTRAINT CK_PasswordLockerSchemaVersion_Singleton CHECK (singleton_id = 1),
    CONSTRAINT CK_PasswordLockerSchemaVersion_Positive CHECK (schema_version > 0)
);

CREATE TABLE dbo.PasswordLockerVault (
    vault_id UNIQUEIDENTIFIER NOT NULL,
    singleton_id TINYINT NOT NULL
        CONSTRAINT DF_PasswordLockerVault_Singleton DEFAULT (1),
    format_version SMALLINT NOT NULL,
    kdf_algorithm NVARCHAR(64) NOT NULL,
    kdf_version INT NOT NULL,
    kdf_memory_cost INT NOT NULL,
    kdf_time_cost INT NOT NULL,
    kdf_parallelism INT NOT NULL,
    derived_key_length SMALLINT NOT NULL,
    kdf_salt VARBINARY(16) NOT NULL,
    wrap_algorithm NVARCHAR(64) NOT NULL,
    wrap_envelope_version SMALLINT NOT NULL,
    wrapped_key_ciphertext VARBINARY(32) NOT NULL,
    wrapping_nonce VARBINARY(12) NOT NULL,
    wrapping_authentication_tag VARBINARY(16) NOT NULL,
    wrap_associated_data VARBINARY(MAX) NOT NULL,
    created_at DATETIMEOFFSET(7) NOT NULL
        CONSTRAINT DF_PasswordLockerVault_CreatedAt DEFAULT SYSUTCDATETIME(),
    row_version ROWVERSION NOT NULL,
    CONSTRAINT PK_PasswordLockerVault PRIMARY KEY (vault_id),
    CONSTRAINT UQ_PasswordLockerVault_Singleton UNIQUE (singleton_id),
    CONSTRAINT CK_PasswordLockerVault_Singleton CHECK (singleton_id = 1),
    CONSTRAINT CK_PasswordLockerVault_SaltLength CHECK (DATALENGTH(kdf_salt) = 16),
    CONSTRAINT CK_PasswordLockerVault_WrappedKeyLength
        CHECK (DATALENGTH(wrapped_key_ciphertext) = 32),
    CONSTRAINT CK_PasswordLockerVault_NonceLength CHECK (DATALENGTH(wrapping_nonce) = 12),
    CONSTRAINT CK_PasswordLockerVault_TagLength
        CHECK (DATALENGTH(wrapping_authentication_tag) = 16)
);

CREATE TABLE dbo.PasswordLockerCredential (
    vault_id UNIQUEIDENTIFIER NOT NULL,
    normalized_account NVARCHAR(450) NOT NULL,
    envelope_version SMALLINT NOT NULL,
    algorithm NVARCHAR(64) NOT NULL,
    ciphertext VARBINARY(MAX) NOT NULL,
    nonce VARBINARY(12) NOT NULL,
    authentication_tag VARBINARY(16) NOT NULL,
    associated_data VARBINARY(MAX) NOT NULL,
    created_at DATETIMEOFFSET(7) NOT NULL,
    updated_at DATETIMEOFFSET(7) NOT NULL,
    revision INT NOT NULL,
    row_version ROWVERSION NOT NULL,
    CONSTRAINT PK_PasswordLockerCredential PRIMARY KEY (vault_id, normalized_account),
    CONSTRAINT FK_PasswordLockerCredential_Vault FOREIGN KEY (vault_id)
        REFERENCES dbo.PasswordLockerVault (vault_id),
    CONSTRAINT CK_PasswordLockerCredential_NonceLength CHECK (DATALENGTH(nonce) = 12),
    CONSTRAINT CK_PasswordLockerCredential_TagLength
        CHECK (DATALENGTH(authentication_tag) = 16),
    CONSTRAINT CK_PasswordLockerCredential_Revision CHECK (revision > 0)
);
