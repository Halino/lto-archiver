class LtoBackupError(Exception):
    """Base error shown to operators without a traceback."""


class ValidationError(LtoBackupError):
    pass


class NoNewSourceFiles(ValidationError):
    """A completed incremental discovery found no eligible source versions."""

    code = "no_new_source_files"


class CutoverAuthorizationInvalid(ValidationError):
    """Cutover evidence is missing, expired, consumed, or no longer bound."""


class CatalogError(LtoBackupError):
    pass


class CatalogBackupDurabilityError(CatalogError):
    """The backup is published but its directory sync could not be confirmed."""


class CapacityError(LtoBackupError):
    pass


class CopyError(LtoBackupError):
    pass


class OperationCancelled(LtoBackupError):
    """The operator requested a cooperative stop at a safe I/O boundary."""
