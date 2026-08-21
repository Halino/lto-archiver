class LtoBackupError(Exception):
    """Base error shown to operators without a traceback."""


class ValidationError(LtoBackupError):
    pass


class CatalogError(LtoBackupError):
    pass


class CapacityError(LtoBackupError):
    pass


class CopyError(LtoBackupError):
    pass


class OperationCancelled(LtoBackupError):
    """The operator requested a cooperative stop at a safe I/O boundary."""
