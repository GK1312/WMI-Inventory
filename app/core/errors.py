from enum import IntEnum
from typing import ClassVar

class Severity(IntEnum):
    MINOR = 10
    WARNING = 20
    VALIDATION = 30
    STRICT = 40

class AppError(Exception):
    severity: ClassVar[Severity] = Severity.WARNING

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field

class MinorError(AppError):
    severity: ClassVar[Severity] = Severity.MINOR

class WarningError(AppError):
    severity: ClassVar[Severity] = Severity.WARNING

class ValidationError(AppError):
    severity: ClassVar[Severity] = Severity.VALIDATION

class StrictError(AppError):
    severity: ClassVar[Severity] = Severity.STRICT

class SecurityError(StrictError):
    pass