class SanitizationError(Exception):
    """A file cannot be safely sanitized."""


class UnsupportedDocument(SanitizationError):
    """The file type is not supported."""


class MalwareDetected(SanitizationError):
    """The antivirus scanner detected malware."""


class ScannerUnavailable(SanitizationError):
    """The antivirus scanner is not available."""


class ProcessingFailed(SanitizationError):
    """A sanitizer or validation step failed."""

