"""Custom exception hierarchy for the DAST framework."""


class DASTError(Exception):
    """Base exception for all DAST framework errors."""


class CrawlerError(DASTError):
    """Raised when the crawler encounters an unrecoverable error."""


class AuthenticationError(DASTError):
    """Raised when pre-scan form-based authentication fails."""


class VectorAnalysisError(DASTError):
    """Raised when vector analysis encounters an unrecoverable error."""


class FuzzingError(DASTError):
    """Raised when the fuzzing engine encounters an unrecoverable error."""


class ReportError(DASTError):
    """Raised when report generation fails."""


class ConfigurationError(DASTError):
    """Raised when the supplied configuration is invalid or incomplete."""


class PayloadLoadError(DASTError):
    """Raised when payload files cannot be loaded."""
