"""Application-specific errors for Luva."""


class LuvaError(Exception):
    """Base class for Luva errors."""


class PCAPReadError(LuvaError):
    """PCAP file could not be read."""


class PCAPValidationError(LuvaError):
    """PCAP path or format validation failed."""


class ParserError(LuvaError):
    """Protocol parser failure."""


class ParserNotFoundError(LuvaError):
    """No parser available for the requested protocol."""


class RuleLoadError(LuvaError):
    """Detection rule file could not be loaded."""


class RuleEvaluationError(LuvaError):
    """Rule evaluation failed at runtime."""


class ReportGenerationError(LuvaError):
    """Report or export generation failed."""


class PipelineError(LuvaError):
    """Analysis pipeline failure."""


class ConfigError(LuvaError):
    """Invalid analysis configuration."""
