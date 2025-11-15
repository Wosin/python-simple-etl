from enum import Enum


class ThreatLevel(str, Enum):
    """
    Enum representing the threat level of a login attempt.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
