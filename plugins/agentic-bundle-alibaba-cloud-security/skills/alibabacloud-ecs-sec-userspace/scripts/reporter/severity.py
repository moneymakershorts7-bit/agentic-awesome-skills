"""Threat severity level definitions."""
import enum


class Severity(enum.Enum):
    """Threat severity levels with scores for risk assessment."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        """Return numeric score for severity level."""
        scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        return scores[self]

    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return self.score < other.score

    def __le__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return self.score <= other.score

    def __gt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return self.score > other.score

    def __ge__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return self.score >= other.score

    @classmethod
    def from_string(cls, name: str) -> 'Severity':
        """Create Severity from string (case-insensitive). Returns INFO for invalid input."""
        try:
            return cls(name.upper())
        except (ValueError, AttributeError):
            return cls.INFO
