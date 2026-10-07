"""
Environment detectionModule - 识别RunEnvironment（Host/WSL2）
"""
from .detector import EnvInfo, EnvironmentDetector

__all__ = ["EnvInfo", "EnvironmentDetector"]
