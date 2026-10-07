#!/usr/bin/env python3
"""Detection Orchestrator - Basic workflow orchestration (mode management removed)"""

import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class OrchestratorState:
    """Current state of the orchestrator"""
    is_running: bool = False
    start_time: float = 0.0
    analyzers_loaded: int = 0
    last_scan_time: Optional[float] = None
    errors: List[str] = field(default_factory=list)


class DetectionOrchestrator:
    """
    Detection orchestrator for managing security scan workflows.
    
    Responsibilities:
    - Analyzer loading and tracking
    - Workflow coordination
    - State management
    
    Note: DetectionMode and mode switching have been removed (P1-2026-04-24).
    The tool now runs in a single adaptive mode based on EnvironmentContext.
    """
    
    _MAX_ERRORS = 100  # Cap error list size to prevent memory growth
    
    def __init__(self, analyzer_registry: Optional[List[tuple]] = None):
        """
        Initialize detection orchestrator.
        
        Args:
            analyzer_registry: List of (name, class) tuples from main.py
        """
        self.logger = logging.getLogger(__name__)
        self.analyzer_registry = analyzer_registry or []
        self.state = OrchestratorState()
        self._active_analyzers: List[tuple] = list(self.analyzer_registry)
        self.state.analyzers_loaded = len(self._active_analyzers)
        
        # Callbacks for extensibility
        self._on_scan_start_callbacks: List[callable] = []
        self._on_scan_complete_callbacks: List[callable] = []
    
    def register_on_scan_start(self, callback: callable) -> None:
        """Register callback for scan start events"""
        self._on_scan_start_callbacks.append(callback)
    
    def register_on_scan_complete(self, callback: callable) -> None:
        """Register callback for scan complete events"""
        self._on_scan_complete_callbacks.append(callback)
    
    def get_active_analyzers(self) -> List[tuple]:
        """Get list of active analyzers"""
        return self._active_analyzers
    
    def get_state(self) -> OrchestratorState:
        """Get current orchestrator state"""
        return self.state
    
    def start_scan(self) -> bool:
        """
        Mark scan as started.
        
        Returns:
            True if scan started successfully
        """
        if self.state.is_running:
            self.logger.warning("Scan already running")
            return False
        
        self.state.is_running = True
        self.state.start_time = time.monotonic()
        self.state.errors = []
        
        # Trigger callbacks
        for callback in self._on_scan_start_callbacks:
            try:
                callback(self._active_analyzers)
            except (OSError, ValueError, TypeError, RuntimeError) as e:
                self.logger.error(f"Scan start callback error: {e}")
        
        self.logger.info(f"Scan started with {len(self._active_analyzers)} analyzers")
        return True
    
    def complete_scan(self) -> float:
        """
        Mark scan as completed.
        
        Returns:
            Scan duration in seconds
        """
        if not self.state.is_running:
            return 0.0
        
        duration = time.monotonic() - self.state.start_time
        self.state.is_running = False
        self.state.last_scan_time = duration
        
        # Trigger callbacks
        for callback in self._on_scan_complete_callbacks:
            try:
                callback(duration)
            except (OSError, ValueError, TypeError, RuntimeError) as e:
                self.logger.error(f"Scan complete callback error: {e}")
        
        self.logger.info(f"Scan completed in {duration:.1f}s")
        return duration
    
    def add_error(self, error: str) -> None:
        """Add error to state, capped at _MAX_ERRORS to prevent memory growth"""
        if len(self.state.errors) >= self._MAX_ERRORS:
            self.state.errors.append(f"[error limit reached] {error}")
            self.state.errors = self.state.errors[-self._MAX_ERRORS:]
        else:
            self.state.errors.append(error)
        self.logger.error(f"Orchestrator error: {error}")
    
    def get_available_modes(self) -> List[Dict[str, Any]]:
        """Get available modes info (legacy - returns single mode)."""
        return [
            {
                "name": "adaptive",
                "description": "Single adaptive mode based on EnvironmentContext",
                "analyzers": "all",
                "interval": "on-demand",
                "resource_limit": "adaptive",
                "timeout": None,
            }
        ]
