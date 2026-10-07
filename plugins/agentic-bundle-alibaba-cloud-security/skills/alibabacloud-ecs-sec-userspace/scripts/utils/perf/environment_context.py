"""Performance Regression Context Awareness

Records test environment information (CPU, memory, disk) and adjusts performance
thresholds based on environment differences. Generates environment comparison reports.

This module solves the problem where performance regression tests don't account for
environmental differences, leading to false positives when comparing across different
hardware configurations.

Usage:
    from scripts.perf.environment_context import EnvironmentContextDetector
    
    detector = EnvironmentContextDetector()
    
    # Record current environment
    context = detector.record_environment()
    
    # Get adjusted thresholds for current environment
    adjusted_budgets = detector.get_adjusted_budgets(context)
    
    # Compare two environments
    comparison = detector.compare_environments(context_a, context_b)

ATT&CK mapping:
- N/A (Internal tooling for performance testing)
"""
import logging
import os
import platform
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Any, List
import json

logger = logging.getLogger(__name__)


@dataclass
class CPUInfo:
    """CPU information"""
    model: str = ""
    cores_physical: int = 0
    cores_logical: int = 0
    frequency_mhz: float = 0.0
    architecture: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "cores_physical": self.cores_physical,
            "cores_logical": self.cores_logical,
            "frequency_mhz": self.frequency_mhz,
            "architecture": self.architecture,
        }


@dataclass
class MemoryInfo:
    """Memory information"""
    total_mb: float = 0.0
    available_mb: float = 0.0
    used_percent: float = 0.0
    swap_total_mb: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_mb": self.total_mb,
            "available_mb": self.available_mb,
            "used_percent": self.used_percent,
            "swap_total_mb": self.swap_total_mb,
        }


@dataclass
class DiskInfo:
    """Disk information"""
    total_gb: float = 0.0
    used_gb: float = 0.0
    free_gb: float = 0.0
    used_percent: float = 0.0
    iops_read: float = 0.0
    iops_write: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_gb": self.total_gb,
            "used_gb": self.used_gb,
            "free_gb": self.free_gb,
            "used_percent": self.used_percent,
            "iops_read": self.iops_read,
            "iops_write": self.iops_write,
        }


@dataclass
class EnvironmentContext:
    """Complete environment context for performance testing"""
    timestamp: str = ""
    hostname: str = ""
    
    # Hardware info
    cpu: CPUInfo = field(default_factory=CPUInfo)
    memory: MemoryInfo = field(default_factory=MemoryInfo)
    disk: DiskInfo = field(default_factory=DiskInfo)
    
    # System info
    os_name: str = ""
    os_version: str = ""
    kernel_version: str = ""
    python_version: str = ""
    
    # Load averages
    load_1min: float = 0.0
    load_5min: float = 0.0
    load_15min: float = 0.0
    
    # Environment classification
    environment_class: str = "unknown"  # low-end, mid-range, high-end
    performance_score: float = 1.0  # Multiplier for thresholds (1.0 = baseline)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "cpu": self.cpu.to_dict(),
            "memory": self.memory.to_dict(),
            "disk": self.disk.to_dict(),
            "os_name": self.os_name,
            "os_version": self.os_version,
            "kernel_version": self.kernel_version,
            "python_version": self.python_version,
            "load_1min": self.load_1min,
            "load_5min": self.load_5min,
            "load_15min": self.load_15min,
            "environment_class": self.environment_class,
            "performance_score": self.performance_score,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


class EnvironmentContextDetector:
    """Detects and records environment information for performance regression testing"""
    
    # Baseline environment specifications (reference machine)
    BASELINE_CPU_CORES = 4
    BASELINE_CPU_FREQ_MHZ = 2500.0
    BASELINE_MEMORY_MB = 8192.0
    BASELINE_DISK_IOPS = 1000.0
    
    # Environment classification thresholds
    LOW_END_SCORE_THRESHOLD = 0.5
    HIGH_END_SCORE_THRESHOLD = 1.5
    
    def __init__(self):
        self._cache: Optional[EnvironmentContext] = None
    
    def record_environment(self, force: bool = False) -> EnvironmentContext:
        """Record current environment information
        
        Args:
            force: Force re-detection even if cached
            
        Returns:
            EnvironmentContext with complete environment information
        """
        if self._cache is not None and not force:
            return self._cache
        
        from datetime import datetime, timezone
        
        context = EnvironmentContext()
        context.timestamp = datetime.now(timezone.utc).isoformat()
        context.hostname = platform.node()
        
        # Detect hardware and system info
        context.cpu = self._detect_cpu()
        context.memory = self._detect_memory()
        context.disk = self._detect_disk()
        
        # System information
        context.os_name = platform.system()
        context.os_version = platform.version()
        context.kernel_version = platform.release()
        context.python_version = platform.python_version()
        
        # Load averages (Linux only)
        try:
            load_avg = os.getloadavg()
            context.load_1min = load_avg[0]
            context.load_5min = load_avg[1]
            context.load_15min = load_avg[2]
        except (OSError, AttributeError):
            # Windows doesn't support getloadavg
            context.load_1min = 0.0
            context.load_5min = 0.0
            context.load_15min = 0.0
        
        # Calculate performance score and environment class
        context.performance_score = self._calculate_performance_score(context)
        context.environment_class = self._classify_environment(context.performance_score)
        
        self._cache = context
        logger.info(
            f"Environment recorded: {context.environment_class} "
            f"(score: {context.performance_score:.2f})"
        )
        
        return context
    
    def _detect_cpu(self) -> CPUInfo:
        """Detect CPU information"""
        cpu_info = CPUInfo()
        cpu_info.architecture = platform.machine()
        
        # Try to get CPU info from /proc/cpuinfo (Linux)
        try:
            cpuinfo_path = Path("/proc/cpuinfo")
            if cpuinfo_path.exists():
                content = cpuinfo_path.read_text(encoding='utf-8')
                
                # Extract model name
                for line in content.split('\n'):
                    if line.startswith('model name'):
                        cpu_info.model = line.split(':', 1)[1].strip()
                        break
                
                # Count physical cores
                physical_ids = set()
                core_ids = set()
                for line in content.split('\n'):
                    if line.startswith('physical id'):
                        physical_ids.add(line.split(':', 1)[1].strip())
                    elif line.startswith('core id'):
                        core_ids.add(line.split(':', 1)[1].strip())
                
                cpu_info.cores_physical = len(physical_ids) * len(core_ids) if physical_ids and core_ids else 0
                
                # Count logical cores
                processors = [line for line in content.split('\n') if line.startswith('processor')]
                cpu_info.cores_logical = len(processors)
                
                # Get CPU frequency
                for line in content.split('\n'):
                    if line.startswith('cpu MHz'):
                        try:
                            cpu_info.frequency_mhz = float(line.split(':', 1)[1].strip())
                        except ValueError:
                            pass
                        break
        
        except (OSError, ValueError, IndexError) as e:
            logger.warning(f"Failed to read /proc/cpuinfo: {e}")
        
        # Fallback to platform module
        if not cpu_info.model:
            cpu_info.model = platform.processor()
        
        if cpu_info.cores_logical == 0:
            try:
                import multiprocessing
                cpu_info.cores_logical = multiprocessing.cpu_count()
            except (ImportError, OSError, ValueError):
                cpu_info.cores_logical = 1
        
        if cpu_info.cores_physical == 0:
            # Estimate physical cores (assume 2 logical per physical)
            cpu_info.cores_physical = max(1, cpu_info.cores_logical // 2)
        
        return cpu_info
    
    def _detect_memory(self) -> MemoryInfo:
        """Detect memory information"""
        mem_info = MemoryInfo()
        
        try:
            # Try reading from /proc/meminfo (Linux)
            meminfo_path = Path("/proc/meminfo")
            if meminfo_path.exists():
                content = meminfo_path.read_text(encoding='utf-8')
                
                for line in content.split('\n'):
                    if line.startswith('MemTotal:'):
                        mem_info.total_mb = float(line.split()[1]) / 1024
                    elif line.startswith('MemAvailable:'):
                        mem_info.available_mb = float(line.split()[1]) / 1024
                    elif line.startswith('SwapTotal:'):
                        mem_info.swap_total_mb = float(line.split()[1]) / 1024
                
                if mem_info.total_mb > 0:
                    mem_info.used_percent = (
                        (mem_info.total_mb - mem_info.available_mb) / mem_info.total_mb * 100
                    )
        
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to read /proc/meminfo: {e}")
        
        # Fallback: use psutil if available
        if mem_info.total_mb == 0:
            try:
                import psutil
                mem = psutil.virtual_memory()
                mem_info.total_mb = mem.total / (1024 * 1024)
                mem_info.available_mb = mem.available / (1024 * 1024)
                mem_info.used_percent = mem.percent
                
                swap = psutil.swap_memory()
                mem_info.swap_total_mb = swap.total / (1024 * 1024)
            
            except ImportError:
                logger.debug("psutil not available, using fallback memory detection")
                # Very rough fallback estimate
                mem_info.total_mb = 4096.0
                mem_info.available_mb = 2048.0
                mem_info.used_percent = 50.0
        
        return mem_info
    
    def _detect_disk(self) -> DiskInfo:
        """Detect disk information"""
        disk_info = DiskInfo()
        
        try:
            # Get disk usage for root partition
            stat = os.statvfs('/')
            
            total_bytes = stat.f_frsize * stat.f_blocks
            free_bytes = stat.f_frsize * stat.f_bfree
            used_bytes = total_bytes - free_bytes
            
            disk_info.total_gb = total_bytes / (1024 ** 3)
            disk_info.used_gb = used_bytes / (1024 ** 3)
            disk_info.free_gb = free_bytes / (1024 ** 3)
            
            if disk_info.total_gb > 0:
                disk_info.used_percent = (disk_info.used_gb / disk_info.total_gb) * 100
        
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to get disk usage: {e}")
        
        # Try to detect IOPS using fio or simple benchmark
        disk_info.iops_read, disk_info.iops_write = self._estimate_disk_iops()
        
        return disk_info
    
    def _estimate_disk_iops(self) -> tuple:
        """Estimate disk IOPS (rough estimate)"""
        read_iops = 0.0
        write_iops = 0.0
        
        # Try using dd for a rough estimate
        try:
            # Simple read test (read 100MB)
            result = subprocess.run(
                ['dd', 'if=/dev/zero', 'of=/dev/null', 'bs=4k', 'count=25600', 'status=none'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10
            )
            
            # Parse output to get throughput (very rough IOPS estimate)
            if result.returncode == 0:
                # Assume ~4K block size operations
                # This is a very rough estimate
                read_iops = 1000.0  # Default baseline
        
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Disk IOPS estimation failed: {e}")
            read_iops = self.BASELINE_DISK_IOPS
        
        write_iops = read_iops * 0.8  # Assume write is 80% of read
        
        return read_iops, write_iops
    
    def _calculate_performance_score(self, context: EnvironmentContext) -> float:
        """Calculate performance score relative to baseline
        
        Returns:
            Performance multiplier (1.0 = baseline, >1.0 = faster, <1.0 = slower)
        """
        # CPU score (based on cores and frequency)
        cpu_score = 1.0
        if context.cpu.cores_logical > 0:
            core_ratio = context.cpu.cores_logical / self.BASELINE_CPU_CORES
            freq_ratio = context.cpu.frequency_mhz / self.BASELINE_CPU_FREQ_MHZ if context.cpu.frequency_mhz > 0 else 1.0
            cpu_score = (core_ratio * 0.7 + freq_ratio * 0.3)  # Cores more important for parallel work
        
        # Memory score (based on total memory)
        memory_score = 1.0
        if context.memory.total_mb > 0:
            memory_score = context.memory.total_mb / self.BASELINE_MEMORY_MB
        
        # Disk score (based on IOPS)
        disk_score = 1.0
        if context.disk.iops_read > 0:
            disk_score = context.disk.iops_read / self.BASELINE_DISK_IOPS
        
        # Load factor (higher load = slower performance)
        load_factor = 1.0
        if context.load_5min > 0 and context.cpu.cores_logical > 0:
            load_ratio = context.load_5min / context.cpu.cores_logical
            if load_ratio > 1.0:
                load_factor = 1.0 / load_ratio  # Slow down when overloaded
        
        # Weighted average
        performance_score = (
            cpu_score * 0.4 +
            memory_score * 0.2 +
            disk_score * 0.2 +
            load_factor * 0.2
        )
        
        return round(performance_score, 2)
    
    def _classify_environment(self, score: float) -> str:
        """Classify environment based on performance score
        
        Returns:
            Environment class: 'low-end', 'mid-range', or 'high-end'
        """
        if score < self.LOW_END_SCORE_THRESHOLD:
            return "low-end"
        elif score > self.HIGH_END_SCORE_THRESHOLD:
            return "high-end"
        else:
            return "mid-range"
    
    def get_adjusted_budgets(
        self,
        context: Optional[EnvironmentContext] = None,
        base_budgets: Optional[Dict[str, float]] = None
    ) -> Dict[str, float]:
        """Get performance budgets adjusted for current environment
        
        Args:
            context: Environment context (will record if not provided)
            base_budgets: Base budgets to adjust (uses default if not provided)
            
        Returns:
            Dictionary of adjusted budgets
        """
        if context is None:
            context = self.record_environment()
        
        if base_budgets is None:
            from .tracker import PERFORMANCE_BUDGETS
            base_budgets = PERFORMANCE_BUDGETS
        
        # Adjust budgets based on performance score
        # Slower environments get more time, faster environments get less
        adjusted = {}
        for analyzer_name, base_budget in base_budgets.items():
            # Inverse relationship: slower env (score < 1.0) gets more time
            adjustment_factor = 1.0 / context.performance_score
            adjusted_budget = base_budget * adjustment_factor
            adjusted[analyzer_name] = round(adjusted_budget, 2)
        
        return adjusted
    
    def compare_environments(
        self,
        context_a: EnvironmentContext,
        context_b: Optional[EnvironmentContext] = None
    ) -> Dict[str, Any]:
        """Compare two environment contexts
        
        Args:
            context_a: First environment context (usually baseline)
            context_b: Second environment context (usually current, recorded if not provided)
            
        Returns:
            Comparison report with differences and adjustment recommendations
        """
        if context_b is None:
            context_b = self.record_environment()
        
        # Calculate differences
        cpu_diff = self._calculate_cpu_diff(context_a.cpu, context_b.cpu)
        memory_diff = self._calculate_memory_diff(context_a.memory, context_b.memory)
        disk_diff = self._calculate_disk_diff(context_a.disk, context_b.disk)
        
        # Performance score ratio
        score_ratio = context_b.performance_score / context_a.performance_score if context_a.performance_score > 0 else 1.0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(context_a, context_b, score_ratio)
        
        return {
            "baseline": {
                "hostname": context_a.hostname,
                "timestamp": context_a.timestamp,
                "environment_class": context_a.environment_class,
                "performance_score": context_a.performance_score,
            },
            "current": {
                "hostname": context_b.hostname,
                "timestamp": context_b.timestamp,
                "environment_class": context_b.environment_class,
                "performance_score": context_b.performance_score,
            },
            "differences": {
                "cpu": cpu_diff,
                "memory": memory_diff,
                "disk": disk_diff,
                "performance_score_ratio": round(score_ratio, 2),
            },
            "adjustment_factor": round(1.0 / score_ratio if score_ratio > 0 else 1.0, 2),
            "recommendations": recommendations,
        }
    
    def _calculate_cpu_diff(self, cpu_a: CPUInfo, cpu_b: CPUInfo) -> Dict[str, Any]:
        """Calculate CPU differences"""
        return {
            "cores_logical_diff": cpu_b.cores_logical - cpu_a.cores_logical,
            "cores_logical_ratio": cpu_b.cores_logical / cpu_a.cores_logical if cpu_a.cores_logical > 0 else 1.0,
            "frequency_diff_mhz": cpu_b.frequency_mhz - cpu_a.frequency_mhz,
            "frequency_ratio": cpu_b.frequency_mhz / cpu_a.frequency_mhz if cpu_a.frequency_mhz > 0 else 1.0,
        }
    
    def _calculate_memory_diff(self, mem_a: MemoryInfo, mem_b: MemoryInfo) -> Dict[str, Any]:
        """Calculate memory differences"""
        return {
            "total_diff_mb": mem_b.total_mb - mem_a.total_mb,
            "total_ratio": mem_b.total_mb / mem_a.total_mb if mem_a.total_mb > 0 else 1.0,
        }
    
    def _calculate_disk_diff(self, disk_a: DiskInfo, disk_b: DiskInfo) -> Dict[str, Any]:
        """Calculate disk differences"""
        return {
            "iops_read_diff": disk_b.iops_read - disk_a.iops_read,
            "iops_read_ratio": disk_b.iops_read / disk_a.iops_read if disk_a.iops_read > 0 else 1.0,
        }
    
    def _generate_recommendations(
        self,
        context_a: EnvironmentContext,
        context_b: EnvironmentContext,
        score_ratio: float
    ) -> List[str]:
        """Generate recommendations for performance testing"""
        recommendations = []
        
        if score_ratio < 0.7:
            recommendations.append(
                f"Current environment is significantly slower than baseline "
                f"({score_ratio:.2f}x). Consider using faster hardware for testing "
                f"or adjusting performance thresholds by {1/score_ratio:.2f}x."
            )
        elif score_ratio > 1.3:
            recommendations.append(
                f"Current environment is significantly faster than baseline "
                f"({score_ratio:.2f}x). Performance thresholds may be too lenient."
            )
        
        if context_b.cpu.cores_logical < context_a.cpu.cores_logical:
            recommendations.append(
                f"Fewer CPU cores than baseline ({context_b.cpu.cores_logical} vs "
                f"{context_a.cpu.cores_logical}). Parallel tests will be slower."
            )
        
        if context_b.memory.total_mb < context_a.memory.total_mb * 0.5:
            recommendations.append(
                f"Significantly less memory than baseline "
                f"({context_b.memory.total_mb:.0f}MB vs {context_a.memory.total_mb:.0f}MB). "
                f"Memory-intensive tests may behave differently."
            )
        
        if context_b.load_5min > context_b.cpu.cores_logical * 0.8:
            recommendations.append(
                f"System load is high ({context_b.load_5min:.2f}). "
                f"Performance measurements may be inconsistent."
            )
        
        if not recommendations:
            recommendations.append(
                "Environment is similar to baseline. Standard performance thresholds apply."
            )
        
        return recommendations
    
    def save_environment_context(
        self,
        context: Optional[EnvironmentContext] = None,
        output_path: Optional[str] = None
    ) -> str:
        """Save environment context to JSON file
        
        Args:
            context: Environment context (will record if not provided)
            output_path: Output file path (default: workspace/env/context-{timestamp}.json)
            
        Returns:
            Path to saved file
        """
        if context is None:
            context = self.record_environment()
        
        if output_path is None:
            # Default to workspace
            workspace = Path("/data/sec-userspace/workspace/env")
            workspace.mkdir(parents=True, exist_ok=True)
            timestamp = context.timestamp.replace(':', '-').replace('+', '')
            output_path = str(workspace / f"context-{timestamp}.json")
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(context.to_json(), encoding='utf-8')
        
        logger.info(f"Environment context saved to {output_path}")
        return output_path
    
    def load_environment_context(self, input_path: str) -> EnvironmentContext:
        """Load environment context from JSON file
        
        Args:
            input_path: Path to JSON file
            
        Returns:
            EnvironmentContext instance
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Environment context file not found: {input_path}")
        
        data = json.loads(input_file.read_text(encoding='utf-8'))
        
        context = EnvironmentContext()
        context.timestamp = data.get("timestamp", "")
        context.hostname = data.get("hostname", "")
        
        # CPU info
        cpu_data = data.get("cpu", {})
        context.cpu = CPUInfo(
            model=cpu_data.get("model", ""),
            cores_physical=cpu_data.get("cores_physical", 0),
            cores_logical=cpu_data.get("cores_logical", 0),
            frequency_mhz=cpu_data.get("frequency_mhz", 0.0),
            architecture=cpu_data.get("architecture", ""),
        )
        
        # Memory info
        mem_data = data.get("memory", {})
        context.memory = MemoryInfo(
            total_mb=mem_data.get("total_mb", 0.0),
            available_mb=mem_data.get("available_mb", 0.0),
            used_percent=mem_data.get("used_percent", 0.0),
            swap_total_mb=mem_data.get("swap_total_mb", 0.0),
        )
        
        # Disk info
        disk_data = data.get("disk", {})
        context.disk = DiskInfo(
            total_gb=disk_data.get("total_gb", 0.0),
            used_gb=disk_data.get("used_gb", 0.0),
            free_gb=disk_data.get("free_gb", 0.0),
            used_percent=disk_data.get("used_percent", 0.0),
            iops_read=disk_data.get("iops_read", 0.0),
            iops_write=disk_data.get("iops_write", 0.0),
        )
        
        # System info
        context.os_name = data.get("os_name", "")
        context.os_version = data.get("os_version", "")
        context.kernel_version = data.get("kernel_version", "")
        context.python_version = data.get("python_version", "")
        
        # Load averages
        context.load_1min = data.get("load_1min", 0.0)
        context.load_5min = data.get("load_5min", 0.0)
        context.load_15min = data.get("load_15min", 0.0)
        
        # Classification
        context.environment_class = data.get("environment_class", "unknown")
        context.performance_score = data.get("performance_score", 1.0)
        
        return context


# Convenience functions
_detector_instance: Optional[EnvironmentContextDetector] = None
_detector_lock = threading.Lock()


def get_detector() -> EnvironmentContextDetector:
    """Get singleton detector instance"""
    global _detector_instance
    if _detector_instance is None:
        with _detector_lock:
            if _detector_instance is None:
                _detector_instance = EnvironmentContextDetector()
    return _detector_instance


def record_environment() -> EnvironmentContext:
    """Record current environment (convenience function)"""
    return get_detector().record_environment()


def get_adjusted_budgets(base_budgets: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """Get adjusted budgets for current environment (convenience function)"""
    return get_detector().get_adjusted_budgets(base_budgets=base_budgets)


def compare_with_baseline(baseline_path: str) -> Dict[str, Any]:
    """Compare current environment with saved baseline (convenience function)"""
    detector = get_detector()
    baseline = detector.load_environment_context(baseline_path)
    current = detector.record_environment()
    return detector.compare_environments(baseline, current)
