"""System Log Collector"""
import gc
import hashlib
import json
import os
import re
import stat
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from ..collector.base import BaseCollector
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

# Pre-compiled regex patterns (performance optimization)
_FAILED_PATTERN = re.compile(r"Failed password for (.+?) from (\d+\.\d+\.\d+\.\d+)")
_ACCEPTED_PATTERN = re.compile(r"Accepted (\w+) for (\w+) from (\d+\.\d+\.\d+\.\d+)")
_SUDO_PATTERN = re.compile(r"sudo:.*COMMAND=(.+)")
_TIMESTAMP_PATTERN = re.compile(r"^(\w+\s+\d+\s+\d+:\d+:\d+)")

# Log file list
_AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
_SYSTEM_LOG_PATHS = ["/var/log/syslog", "/var/log/messages", "/var/log/kern.log"]
_SPECIAL_LOG_PATHS = ["/var/log/cron.log", "/var/log/audit/audit.log", "/var/log/wtmp", "/var/log/btmp"]

# ML/AI framework log paths for adversarial attack detection
_ML_LOG_PATHS = [
    # LLM inference servers
    "/var/log/vllm",
    "/var/log/ollama",
    "/var/log/text-generation-inference",
    "/var/log/llama_cpp",
    "/var/log/transformers",
    
    # RAG and agent frameworks
    "/var/log/langchain",
    "/var/log/litellm",
    "/var/log/haystack",
    "/var/log/semantic-kernel",
    
    # Vector databases
    "/var/log/milvus",
    "/var/log/chroma",
    "/var/log/qdrant",
    "/var/log/weaviate",
    "/var/log/pgvector",
    
    # ML training frameworks
    "/var/log/huggingface",
    "/var/log/lightning",
    "/var/log/mxnet",
    "/var/log/jax",
    "/var/log/flax",
    "/var/log/fastai",
    
    # ML flow and experiment tracking
    "/var/log/mlflow",
    "/var/log/kubeflow",
    "/var/log/sagemaker",
    "/var/log/wandb",
    "/var/log/neptune",
    
    # Model serving platforms
    "/var/log/triton-server",
    "/var/log/torchserve",
    "/var/log/tensorflow-serving",
    "/var/log/bentoml",
    
    # Distributed training
    "/tmp/ray/session_latest/logs",
    "/var/log/deepspeed",
    "/var/log/fsdp",
    "/var/log/megatron-lm",
    
    # User home directory logs (common ML framework cache/logs)
    os.path.expanduser("~/.huggingface/logs"),
    os.path.expanduser("~/.lightning/logs"),
    os.path.expanduser("~/.cache/huggingface/logs"),
    os.path.expanduser("~/.mlflow/logs"),
    
    # Containerized ML services (mounted volumes)
    "/data/ml-logs",
    "/opt/ml/logs",
    "/workspace/logs",
    "/app/logs",
    
    # Docker container logs for ML services
    "/var/lib/docker/containers",  # Docker container stdout/stderr logs
    "/var/log/docker.log",  # Docker daemon logs
    "/var/log/containers",  # Kubernetes container logs (Docker runtime)
    
    # Podman container logs
    "/var/lib/containers/storage",  # Podman storage
    "/var/log/podman",  # Podman logs
    
    # Containerd logs
    "/var/log/containerd.log",  # Containerd daemon logs
    "/var/lib/containerd/io.containerd.runtime.v2.task",  # Containerd task logs
    
    # Kubernetes container runtime logs (CRI-O, containerd CRI)
    "/var/log/pods",  # Kubernetes pod logs (container stdout/stderr)
    "/var/log/containers/*.log",  # Kubernetes symlinked container logs
    "/var/log/kubernetes",  # Kubernetes component logs
    
    # CRI-O container logs
    "/var/log/crio",  # CRI-O daemon logs
    "/var/lib/containers/storage/overlay-containers",  # CRI-O storage
    
    # Docker Compose project logs (common mounted volumes)
    "/app/logs",  # Common Docker Compose mount point
    "/srv/logs",  # Alternative compose mount
    "/opt/docker-logs",  # Custom docker-compose log directory
]

MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
MAX_LIST_SIZE = 10000

def _hash_sensitive(value: str) -> str:
    """SHA256 hash a sensitive value (retain first 16 characters)
    
    Args:
        value: Sensitive value to be desensitized (username, IP address, etc.)
    
    Returns:
        Hashed string (16 hexadecimal characters)
    """
    if not value:
        return ""
    return hashlib.sha256(value.encode()).hexdigest()[:16]

class LogCollector(BaseCollector):
    """System Log Collector"""
    name = "log"

    def __init__(self):
        super().__init__()
        self._partial_result = None
        self._lock = threading.Lock()
        self._scan_start_time = None
        
        self.timeout = self._get_config("timeout", 90)
        
        self._max_lines = self._get_config("max_lines", 1000)
        
        self._paths = self._get_config("paths", {})

    def _calculate_completeness_internal(self, partial_result: dict) -> dict:
        """Calculate data completeness score for partial results (internal, no lock)
        
        Args:
            partial_result: Current partial result data
            
        Returns:
            dict with completeness metrics
        """
        if partial_result is None:
            return {
                "score": 0.0,
                "phases_completed": {},
                "data_sufficient": False,
                "warnings": ["No log data collected"],
            }
        
        # Phase completion tracking
        auth_log = partial_result.get("auth_log", {})
        has_auth_data = len(auth_log.get("failed_logins", [])) > 0 or len(auth_log.get("sudo_events", [])) > 0
        
        phases = {
            "log_files_metadata": len(partial_result.get("log_files", [])) > 0,
            "auth_log_parsed": has_auth_data,
            "syslog_info_collected": len(partial_result.get("syslog_info", {})) > 0,
            "wtmp_info_collected": len(partial_result.get("wtmp_info", {})) > 0,
            "btmp_info_collected": len(partial_result.get("btmp_info", {})) > 0,
            "ml_logs_collected": len(partial_result.get("ml_logs", [])) > 0,
        }
        
        # Weight-based scoring (auth log is most critical for security)
        phase_weights = {
            "log_files_metadata": 0.15,
            "auth_log_parsed": 0.45,
            "syslog_info_collected": 0.15,
            "wtmp_info_collected": 0.10,
            "btmp_info_collected": 0.10,
            "ml_logs_collected": 0.05,
        }
        
        score = sum(phase_weights.get(phase, 0) for phase, completed in phases.items()
                   if completed)
        
        # Determine if data is sufficient for core detections
        has_failed_logins = len(auth_log.get("failed_logins", [])) > 0
        has_sudo_events = len(auth_log.get("sudo_events", [])) > 0
        data_sufficient = has_auth_data
        
        # Generate warnings
        warnings = []
        if not phases.get("auth_log_parsed"):
            warnings.append("Auth log not parsed - brute force and privilege escalation detection unavailable")
        elif not has_failed_logins and not has_sudo_events:
            warnings.append("No auth events found - log file may be empty or not rotated recently")
        if not phases.get("log_files_metadata"):
            warnings.append("Log file metadata not collected - cannot verify log integrity")
        if not phases.get("syslog_info_collected"):
            warnings.append("Syslog info not collected - system event correlation unavailable")
        if not phases.get("ml_logs_collected"):
            warnings.append("ML/AI logs not collected - adversarial attack detection unavailable")
        
        return {
            "score": round(score, 2),
            "phases_completed": phases,
            "data_sufficient": data_sufficient,
            "total_auth_events": auth_log.get("total_lines", 0),
            "warnings": warnings,
        }

    def _calculate_completeness(self) -> dict:
        """Thread-safe wrapper around _calculate_completeness_internal."""
        with self._lock:
            return self._calculate_completeness_internal(self._partial_result)

    def _update_partial_result(self, **kwargs):
        """Update partial result with current collection progress"""
        with self._lock:
            if self._partial_result is None:
                self._partial_result = {
                    "log_files": [],
                    "auth_log": {},
                    "syslog_info": {},
                    "wtmp_info": {},
                    "btmp_info": {},
                    "ml_logs": [],
                    "_partial": False,
                }

            for key, value in kwargs.items():
                if key in self._partial_result:
                    self._partial_result[key] = value

    def get_partial_result(self) -> dict:
        """Return current partial result for timeout recovery"""
        with self._lock:
            if self._partial_result is None:
                return {}
            result = dict(self._partial_result)
            # Include completeness score in partial result (compute inline to avoid deadlock)
            result["_completeness"] = self._calculate_completeness_internal(self._partial_result)
            return result

    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout"""
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time
        
        # Use configured timeout
        effective_timeout = self.timeout
        soft_timeout = effective_timeout * 0.8
        return elapsed > soft_timeout

    def collect(self) -> dict:
        """Collect log information with progressive results"""
        self._scan_start_time = time.time()

        # Phase 1: Log file metadata (quick)
        log_files = self._collect_log_file_metadata()
        self._update_partial_result(log_files=log_files)

        # Phase 2: Auth log parsing (critical for security)
        auth_log = self._parse_auth_log()
        self._update_partial_result(auth_log=auth_log)

        if self._should_skip_due_to_timeout():
            _get_logger().warning("Log collector: soft timeout reached after auth log parsing")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 3: Syslog info
        syslog_info = self._get_syslog_info()
        self._update_partial_result(syslog_info=syslog_info)

        # Phase 4: wtmp info
        wtmp_info = self._get_wtmp_info()
        self._update_partial_result(wtmp_info=wtmp_info)

        # Phase 5: btmp info
        btmp_info = self._get_btmp_info()
        self._update_partial_result(btmp_info=btmp_info)

        if self._should_skip_due_to_timeout():
            _get_logger().warning("Log collector: soft timeout reached, skipping ML logs")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 6: ML/AI framework logs (expensive, many paths)
        ml_logs = self._collect_ml_logs()
        self._update_partial_result(ml_logs=ml_logs)

        elapsed = time.time() - self._scan_start_time
        _get_logger().debug(
            f"Log collector: returning logs "
            f"(Log files: {len(log_files)}, Auth log parsed, "
            f"Syslog: {syslog_info.get('size', 0)}B, "
            f"ML logs: {len(ml_logs)} files)"
        )

        result = {
            "log_files": log_files,
            "auth_log": auth_log,
            "syslog_info": syslog_info,
            "wtmp_info": wtmp_info,
            "btmp_info": btmp_info,
            "ml_logs": ml_logs,
        }

        del log_files, auth_log, syslog_info, wtmp_info, btmp_info, ml_logs
        
        gc.collect()

        # Include completeness in final result for executor extraction
        completeness = self._calculate_completeness()
        result["_completeness"] = completeness

        return result

    def _collect_log_file_metadata(self) -> List[Dict]:
        """Collect metadata for all log files"""
        all_paths = _AUTH_LOG_PATHS + _SYSTEM_LOG_PATHS + _SPECIAL_LOG_PATHS
        log_files = []

        for path in all_paths:
            try:
                if os.path.exists(path):
                    file_stat = os.stat(path)
                    mtime = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                    permissions = oct(stat.S_IMODE(file_stat.st_mode))
                    log_files.append({
                        "path": path,
                        "exists": True,
                        "size": file_stat.st_size,
                        "mtime": mtime,
                        "permissions": permissions,
                        "is_empty": file_stat.st_size == 0,
                    })
                else:
                    log_files.append({
                        "path": path,
                        "exists": False,
                        "size": 0,
                        "mtime": "",
                        "permissions": "",
                        "is_empty": True,
                    })
            except OSError as e:
                _get_logger().debug(f"Failed to check log file {path}: {type(e).__name__}: {e}")
                log_files.append({
                    "path": path,
                    "exists": False,
                    "size": 0,
                    "mtime": "",
                    "permissions": "",
                    "is_empty": True,
                })

        return log_files

    def _parse_auth_log(self) -> Dict:
        """Parse authentication logs"""
        auth_log_path = self._find_auth_log_path()
        auth_log = {
            "path": auth_log_path,
            "total_lines": 0,
            "failed_logins": [],
            "successful_logins": [],
            "sudo_events": [],
        }

        if not os.path.exists(auth_log_path):
            return auth_log

        try:
            with open(auth_log_path, 'r', errors='ignore', encoding='utf-8') as f:
                self._parse_auth_log_lines(f, auth_log)
        except OSError as e:
            _get_logger().debug(f"Failed to parse auth.log: {type(e).__name__}: {e}")

        return auth_log

    def _find_auth_log_path(self) -> str:
        """Find auth log path"""
        for path in _AUTH_LOG_PATHS:
            if os.path.exists(path):
                return path
        return _AUTH_LOG_PATHS[0]

    def _parse_auth_log_lines(self, f, auth_log: Dict) -> None:
        """Parse auth log lines"""
        file_size = f.seek(0, 2)
        f.seek(0)

        if file_size > MAX_LOG_SIZE:
            _get_logger().warning(f"auth.log exceeds {MAX_LOG_SIZE // (1024*1024)}MB ({file_size // (1024*1024)}MB), reading only tail")
            f.seek(file_size - MAX_LOG_SIZE)
            f.readline()  # Discard the first incomplete line
        
        # Cache list references for performance
        failed_logins = auth_log["failed_logins"]
        successful_logins = auth_log["successful_logins"]
        sudo_events = auth_log["sudo_events"]
        max_list_size = MAX_LIST_SIZE
        
        for line in f:
            auth_log["total_lines"] += 1
            ts_match = _TIMESTAMP_PATTERN.search(line)
            timestamp = ts_match.group(1) if ts_match else ""
            
            # Failed login
            if len(failed_logins) < max_list_size:
                failed_match = _FAILED_PATTERN.search(line)
                if failed_match:
                    user = failed_match.group(1)
                    source_ip = failed_match.group(2)
                    failed_logins.append({
                        "timestamp": timestamp,
                        "user_hash": _hash_sensitive(user),
                        "source_ip_hash": _hash_sensitive(source_ip),
                        "method": "password",
                    })
                    continue
            
            # Successful login
            if len(successful_logins) < max_list_size:
                accepted_match = _ACCEPTED_PATTERN.search(line)
                if accepted_match:
                    method = accepted_match.group(1)
                    user = accepted_match.group(2)
                    source_ip = accepted_match.group(3)
                    successful_logins.append({
                        "timestamp": timestamp,
                        "user_hash": _hash_sensitive(user),
                        "source_ip_hash": _hash_sensitive(source_ip),
                        "method": method,
                    })
                    continue

            # Sudo event
            if len(sudo_events) < max_list_size:
                sudo_match = _SUDO_PATTERN.search(line)
                if sudo_match:
                    command = sudo_match.group(1).strip()
                    success = "authentication failure" not in line
                    sudo_events.append({
                        "timestamp": timestamp,
                        "user_hash": "",
                        "command": command,
                        "success": success,
                    })

    def _get_syslog_info(self) -> Dict:
        """Get syslog information"""
        syslog_info = {"path": "/var/log/syslog", "size": 0, "is_empty": True}
        if os.path.exists("/var/log/syslog"):
            try:
                syslog_info["size"] = os.path.getsize("/var/log/syslog")
                syslog_info["is_empty"] = syslog_info["size"] == 0
            except OSError as e:
                _get_logger().debug(f"Failed to read syslog: {type(e).__name__}: {e}")
        return syslog_info

    def _get_wtmp_info(self) -> Dict:
        """Get wtmp information"""
        wtmp_info = {
            "path": "/var/log/wtmp",
            "size": 0,
            "is_empty": True,
            "records": [],
        }
        if os.path.exists("/var/log/wtmp"):
            try:
                wtmp_info["size"] = os.path.getsize("/var/log/wtmp")
                wtmp_info["is_empty"] = wtmp_info["size"] == 0
            except OSError as e:
                _get_logger().debug(f"Failed to read wtmp: {type(e).__name__}: {e}")
        return wtmp_info

    def _get_btmp_info(self) -> Dict:
        """Get btmp information"""
        btmp_info = {
            "path": "/var/log/btmp",
            "size": 0,
            "record_count": 0,
        }
        if os.path.exists("/var/log/btmp"):
            try:
                btmp_info["size"] = os.path.getsize("/var/log/btmp")
            except OSError as e:
                _get_logger().debug(f"Failed to read btmp: {type(e).__name__}: {e}")
        return btmp_info

    def _collect_ml_logs(self) -> List[Dict]:
        """Collect ML/AI framework log files metadata and entries
        
        P3-2026-04-20: Memory optimized with batch processing and explicit GC.
        Processes log files in batches and releases intermediate data.
        
        Returns:
            List of ML log file metadata and parsed entries
        """
        ml_logs = []
        batch_size = 10  # Process 10 files at a time before GC
        files_processed = 0
        
        for log_dir in _ML_LOG_PATHS:
            try:
                if not os.path.exists(log_dir):
                    continue
                
                # Scan all .log files in the directory
                for log_file in Path(log_dir).glob("*.log"):
                    try:
                        file_stat = os.stat(log_file)
                        mtime = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                        
                        log_entry = {
                            "path": str(log_file),
                            "exists": True,
                            "size": file_stat.st_size,
                            "mtime": mtime,
                            "permissions": oct(stat.S_IMODE(file_stat.st_mode)),
                            "is_empty": file_stat.st_size == 0,
                            "source": self._infer_ml_source(str(log_file)),
                            "entries": [],
                        }
                        
                        # Parse log entries (limit to recent 1000 lines for performance)
                        if file_stat.st_size < MAX_LOG_SIZE:
                            log_entry["entries"] = self._parse_ml_log_file(log_file)
                        
                        ml_logs.append(log_entry)
                        files_processed += 1
                        
                        if files_processed % batch_size == 0:
                            gc.collect()
                        
                    except (OSError, ValueError, UnicodeDecodeError) as e:
                        _get_logger().debug(f"Failed to process ML log file {log_file}: {type(e).__name__}: {e}")
                        
            except OSError as e:
                _get_logger().debug(f"Failed to scan ML log directory {log_dir}: {type(e).__name__}: {e}")
        
        return ml_logs
    
    def _infer_ml_source(self, log_path: str) -> str:
        """Infer ML framework source from log path
        
        Args:
            log_path: Path to the log file
            
        Returns:
            Inferred ML framework name (e.g., 'vllm', 'ollama', 'langchain')
        """
        path_lower = log_path.lower()
        
        # Container runtime logs
        if "/var/lib/docker/containers" in path_lower:
            return "docker_container"
        elif "/var/log/docker.log" in path_lower:
            return "docker_daemon"
        elif "/var/log/containers/" in path_lower or "/var/log/containers\\" in path_lower:
            return "kubernetes_container"
        elif "/var/log/pods" in path_lower:
            return "kubernetes_pods"
        elif "/var/log/kubernetes" in path_lower:
            return "kubernetes_components"
        elif "/var/log/crio" in path_lower:
            return "crio"
        elif "/var/lib/containers/storage" in path_lower:
            return "podman_crio_storage"
        elif "/var/log/podman" in path_lower:
            return "podman"
        elif "/var/log/containerd.log" in path_lower:
            return "containerd"
        elif "/var/lib/containerd/" in path_lower:
            return "containerd_runtime"
        
        # Docker Compose project logs
        elif "/app/logs" in path_lower or "/srv/logs" in path_lower or "/opt/docker-logs" in path_lower:
            return "docker_compose"
        
        # LLM inference servers
        if "vllm" in path_lower:
            return "vllm"
        elif "ollama" in path_lower:
            return "ollama"
        elif "text-generation-inference" in path_lower or "tgi" in path_lower:
            return "tgi"
        elif "llama_cpp" in path_lower:
            return "llama_cpp"
        elif "litellm" in path_lower:
            return "litellm"
        
        # RAG and agent frameworks
        elif "langchain" in path_lower:
            return "langchain"
        elif "haystack" in path_lower:
            return "haystack"
        elif "semantic-kernel" in path_lower:
            return "semantic_kernel"
        
        # Vector databases
        elif "milvus" in path_lower:
            return "milvus"
        elif "chroma" in path_lower:
            return "chroma"
        elif "qdrant" in path_lower:
            return "qdrant"
        elif "weaviate" in path_lower:
            return "weaviate"
        elif "pgvector" in path_lower:
            return "pgvector"
        
        # ML training frameworks
        elif "huggingface" in path_lower or "transformers" in path_lower:
            return "huggingface"
        elif "lightning" in path_lower:
            return "lightning"
        elif "mxnet" in path_lower:
            return "mxnet"
        elif "jax" in path_lower:
            return "jax"
        elif "flax" in path_lower:
            return "flax"
        elif "fastai" in path_lower:
            return "fastai"
        
        # ML flow and experiment tracking
        elif "mlflow" in path_lower:
            return "mlflow"
        elif "kubeflow" in path_lower:
            return "kubeflow"
        elif "sagemaker" in path_lower:
            return "sagemaker"
        elif "wandb" in path_lower:
            return "wandb"
        elif "neptune" in path_lower:
            return "neptune"
        
        # Model serving platforms
        elif "triton" in path_lower:
            return "triton"
        elif "torchserve" in path_lower:
            return "torchserve"
        elif "tensorflow-serving" in path_lower:
            return "tensorflow_serving"
        elif "bentoml" in path_lower:
            return "bentoml"
        
        # Distributed training
        elif "ray" in path_lower:
            return "ray"
        elif "deepspeed" in path_lower:
            return "deepspeed"
        elif "fsdp" in path_lower:
            return "fsdp"
        elif "megatron" in path_lower:
            return "megatron_lm"
        
        else:
            return "unknown"
    
    def _parse_ml_log_file(self, log_file: Path) -> List[Dict]:
        """Parse ML framework log file
        
        P3-2026-04-20: Memory optimized with generator-based processing.
        Processes lines one at a time without building intermediate lists.
        
        Args:
            log_file: Path to the log file
            
        Returns:
            List of parsed log entries
        """
        entries = []
        max_entries = 1000  # Limit entries per file
        
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8') as f:
                # Read tail for large files
                file_size = f.seek(0, 2)
                f.seek(0)
                
                if file_size > MAX_LOG_SIZE:
                    f.seek(file_size - MAX_LOG_SIZE)
                    f.readline()  # Skip partial line
                
                for line in f:
                    if len(entries) >= max_entries:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to parse common ML log formats
                    entry = self._parse_ml_log_line(line, str(log_file))
                    if entry:
                        entries.append(entry)

        except (OSError, ValueError, UnicodeDecodeError) as e:
            _get_logger().debug(f"Failed to parse ML log file {log_file}: {type(e).__name__}: {e}")
        
        return entries
    
    def _parse_ml_log_line(self, line: str, source: str) -> Optional[Dict]:
        """Parse a single ML log line
        
        Args:
            line: Log line content
            source: Log source path
            
        Returns:
            Parsed log entry dict or None
        """
        # Try JSON format first (common in vLLM, LangChain, TGI)
        if line.startswith('{'):
            try:
                data = json.loads(line)
                return {
                    "timestamp": data.get("timestamp", data.get("time", "")),
                    "level": data.get("level", data.get("severity", "INFO")),
                    "message": data.get("message", data.get("msg", str(data))),
                    "source": source,
                    "format": "json",
                }
            except (ValueError, KeyError):
                pass

        # Try common text log format: [TIMESTAMP] LEVEL MESSAGE
        ts_match = _TIMESTAMP_PATTERN.match(line)
        if ts_match:
            timestamp = ts_match.group(1)
            # Extract level and message
            rest = line[len(timestamp):].strip()
            parts = rest.split(None, 1)
            level = parts[0] if parts else "INFO"
            message = parts[1] if len(parts) > 1 else ""
            
            return {
                "timestamp": timestamp,
                "level": level.upper(),
                "message": message,
                "source": source,
                "format": "text",
            }
        
        # Fallback: treat entire line as message
        return {
            "timestamp": "",
            "level": "INFO",
            "message": line,
            "source": source,
            "format": "text",
        }
