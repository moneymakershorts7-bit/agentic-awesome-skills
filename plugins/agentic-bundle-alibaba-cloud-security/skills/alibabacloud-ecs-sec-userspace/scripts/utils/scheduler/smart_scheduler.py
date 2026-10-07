"""Smart Scheduler - Intelligent analyzer scheduling based on environment risk"""
import glob
import logging
import os
from enum import Enum
from typing import List, Dict, Optional, Set

logger = logging.getLogger("sec-userspace")


class RiskProfile(Enum):
    """Environment risk profile for adaptive scheduling"""
    DEVELOPMENT = "development"    # Dev workstation, low risk
    MIXED = "mixed"                # Dev + production mixed environment
    STAGING = "staging"            # Staging/testing, medium risk
    PRODUCTION = "production"      # Production server, high risk
    UNKNOWN = "unknown"            # Unknown environment


class SmartScheduler:
    """Smart scheduler for analyzer scheduling based on environment risk"""

    # Development environment indicators
    DEV_INDICATORS = {
        "files": [
            "/usr/bin/python3", "/usr/bin/npm", "/usr/bin/node",
            "/usr/bin/gcc", "/usr/bin/g++", "/usr/bin/go",
            "/usr/local/bin/pytest", "/usr/bin/pytest",
            "/usr/bin/make", "/usr/bin/cmake",
        ],
        "dirs": [
            "/data/work", "/home/*/projects", "/home/*/dev",
            "/home/*/workspace", "/opt/development",
        ],
        "env_vars": [
            "CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
            "NODE_ENV=development", "PYTHONDONTWRITEBYTECODE",
        ],
    }

    # AI/ML development environment indicators (additional dev context)
    AI_DEV_INDICATORS = {
        "files": [
            "/usr/bin/python3", "/usr/local/bin/pip", "/usr/bin/pip3",
        ],
        "packages": [
            "torch", "tensorflow", "transformers", "langchain", "openai",
            "vllm", "ollama", "llama.cpp",
        ],
        "processes": [
            "jupyter", "ipython", "python3", "node", "vllm", "ollama",
        ],
        "dirs": [
            "/data/work", "/home/*/.cache/huggingface",
            "/home/*/.cache/ollama", "/root/.ollama",
        ],
    }

    # CI/CD pipeline environment indicators
    CI_CD_INDICATORS = {
        "env_vars": [
            "CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
            "CIRCLECI", "TRAVIS", "BUILDKITE", "DRONE",
            "BITBUCKET_COMMIT", "CODEBUILD_BUILD_ARN",
        ],
        "files": [
            "/run/buildkit", "/var/run/docker.sock",
        ],
    }

    # Production environment indicators
    PROD_INDICATORS = {
        "files": [
            "/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf",
            "/var/lib/docker", "/var/lib/kubelet",
        ],
        "env_vars": [
            "NODE_ENV=production", "DJANGO_SETTINGS_MODULE",
            "KUBERNETES_SERVICE_HOST", "AWS_EXECUTION_ENV",
        ],
    }

    # Mixed environment indicator (dev tools + production services)
    MIXED_INDICATORS = {
        "files": [
            "/var/lib/docker", "/var/lib/kubelet",
            "/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf",
        ],
        "processes": [
            "kubelet", "dockerd", "containerd",
            "nginx", "httpd", "apache2",
        ],
    }

    def __init__(self, analyzers):
        """
        Initialize scheduler

        Args:
            analyzers: List of (name, analyzer_class) tuples or _LazyAnalyzerList from main.py
        """
        self.analyzers = analyzers
        self._analyzer_info = {}
        self._analyzer_names: Set[str] = set()
        # Don't load all analyzer info at init - load on demand instead
        # This saves memory by not instantiating all 180+ analyzers upfront
        self._info_loaded_for: Set[str] = set()
        
        # Check if we have a lazy analyzer list
        self._is_lazy = hasattr(analyzers, 'get_names') and hasattr(analyzers, 'load_subset')
        if self._is_lazy:
            # Use name list without loading classes
            self._analyzer_names = set(analyzers.get_names())
        else:
            # Legacy: extract names from list
            for name, cls in analyzers:
                self._analyzer_names.add(name)

    def _load_analyzer_info(self, name: str) -> Optional[Dict]:
        """Load analyzer metadata on demand (lazy loading).
        
        Args:
            name: Analyzer name to load info for
            
        Returns:
            Dict with analyzer info or None if failed
        """
        if name in self._info_loaded_for:
            return self._analyzer_info.get(name)
        
        # Find the analyzer class
        cls = None
        
        if self._is_lazy:
            # For lazy list, load just this one analyzer
            loaded = self.analyzers.load_subset({name})
            if loaded:
                cls = loaded[0][1]
        else:
            # Legacy: search in list
            for n, c in self.analyzers:
                if n == name:
                    cls = c
                    break
        
        if cls is None:
            return None
        
        try:
            instance = cls()
            self._analyzer_info[name] = {
                "class": cls,
                "estimated_time": getattr(instance, 'estimated_time', 1.0),
                "analyzer_type": getattr(instance, 'analyzer_type', 'routine'),
            }
        except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as e:
            logger.debug(f"Failed to load analyzer info for {name}: {e}")
            self._analyzer_info[name] = {
                "class": cls,
                "estimated_time": 1.0,
                "analyzer_type": "routine",
            }
        
        self._info_loaded_for.add(name)
        return self._analyzer_info[name]

    def detect_risk_profile(self, collected_data: Optional[dict] = None) -> RiskProfile:
        """
        Detect environment risk profile based on filesystem and process indicators.

        Enhanced with AI/ML development, CI/CD, and cloud-native environment detection.

        Args:
            collected_data: Optional collected data for enhanced profiling

        Returns:
            RiskProfile enum value
        """
        dev_score = 0
        prod_score = 0
        mixed_score = 0
        ci_cd_score = 0
        ai_dev_score = 0

        # Check development file indicators
        for filepath in self.DEV_INDICATORS["files"]:
            # Handle wildcard patterns
            if '*' in filepath:
                matches = glob.glob(filepath)
                dev_score += len(matches) * 2
            elif os.path.exists(filepath):
                dev_score += 2

        # Check development directory indicators
        for dirpattern in self.DEV_INDICATORS["dirs"]:
            matches = glob.glob(dirpattern)
            dev_score += len(matches) * 3

        # Check production file indicators
        for filepath in self.PROD_INDICATORS["files"]:
            if os.path.exists(filepath):
                prod_score += 3

        # Check environment variables for dev/prod
        for env_var in self.DEV_INDICATORS["env_vars"]:
            if '=' in env_var:
                key, value = env_var.split('=', 1)
                if os.environ.get(key) == value:
                    dev_score += 5
            elif os.environ.get(env_var):
                dev_score += 3

        for env_var in self.PROD_INDICATORS["env_vars"]:
            if '=' in env_var:
                key, value = env_var.split('=', 1)
                if os.environ.get(key) == value:
                    prod_score += 5
            elif os.environ.get(env_var):
                prod_score += 3

        # Check CI/CD indicators (affects scheduling decisions)
        for env_var in self.CI_CD_INDICATORS["env_vars"]:
            if os.environ.get(env_var):
                ci_cd_score += 5
                dev_score += 2  # CI/CD is closer to dev than prod

        for filepath in self.CI_CD_INDICATORS["files"]:
            if os.path.exists(filepath):
                ci_cd_score += 3
                dev_score += 1

        # Check AI/ML development indicators
        for filepath in self.AI_DEV_INDICATORS["files"]:
            if os.path.exists(filepath):
                ai_dev_score += 1
                dev_score += 1

        # Check AI/ML cache directories
        for dirpattern in self.AI_DEV_INDICATORS["dirs"]:
            matches = glob.glob(dirpattern)
            if matches:
                ai_dev_score += len(matches) * 2
                dev_score += len(matches)

        # Check for development tools in processes
        has_dev_processes = False
        if collected_data:
            process_data = self._safe_get_data(collected_data, "process")
            if process_data:
                dev_processes = {"python3", "node", "npm", "gcc", "g++", "go", "pytest", "make", "cmake", "cargo", "rustc"}
                prod_processes = {"kubelet", "dockerd", "containerd", "nginx", "httpd", "apache2"}
                ai_processes = set(self.AI_DEV_INDICATORS["processes"])
                for proc in process_data.get("processes", []):
                    comm = proc.get("comm", "").lower()
                    if comm in dev_processes:
                        dev_score += 1
                        has_dev_processes = True
                    if comm in prod_processes:
                        prod_score += 2
                    if comm in ai_processes:
                        ai_dev_score += 1
                        dev_score += 1

        # Check mixed environment indicators
        # Mixed = both dev and production indicators present
        for filepath in self.MIXED_INDICATORS["files"]:
            if os.path.exists(filepath):
                mixed_score += 2

        if collected_data and has_dev_processes:
            process_data = self._safe_get_data(collected_data, "process")
            if process_data:
                for proc in process_data.get("processes", []):
                    comm = proc.get("comm", "").lower()
                    if comm in self.MIXED_INDICATORS["processes"]:
                        mixed_score += 3

        # Detect cloud-native environments (K8s, containers, serverless)
        cloud_native_score = 0
        cloud_indicators = [
            "/var/run/secrets/kubernetes.io",  # K8s service account
            "/var/run/docker.sock",  # Docker socket
            "/.dockerenv",  # Docker container
            "/run/secrets/kubernetes.io",  # Alternative K8s path
        ]
        for indicator in cloud_indicators:
            if os.path.exists(indicator):
                cloud_native_score += 5
                prod_score += 2  # Cloud-native leans toward production

        # Determine risk profile
        # Priority 1: Mixed environment (both dev and production indicators)
        # Lowered threshold from 5 to 3 for better mixed environment detection
        if mixed_score >= 3 and (dev_score >= 3 or has_dev_processes):
            return RiskProfile.MIXED
        # Priority 2: Pure development environment
        elif dev_score > prod_score and dev_score >= 5:
            return RiskProfile.DEVELOPMENT
        # Priority 3: Pure production environment
        elif prod_score > dev_score and prod_score >= 5:
            return RiskProfile.PRODUCTION
        # Priority 4: Staging (some indicators but not clear)
        elif dev_score >= 3 or prod_score >= 3:
            return RiskProfile.STAGING
        else:
            return RiskProfile.UNKNOWN

    def get_environment_metadata(self, collected_data: Optional[dict] = None) -> Dict:
        """
        Get detailed environment metadata for logging and analysis.

        Returns:
            Dict with environment metadata including risk profile, CI/CD status, etc.
        """
        risk_profile = self.detect_risk_profile(collected_data)

        # Detect CI/CD environment
        is_ci_cd = any(os.environ.get(var) for var in self.CI_CD_INDICATORS["env_vars"])

        # Detect AI/ML development
        ai_ml_dev = any(os.path.exists(f) for f in self.AI_DEV_INDICATORS["files"])
        ai_ml_dev = ai_ml_dev or any(glob.glob(d) for d in self.AI_DEV_INDICATORS["dirs"])

        # Detect container environment
        in_container = os.path.exists("/.dockerenv") or os.path.exists("/var/run/docker.sock")

        # Detect Kubernetes
        in_kubernetes = (
            os.path.exists("/var/run/secrets/kubernetes.io") or
            os.environ.get("KUBERNETES_SERVICE_HOST") is not None
        )

        return {
            "risk_profile": risk_profile.value,
            "is_ci_cd": is_ci_cd,
            "is_ai_ml_development": ai_ml_dev,
            "in_container": in_container,
            "in_kubernetes": in_kubernetes,
            "dev_score": sum(1 for f in self.DEV_INDICATORS["files"] if os.path.exists(f)),
            "prod_score": sum(1 for f in self.PROD_INDICATORS["files"] if os.path.exists(f)),
        }

    @staticmethod
    def _safe_get_data(collected_data: dict, key: str) -> Optional[dict]:
        """Safely get collected data, compatible with CollectResult and plain dict"""
        if key not in collected_data:
            return None
        result = collected_data[key]
        if isinstance(result, dict):
            return result
        if hasattr(result, "status") and result.status == "success":
            return result.data
        return None
    
    def get_analyzer_stats(self) -> Dict:
        """
        Get analyzer statistics
        
        Returns:
            Dict with analyzer statistics by type
        """
        stats = {
            'total': len(self._analyzer_names),
            'by_type': {},
            'total_estimated_time': 0.0,
        }
        
        for name in self._analyzer_names:
            info = self._load_analyzer_info(name)
            if info:
                analyzer_type = info.get('analyzer_type', 'routine')
                est_time = info.get('estimated_time', 1.0)
            else:
                analyzer_type = 'routine'
                est_time = 1.0
            
            if analyzer_type not in stats['by_type']:
                stats['by_type'][analyzer_type] = {'count': 0, 'time': 0.0}
            
            stats['by_type'][analyzer_type]['count'] += 1
            stats['by_type'][analyzer_type]['time'] += est_time
            stats['total_estimated_time'] += est_time
        
        return stats
    
    def list_analyzers(self) -> List[Dict]:
        """
        List all analyzers with their metadata
        
        Returns:
            List of dicts with analyzer info
        """
        result = []
        for name in sorted(self._analyzer_names):
            info = self._load_analyzer_info(name)
            
            # Get timeout from registry if available
            timeout = 60  # default
            if self._is_lazy:
                from ...analyzer.analyzer_registry import ANALYZER_REGISTRY, load_analyzer
                if name in ANALYZER_REGISTRY:
                    try:
                        cls = load_analyzer(name)
                        timeout = getattr(cls, 'timeout', 60)
                    except (ImportError, AttributeError, TypeError):
                        pass
            
            if info:
                result.append({
                    'name': name,
                    'type': info.get('analyzer_type', 'routine'),
                    'estimated_time': info.get('estimated_time', 1.0),
                    'timeout': timeout,
                })
            else:
                result.append({
                    'name': name,
                    'type': 'routine',
                    'estimated_time': 1.0,
                    'timeout': timeout,
                })
        return result
