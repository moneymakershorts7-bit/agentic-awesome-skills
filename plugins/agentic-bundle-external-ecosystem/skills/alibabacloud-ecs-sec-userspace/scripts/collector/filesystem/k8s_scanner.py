"""Kubernetes sensitive file scanning mixin for FilesystemCollector"""
import logging
import os
import stat
from datetime import datetime

logger = logging.getLogger("sec-userspace")

# Maximum safe timestamp (2070-01-01)
_MAX_SAFE_TIMESTAMP = 32503680000


def _safe_timestamp_to_iso(timestamp: float) -> str:
    """Safely convert a Unix timestamp to ISO format"""
    safe_ts = max(0, min(timestamp, _MAX_SAFE_TIMESTAMP))
    return datetime.fromtimestamp(safe_ts).isoformat()


class K8sScannerMixin:
    """Mixin providing Kubernetes sensitive file scanning."""

    def _scan_k8s_sensitive_files(self) -> list:
        """Scan Kubernetes sensitive files for runtime detection

        Monitors K8s runtime artifacts:
        - ServiceAccount tokens and credentials
        - kubeconfig files (credential exposure)
        - K8s configuration directories
        - Container boundary files
        - K8s certificate files

        Returns:
            List of K8s sensitive file metadata dicts with:
            - path: File path
            - category: Classification (sa_token, kubeconfig, cert, config, boundary)
            - size: File size
            - mtime: Last modification time (ISO format)
            - permissions: File permissions (octal)
        """
        k8s_sensitive_files = []

        # K8s sensitive file patterns with categories
        k8s_file_patterns = [
            # ServiceAccount tokens (critical for workload identity)
            ("/var/run/secrets/kubernetes.io/serviceaccount/token", "sa_token"),
            ("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "sa_token"),
            ("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "sa_token"),

            # Kubeconfig files (credential exposure risk)
            ("/root/.kube/config", "kubeconfig"),
            ("/etc/kubernetes/admin.conf", "kubeconfig"),
            ("/etc/kubernetes/kubelet.conf", "kubeconfig"),
            ("/etc/kubernetes/controller-manager.conf", "kubeconfig"),
            ("/etc/kubernetes/scheduler.conf", "kubeconfig"),

            # K8s PKI certificates
            ("/etc/kubernetes/pki/ca.crt", "cert"),
            ("/etc/kubernetes/pki/ca.key", "cert"),
            ("/etc/kubernetes/pki/apiserver.crt", "cert"),
            ("/etc/kubernetes/pki/apiserver.key", "cert"),
            ("/etc/kubernetes/pki/front-proxy-ca.crt", "cert"),
            ("/etc/kubernetes/pki/sa.pub", "cert"),
            ("/etc/kubernetes/pki/sa.key", "cert"),

            # K8s configuration files
            ("/etc/kubernetes/manifests/", "config"),
            ("/etc/kubernetes/kubelet.conf", "config"),
            ("/var/lib/kubelet/config.yaml", "config"),
            ("/var/lib/kubelet/kubeadm-flags.env", "config"),

            # Container boundary files (escape indicators)
            ("/.dockerenv", "boundary"),
            ("/run/containerd/containerd.sock", "boundary"),
            ("/run/crio/crio.sock", "boundary"),
            ("/var/run/docker.sock", "boundary"),
        ]

        for file_path, category in k8s_file_patterns:
            try:
                # Handle directories - check if exists and list contents
                if file_path.endswith('/'):
                    if os.path.isdir(file_path):
                        try:
                            with os.scandir(file_path) as it:
                                for entry in it:
                                    try:
                                        st = entry.stat(follow_symlinks=False)
                                        if stat.S_ISREG(st.st_mode):
                                            mtime = _safe_timestamp_to_iso(st.st_mtime)
                                            k8s_sensitive_files.append({
                                                "path": entry.path,
                                                "category": category,
                                                "size": st.st_size,
                                                "mtime": mtime,
                                                "permissions": oct(stat.S_IMODE(st.st_mode)),
                                            })
                                    except OSError:
                                        continue
                        except OSError:
                            pass
                else:
                    # Handle files
                    if os.path.isfile(file_path):
                        st = os.stat(file_path)
                        mtime = _safe_timestamp_to_iso(st.st_mtime)
                        k8s_sensitive_files.append({
                            "path": file_path,
                            "category": category,
                            "size": st.st_size,
                            "mtime": mtime,
                            "permissions": oct(stat.S_IMODE(st.st_mode)),
                        })
            except OSError:
                continue

        # Also scan for kubeconfig files in common locations
        kubeconfig_search_dirs = ['/tmp', '/home', '/opt', '/var/tmp']
        for search_dir in kubeconfig_search_dirs:
            if not os.path.isdir(search_dir):
                continue

            try:
                self._scan_kubeconfig_files(search_dir, k8s_sensitive_files)
            except OSError:
                continue

        # Scan for recently created SA token files
        sa_token_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
        if os.path.isdir(sa_token_dir):
            try:
                with os.scandir(sa_token_dir) as it:
                    for entry in it:
                        try:
                            st = entry.stat(follow_symlinks=False)
                            if stat.S_ISREG(st.st_mode):
                                mtime = _safe_timestamp_to_iso(st.st_mtime)
                                # Check if already added
                                already_added = any(
                                    f["path"] == entry.path for f in k8s_sensitive_files
                                )
                                if not already_added:
                                    k8s_sensitive_files.append({
                                        "path": entry.path,
                                        "category": "sa_token",
                                        "size": st.st_size,
                                        "mtime": mtime,
                                        "permissions": oct(stat.S_IMODE(st.st_mode)),
                                    })
                        except OSError:
                            continue
            except OSError:
                pass

        return k8s_sensitive_files

    def _scan_kubeconfig_files(self, directory: str, result_list: list, depth: int = 0, max_depth: int = 2) -> None:
        """Recursively scan for kubeconfig files"""
        if depth > max_depth:
            return

        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if stat.S_ISDIR(entry.stat(follow_symlinks=False).st_mode):
                            # Skip system directories
                            if entry.name in ('proc', 'sys', 'dev'):
                                continue
                            self._scan_kubeconfig_files(entry.path, result_list, depth + 1, max_depth)
                        elif stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                            # Check for kubeconfig patterns
                            name_lower = entry.name.lower()
                            if ('kubeconfig' in name_lower or
                                (name_lower.endswith('.yaml') or name_lower.endswith('.yml'))):
                                # Quick content check for kubeconfig indicators
                                try:
                                    with open(entry.path, 'r', errors='replace', encoding='utf-8') as f:
                                        content = f.read(512)  # Read first 512 bytes
                                        if any(kw in content for kw in ['apiVersion:', 'kind: Config', 'clusters:', 'contexts:']):
                                            st = entry.stat(follow_symlinks=False)
                                            mtime = _safe_timestamp_to_iso(st.st_mtime)
                                            result_list.append({
                                                "path": entry.path,
                                                "category": "kubeconfig",
                                                "size": st.st_size,
                                                "mtime": mtime,
                                                "permissions": oct(stat.S_IMODE(st.st_mode)),
                                            })
                                except (OSError, UnicodeDecodeError):
                                    continue
                    except OSError:
                        continue
        except OSError:
            pass
