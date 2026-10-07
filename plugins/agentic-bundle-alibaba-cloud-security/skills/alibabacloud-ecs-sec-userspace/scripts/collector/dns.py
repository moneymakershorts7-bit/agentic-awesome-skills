"""DNS Configuration and Domain Name Resolution Collector"""
import socket
import logging
import threading
from .base import BaseCollector

logger = logging.getLogger("sec-userspace")


class DnsCollector(BaseCollector):
    """DNS Configuration and Domain Name Resolution Collector

    Collection capabilities:
    1. /etc/resolv.conf DNS server configuration
    2. /etc/hosts local domain name mappings
    3. Reverse DNS lookups for remote IPs of active connections
    """
    name = "dns"


    def __init__(self):
        """Initialize DNS collector with config-driven settings"""
        super().__init__()
        self.timeout = self._get_config("timeout", 60)
        self._paths = self._get_config("paths", {})
        self._max_reverse_lookups = self._get_config("max_reverse_lookups", 50)
        self._reverse_dns_timeout = self._get_config("reverse_dns_timeout", 2)

    def collect(self) -> dict:
        """Collect DNS-related information"""
        return {
            "resolv_conf": self._parse_resolv_conf(),
            "hosts_entries": self._parse_hosts(),
            "reverse_dns": {},  # Will be populated on-demand during the Analyze phase
        }

    def _parse_resolv_conf(self) -> dict:
        """Parse /etc/resolv.conf"""
        path = self._paths.get("resolv_conf", "/etc/resolv.conf")
        result = {
            "nameservers": [],
            "search_domains": [],
            "raw_path": path,
        }

        try:
            with open(path, "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        if parts[0] == "nameserver":
                            result["nameservers"].append(parts[1])
                        elif parts[0] in ("search", "domain"):
                            result["search_domains"].extend(parts[1:])
        except (FileNotFoundError, PermissionError):
            pass

        return result

    def _parse_hosts(self) -> list:
        """Parse /etc/hosts"""
        path = self._paths.get("hosts", "/etc/hosts")
        entries = []
        try:
            with open(path, "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        hostnames = parts[1:]
                        entries.append({
                            "ip": ip,
                            "hostnames": hostnames,
                        })
        except (FileNotFoundError, PermissionError):
            pass

        return entries

    @classmethod
    def reverse_dns_lookup(cls, ip: str, timeout: int = 2) -> str:
        """Perform reverse DNS lookup for a single IP"""
        result = [""]

        def _lookup():
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                result[0] = hostname
            except OSError:
                pass

        t = threading.Thread(target=_lookup, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result[0]
