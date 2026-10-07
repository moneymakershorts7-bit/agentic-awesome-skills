"""统一 IoC 加载器 - 支持本地冷启动 + sec-server 热更新

IoC 数据以 line-based-b64 格式存储，每行一条 base64 编码的条目。
支持标签格式: [tag]value，用于区分不同来源/类型的 IoC。
仅使用 Python 标准库。

数据文件:
  - ip_port.b64: IP 地址和端口 (tags: c2, mining, whitelist, cloud_metadata)
  - domain.b64:  域名 (tags: c2, mining, ddns)
  - url.b64:     URL/路径/文件名 (tags: webshell, backdoor, malware)
  - hash.b64:    哈希/CVE/包名 (tags: hash, cve, package)
"""
import base64
import binascii
import json
import logging
import os
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class IoCEntry:
    """Parsed IoC entry with optional tag and description."""
    value: str
    tag: str = ""
    description: str = ""


class IoCLoader:
    """统一 IoC (Indicators of Compromise) 加载器

    支持两种数据源:
    1. 本地冷启动: 从 assets/ioc/ 加载 line-based-b64 编码的 IoC 数据
    2. 远程热更新: 从 sec-server 拉取最新 IoC 并合并（取并集）

    数据文件 (v4.0):
      ip_port.b64, domain.b64, url.b64, hash.b64
    """

    def __init__(self, ioc_db_path: Optional[str] = None):
        """初始化加载器

        Args:
            ioc_db_path: IoC 数据库路径，默认为 assets/ioc/
        """
        if ioc_db_path is None:
            # Use path_resolver for zipapp/plain compatibility
            from ..utils.path_resolver import get_asset_path
            ioc_db_path = get_asset_path("ioc")

        self.db_path = ioc_db_path

        # --- Backward-compatible internal stores ---
        # These sets/dicts are populated from the new 4-file format
        # but present the same interface as the old 11-attribute design.
        self._domains: Set[str] = set()
        self._hashes: Set[str] = set()
        self._ips: Set[str] = set()
        self._cves: Set[str] = set()
        self._c2_ports: Dict[int, str] = {}       # port → description
        self._mining_pools: Set[str] = set()      # mining pool domains
        self._mining_ports: Set[int] = set()      # mining pool ports
        self._ddns_domains: Set[str] = set()      # dynamic DNS suffixes
        self._public_dns: Set[str] = set()        # public DNS whitelist IPs
        self._cloud_metadata: Set[str] = set()    # cloud metadata IPs
        self._malicious_packages: Set[str] = set()  # malicious package names

        # --- New structured storage ---
        self._ip_port_entries: List[IoCEntry] = []
        self._domain_entries: List[IoCEntry] = []
        self._url_entries: List[IoCEntry] = []
        self._hash_entries: List[IoCEntry] = []

        self._loaded = False
        self._manifest: Dict = {}
        self._merge_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Tag parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tagged_value(decoded: str) -> IoCEntry:
        """Parse a tagged value: [tag]value or [tag]value:description

        Args:
            decoded: Decoded string from base64 line

        Returns:
            IoCEntry with parsed tag, value, and description
        """
        tag = ""
        if decoded.startswith("[") and "]" in decoded:
            bracket_end = decoded.index("]")
            tag = decoded[1:bracket_end]
            decoded = decoded[bracket_end + 1:]
        # value may contain description after last ':'
        # but only for ip_port entries with *:port:desc format
        return IoCEntry(value=decoded, tag=tag)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> bool:
        """加载本地 cold-start IoC 数据

        Supports both new v4 format (types dict) and legacy v3 format (sources dict).

        Returns:
            True 如果至少有一类 IoC 加载成功
        """
        if not os.path.isdir(self.db_path):
            logger.warning("IoC 数据库目录不存在: %s", self.db_path)
            return False

        try:
            # 加载 manifest
            manifest_path = os.path.join(self.db_path, "manifest.json")
            if not os.path.isfile(manifest_path):
                logger.warning("manifest.json 不存在: %s", manifest_path)
                return False

            with open(manifest_path, "r", encoding="utf-8") as f:
                self._manifest = json.load(f)

            # Detect format version
            if "types" in self._manifest:
                return self._load_v4()
            elif "sources" in self._manifest:
                return self._load_v3_legacy()
            else:
                logger.warning("Unknown manifest format in %s", manifest_path)
                return False

        except (KeyError, ValueError, OSError) as e:
            logger.error("加载 IoC 数据库失败: %s", e)
            return False

    def _load_v4(self) -> bool:
        """Load v4 format: 4 typed files with tag support."""
        types = self._manifest.get("types", {})
        loaded_any = False

        for type_name, type_info in types.items():
            filepath = os.path.join(self.db_path, type_info["file"])
            entries = self._load_tagged_b64_file(filepath)

            if type_name == "ip_port":
                self._ip_port_entries = entries
                self._populate_ip_port(entries)
            elif type_name == "domain":
                self._domain_entries = entries
                self._populate_domain(entries)
            elif type_name == "url":
                self._url_entries = entries
            elif type_name == "hash":
                self._hash_entries = entries
                self._populate_hash(entries)

            loaded_any = loaded_any or bool(entries)

        self._loaded = loaded_any
        if loaded_any:
            self._log_load_stats()
        return loaded_any

    def _load_v3_legacy(self) -> bool:
        """Load legacy v3 format: 11 separate files with sources dict."""
        sources = self._manifest.get("sources", {})
        loaded_any = False

        for ioc_type, attr_name in [
            ("domains", "_domains"),
            ("hashes", "_hashes"),
            ("ips", "_ips"),
            ("cves", "_cves"),
            ("c2_ports", "_c2_ports"),
            ("mining_pools", "_mining_pools"),
            ("mining_ports", "_mining_ports"),
            ("ddns_domains", "_ddns_domains"),
            ("public_dns", "_public_dns"),
            ("cloud_metadata", "_cloud_metadata"),
            ("malicious_packages", "_malicious_packages"),
        ]:
            if ioc_type in sources:
                filepath = os.path.join(self.db_path, sources[ioc_type]["file"])
                if ioc_type == "c2_ports":
                    data = self._load_kv_b64_file(filepath)
                elif ioc_type == "mining_ports":
                    raw = self._load_b64_file(filepath)
                    data = {int(p) for p in raw if p.isdigit()}
                else:
                    data = self._load_b64_file(filepath)
                setattr(self, attr_name, data)
                loaded_any = loaded_any or bool(data)

        self._loaded = loaded_any
        if loaded_any:
            self._log_load_stats()
        return loaded_any

    def _populate_ip_port(self, entries: List[IoCEntry]) -> None:
        """Populate backward-compatible ip/port sets from ip_port entries."""
        for entry in entries:
            tag = entry.tag
            val = entry.value

            if tag == "c2":
                if val.startswith("*:"):
                    # Wildcard IP: *:port or *:port:description
                    parts = val[2:].split(":", 1)
                    try:
                        port = int(parts[0])
                        desc = parts[1] if len(parts) > 1 else ""
                        self._c2_ports[port] = desc
                    except ValueError:
                        pass
                else:
                    # Pure IP or IP:port
                    ip = val.split(":")[0]
                    self._ips.add(ip)
            elif tag == "mining":
                if val.startswith("*:"):
                    try:
                        port = int(val[2:].split(":")[0])
                        self._mining_ports.add(port)
                    except ValueError:
                        pass
                else:
                    self._ips.add(val.split(":")[0])
            elif tag == "whitelist":
                self._public_dns.add(val)
            elif tag == "cloud_metadata":
                self._cloud_metadata.add(val)
            else:
                # Untagged → treat as plain IP
                self._ips.add(val.split(":")[0])

    def _populate_domain(self, entries: List[IoCEntry]) -> None:
        """Populate backward-compatible domain sets from domain entries."""
        for entry in entries:
            tag = entry.tag
            val = entry.value

            if tag == "c2":
                self._domains.add(val)
            elif tag == "mining":
                self._mining_pools.add(val)
            elif tag == "ddns":
                # Store as suffix for matching (e.g. *.bounceme.net → .bounceme.net)
                suffix = val
                if suffix.startswith("*."):
                    suffix = suffix[1:]  # *.foo.com → .foo.com
                elif suffix.startswith("*"):
                    suffix = suffix[1:]  # *foo.com → foo.com
                self._ddns_domains.add(suffix)
            else:
                self._domains.add(val)

    def _populate_hash(self, entries: List[IoCEntry]) -> None:
        """Populate backward-compatible hash/cve/package sets from hash entries."""
        for entry in entries:
            tag = entry.tag
            val = entry.value

            if tag == "hash":
                # Strip prefix like sha256: or md5: for backward compat
                if ":" in val:
                    _prefix, hash_val = val.split(":", 1)
                    self._hashes.add(hash_val)
                else:
                    self._hashes.add(val)
            elif tag == "cve":
                self._cves.add(val)
            elif tag == "package":
                self._malicious_packages.add(val)
            else:
                # Untagged
                self._hashes.add(val)

    def _log_load_stats(self) -> None:
        """Log loading statistics."""
        logger.info(
            "IoC 数据库加载完成: domains=%d, hashes=%d, ips=%d, cves=%d, "
            "c2_ports=%d, mining_pools=%d, mining_ports=%d, ddns=%d, "
            "public_dns=%d, cloud_metadata=%d, malicious_pkgs=%d",
            len(self._domains), len(self._hashes),
            len(self._ips), len(self._cves),
            len(self._c2_ports), len(self._mining_pools),
            len(self._mining_ports), len(self._ddns_domains),
            len(self._public_dns), len(self._cloud_metadata),
            len(self._malicious_packages),
        )

    # ------------------------------------------------------------------
    # File I/O helpers
    # ------------------------------------------------------------------

    def _load_tagged_b64_file(self, filepath: str) -> List[IoCEntry]:
        """Load a line-based-b64 file with tag support.

        Lines starting with '#' are comments. Blank lines are skipped.
        Each data line is base64-decoded, then parsed for [tag]value format.

        Args:
            filepath: .b64 file path

        Returns:
            List of parsed IoCEntry objects
        """
        result: List[IoCEntry] = []
        if not os.path.isfile(filepath):
            logger.warning("IoC 文件不存在: %s", filepath)
            return result

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        decoded = base64.b64decode(line).decode("utf-8").strip()
                        if decoded:
                            entry = self._parse_tagged_value(decoded)
                            result.append(entry)
                    except (binascii.Error, UnicodeDecodeError):
                        logger.debug("跳过无效 base64 行 %s:%d", filepath, line_num)
        except OSError as e:
            logger.error("读取 IoC 文件失败 %s: %s", filepath, e)

        return result

    def _load_b64_file(self, filepath: str) -> Set[str]:
        """加载 base64 编码的 IoC 文件 (legacy format)

        每行一条 IoC，每行独立 base64 编码。
        空行和解码失败的行会被跳过。
        """
        result: Set[str] = set()
        if not os.path.isfile(filepath):
            logger.warning("IoC 文件不存在: %s", filepath)
            return result

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        decoded = base64.b64decode(line).decode("utf-8").strip()
                        if decoded:
                            result.add(decoded)
                    except (binascii.Error, UnicodeDecodeError):
                        logger.debug("跳过无效 base64 行 %s:%d", filepath, line_num)
        except OSError as e:
            logger.error("读取 IoC 文件失败 %s: %s", filepath, e)

        return result

    def _load_kv_b64_file(self, filepath: str) -> Dict:
        """加载 base64 编码的 key:value 格式 IoC 文件 (legacy format)"""
        result: Dict = {}
        if not os.path.isfile(filepath):
            logger.warning("IoC 文件不存在: %s", filepath)
            return result

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        decoded = base64.b64decode(line).decode("utf-8").strip()
                        if decoded and ":" in decoded:
                            key_str, value = decoded.split(":", 1)
                            try:
                                key = int(key_str.strip())
                                result[key] = value.strip()
                            except ValueError:
                                logger.debug(
                                    "跳过非整数键 %s:%d: %s",
                                    filepath, line_num, key_str,
                                )
                        elif decoded:
                            result[decoded] = ""
                    except (binascii.Error, UnicodeDecodeError):
                        logger.debug("跳过无效 base64 行 %s:%d", filepath, line_num)
        except OSError as e:
            logger.error("读取 IoC 文件失败 %s: %s", filepath, e)

        return result

    # ------------------------------------------------------------------
    # Remote merge
    # ------------------------------------------------------------------

    def merge_remote_ioc(
        self,
        endpoint: str,
        api_version: str = "v1",
        timeout: int = 10,
    ) -> bool:
        """从 sec-server 拉取热更新 IoC 并合并

        合并策略: 本地 + 远程取并集，远程数据优先。

        预期远程 API 响应格式:
        {
            "domains": ["evil.com", ...],
            "hashes": ["abc123...", ...],
            "ips": ["1.2.3.4", ...],
            "cves": ["CVE-2024-xxxx", ...]
        }

        Args:
            endpoint: sec-server 地址（如 http://localhost:8080）
            api_version: API 版本
            timeout: 请求超时秒数

        Returns:
            True 如果合并成功
        """
        url = f"{endpoint.rstrip('/')}/api/{api_version}/ioc/all"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "sec-userspace-ioc-loader/2.0",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("远程 IoC 请求失败: HTTP %d", resp.status)
                    return False

                data = json.loads(resp.read().decode("utf-8"))

            # 合并（并集）
            remote_domains = set(data.get("domains", []))
            remote_hashes = set(data.get("hashes", []))
            remote_ips = set(data.get("ips", []))
            remote_cves = set(data.get("cves", []))

            with self._merge_lock:
                merged_d = len(remote_domains - self._domains)
                merged_h = len(remote_hashes - self._hashes)
                merged_i = len(remote_ips - self._ips)
                merged_c = len(remote_cves - self._cves)

                self._domains |= remote_domains
                self._hashes |= remote_hashes
                self._ips |= remote_ips
                self._cves |= remote_cves

            logger.info(
                "远程 IoC 合并完成: +%d domains, +%d hashes, +%d ips, +%d cves",
                merged_d, merged_h, merged_i, merged_c,
            )
            return True

        except urllib.error.URLError as e:
            logger.warning("远程 IoC 请求失败（离线模式正常）: %s", e)
            return False
        except (KeyError, ValueError, OSError) as e:
            logger.error("远程 IoC 数据解析失败: %s", e)
            return False

    # ------------------------------------------------------------------
    # Lookup API (backward-compatible — signatures unchanged)
    # ------------------------------------------------------------------

    def lookup_domain(self, domain: str) -> bool:
        """查询域名是否为恶意

        Args:
            domain: 要查询的域名

        Returns:
            True 如果域名在恶意列表中
        """
        if not domain:
            return False
        return domain.lower().strip() in self._domains

    def lookup_hash(self, file_hash: str) -> bool:
        """查询文件哈希是否为恶意

        Args:
            file_hash: 文件哈希值（MD5/SHA1/SHA256）

        Returns:
            True 如果哈希在恶意列表中
        """
        if not file_hash:
            return False
        return file_hash.lower().strip() in self._hashes

    def lookup_ip(self, ip: str) -> bool:
        """查询 IP 是否为恶意

        Args:
            ip: IP 地址

        Returns:
            True 如果 IP 在恶意列表中
        """
        if not ip:
            return False
        return ip.strip() in self._ips

    def lookup_cve(self, cve_id: str) -> bool:
        """查询 CVE 是否在已知列表中

        Args:
            cve_id: CVE 编号（如 CVE-2024-3094）

        Returns:
            True 如果 CVE 在已知列表中
        """
        if not cve_id:
            return False
        return cve_id.upper().strip() in self._cves

    def lookup_c2_port(self, port: int) -> Optional[str]:
        """查询端口是否为已知 C2 端口

        Args:
            port: 端口号

        Returns:
            端口描述，如果不是 C2 端口则返回 None
        """
        return self._c2_ports.get(port)

    def lookup_mining_pool(self, domain: str) -> bool:
        """查询域名是否为挖矿矿池

        Args:
            domain: 域名

        Returns:
            True 如果是挖矿矿池域名
        """
        if not domain:
            return False
        return domain.lower().strip() in self._mining_pools

    def lookup_mining_port(self, port: int) -> bool:
        """查询端口是否为挖矿端口

        Args:
            port: 端口号

        Returns:
            True 如果是挖矿端口
        """
        return port in self._mining_ports

    def lookup_ddns_domain(self, domain: str) -> bool:
        """查询域名是否为动态DNS域名（常用于恶意软件）

        Args:
            domain: 域名

        Returns:
            True 如果匹配动态DNS模式
        """
        if not domain:
            return False
        domain_lower = domain.lower()
        for ddns in self._ddns_domains:
            if domain_lower.endswith(ddns.lstrip(".")):
                return True
        return False

    def is_public_dns(self, ip: str) -> bool:
        """查询 IP 是否为公共DNS服务器（白名单）

        Args:
            ip: IP 地址

        Returns:
            True 如果是已知公共DNS
        """
        if not ip:
            return False
        return ip.strip() in self._public_dns

    def is_cloud_metadata_ip(self, ip: str) -> bool:
        """查询 IP 是否为云厂商元数据服务地址

        Args:
            ip: IP 地址

        Returns:
            True 如果是云元数据IP
        """
        if not ip:
            return False
        return ip.strip() in self._cloud_metadata

    def lookup_malicious_package(self, package: str) -> bool:
        """查询包名是否为已知恶意包

        Args:
            package: 包名（格式如 npm:event-stream）

        Returns:
            True 如果是恶意包
        """
        if not package:
            return False
        return package.lower().strip() in self._malicious_packages

    # ------------------------------------------------------------------
    # Properties (backward-compatible)
    # ------------------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        """是否已加载数据"""
        return self._loaded

    @property
    def domains(self) -> Set[str]:
        """返回恶意域名集合（只读副本）"""
        return set(self._domains)

    @property
    def hashes(self) -> Set[str]:
        """返回恶意哈希集合（只读副本）"""
        return set(self._hashes)

    @property
    def ips(self) -> Set[str]:
        """返回恶意 IP 集合（只读副本）"""
        return set(self._ips)

    @property
    def cves(self) -> Set[str]:
        """返回已知 CVE 集合（只读副本）"""
        return set(self._cves)

    @property
    def stats(self) -> Dict:
        """返回 IoC 统计信息"""
        return {
            "loaded": self._loaded,
            "version": self._manifest.get("version", "unknown"),
            "created": self._manifest.get("created", "unknown"),
            "domains": len(self._domains),
            "hashes": len(self._hashes),
            "ips": len(self._ips),
            "cves": len(self._cves),
            "c2_ports": len(self._c2_ports),
            "mining_pools": len(self._mining_pools),
            "mining_ports": len(self._mining_ports),
            "ddns_domains": len(self._ddns_domains),
            "public_dns": len(self._public_dns),
            "cloud_metadata": len(self._cloud_metadata),
            "malicious_packages": len(self._malicious_packages),
            "total": (
                len(self._domains) + len(self._hashes) + len(self._ips) +
                len(self._cves) + len(self._c2_ports) + len(self._mining_pools) +
                len(self._mining_ports) + len(self._ddns_domains) +
                len(self._public_dns) + len(self._cloud_metadata) +
                len(self._malicious_packages)
            ),
        }

    def __repr__(self) -> str:
        s = self.stats
        return (
            f"IoCLoader(loaded={s['loaded']}, v={s['version']}, "
            f"domains={s['domains']}, hashes={s['hashes']}, "
            f"ips={s['ips']}, cves={s['cves']}, "
            f"c2_ports={s['c2_ports']}, mining={s['mining_pools']}, "
            f"pkgs={s['malicious_packages']})"
        )


# 模块级单例，便于全局访问
_default_loader: Optional[IoCLoader] = None
_default_loader_lock = threading.Lock()


def get_loader(ioc_db_path: Optional[str] = None) -> IoCLoader:
    """获取全局 IoC 加载器单例

    Args:
        ioc_db_path: 自定义数据库路径，默认使用内置路径

    Returns:
        IoCLoader 实例（已加载数据）
    """
    global _default_loader
    if _default_loader is None:
        with _default_loader_lock:
            if _default_loader is None:
                loader = IoCLoader(ioc_db_path)
                loader.load()
                _default_loader = loader
    return _default_loader


def reset_loader() -> None:
    """重置全局加载器（主要用于测试）"""
    global _default_loader
    with _default_loader_lock:
        _default_loader = None
