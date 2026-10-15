"""Unified Assets Manager for IoC and Whitelist data.

Handles loading, merging, deduplication, persistence and display of
IoC indicators and whitelist rules stored under the assets/ directory.
Supports automatic recovery from assets-origin/ backup when data is corrupted.

Data format:
  - IoC .b64 files: one base64-encoded entry per line
  - Whitelist analyzer_rules.b64: line-based-b64 format, each line is a
    base64-encoded JSON rule (comments start with #, empty lines ignored)
  - Whitelist IoC-type files (domain.b64, ip_port.b64, url.b64, hash.b64):
    [tag]value format, base64-encoded per line
"""

import os
import json
import base64
import copy
import shutil
import logging
import threading
from typing import Dict, Set, List, Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger("sec-userspace.asset_manager")


class AssetManager:
    """Unified Assets Manager.

    Loads IoC and Whitelist data from the assets/ directory,
    supports merging remote updates, deduplication, persistence and display.
    Falls back to assets-origin/ backup when primary data is corrupted.
    """

    def __init__(self, assets_dir: str):
        """Initialise the manager.

        Args:
            assets_dir: Absolute path to the assets root directory.
        """
        self.assets_dir = assets_dir
        self.ioc_dir = os.path.join(assets_dir, "ioc")
        self.whitelist_dir = os.path.join(assets_dir, "whitelist")
        # origin dir is at the same level as assets_dir: assets-origin/
        self.origin_dir = os.path.join(os.path.dirname(assets_dir), "assets-origin")

        # In-memory stores
        self._ioc_data: Dict[str, Set[str]] = {}
        self._whitelist_data: Dict[str, Any] = {}
        self._ioc_manifest: Dict[str, Any] = {}
        self._whitelist_manifest: Dict[str, Any] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _auto_copy_from_origin(self) -> None:
        """Auto-copy data from assets-origin/ if assets/ subdirectories are empty."""
        for subdir in ("ioc", "whitelist"):
            target = os.path.join(self.assets_dir, subdir)
            origin_src = os.path.join(self.origin_dir, subdir)
            # Copy if target dir doesn't exist or is empty (ignoring .gitkeep)
            needs_copy = False
            if not os.path.isdir(target):
                needs_copy = True
            else:
                contents = [f for f in os.listdir(target) if f != ".gitkeep"]
                if not contents:
                    needs_copy = True
            if needs_copy and os.path.isdir(origin_src):
                logger.info("从 assets-origin 复制 %s/ 到 assets/", subdir)
                if os.path.isdir(target):
                    shutil.rmtree(target)
                shutil.copytree(origin_src, target)

    def load(self) -> bool:
        """Load all assets data.  On failure try restoring from assets-origin/."""
        try:
            self._auto_copy_from_origin()
            self.load_ioc()
            self.load_whitelist()
            self._loaded = True
            return True
        except (OSError, ValueError) as exc:
            logger.warning("Assets 加载失败: %s, 尝试从 origin 恢复", exc)
            if self.restore_from_origin():
                try:
                    self.load_ioc()
                    self.load_whitelist()
                    self._loaded = True
                    return True
                except (OSError, ValueError) as exc2:
                    logger.error("从 origin 恢复后仍然失败: %s", exc2)
        return False

    def load_ioc(self) -> Dict[str, Set[str]]:
        """Load IoC data from .b64 files.

        Supports both v4 format (types dict in manifest, line-based-b64 with
        comment lines starting with #) and legacy format (plain b64 lines).

        Returns:
            ``{type_name: set(decoded_values)}``
        """
        self._ioc_data = {}

        # Load manifest if present
        manifest_path = os.path.join(self.ioc_dir, "manifest.json")
        if os.path.isfile(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as fh:
                self._ioc_manifest = json.load(fh)

        # Scan for .b64 files
        if not os.path.isdir(self.ioc_dir):
            logger.warning("IoC 目录不存在: %s", self.ioc_dir)
            return self._ioc_data

        for fname in os.listdir(self.ioc_dir):
            if not fname.endswith(".b64"):
                continue
            type_name = fname[:-4]  # strip .b64
            filepath = os.path.join(self.ioc_dir, fname)
            entries = self._decode_b64_lines(filepath)
            self._ioc_data[type_name] = entries

        logger.info(
            "IoC 加载完成: %s 类型, %d 条记录",
            len(self._ioc_data),
            sum(len(v) for v in self._ioc_data.values()),
        )
        return self._ioc_data

    def load_whitelist(self) -> Dict[str, Any]:
        """Load whitelist data using new multi-file format.

        Reads manifest.json to discover type files (domain.b64, ip_port.b64,
        url.b64, hash.b64, analyzer_rules.b64).

        Returns:
            ``{category: category_data_dict}``
        """
        self._whitelist_data = {}

        # Load manifest if present
        manifest_path = os.path.join(self.whitelist_dir, "manifest.json")
        if os.path.isfile(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as fh:
                self._whitelist_manifest = json.load(fh)

        if not os.path.isdir(self.whitelist_dir):
            logger.warning("Whitelist 目录不存在: %s", self.whitelist_dir)
            return self._whitelist_data

        # Load analyzer_rules.b64 if present
        analyzer_rules_path = os.path.join(self.whitelist_dir, "analyzer_rules.b64")
        if os.path.isfile(analyzer_rules_path):
            self._whitelist_data = self._load_whitelist_b64(analyzer_rules_path)

        # Also load IoC-type whitelist files if present
        for ioc_type in ("domain", "ip_port", "url", "hash"):
            ioc_file = os.path.join(self.whitelist_dir, f"{ioc_type}.b64")
            if os.path.isfile(ioc_file):
                entries = self._decode_ioc_whitelist(ioc_file, ioc_type)
                if entries:
                    cat_name = f"ioc_{ioc_type}"
                    self._whitelist_data[cat_name] = {"entries": entries, "type": ioc_type}

        total = sum(
            len(cat.get("entries", []))
            for cat in self._whitelist_data.values()
            if isinstance(cat, dict)
        )
        logger.info(
            "Whitelist 加载完成: %s 类别, %d 条规则",
            len(self._whitelist_data),
            total,
        )
        return self._whitelist_data

    # ------------------------------------------------------------------
    # Merging
    # ------------------------------------------------------------------

    def merge_ioc(self, remote_data: Dict[str, List[str]]) -> Dict[str, int]:
        """Merge remote IoC data into current dataset.

        Args:
            remote_data: ``{"domains": ["evil.com", ...], ...}``

        Returns:
            Delta counts ``{"domains": 5, "ips": 2, ...}``
        """
        if not self._loaded:
            self.load()

        delta: Dict[str, int] = {}
        for type_name, values in remote_data.items():
            if not isinstance(values, (list, set)):
                continue
            existing = self._ioc_data.get(type_name, set())
            new_values = set(values) - existing
            delta[type_name] = len(new_values)
            self._ioc_data[type_name] = existing | new_values

        logger.info("IoC 合并完成: %s", delta)
        return delta

    def merge_whitelist(self, remote_data: Dict[str, Any]) -> Dict[str, int]:
        """Merge remote whitelist data.

        Args:
            remote_data: ``{"categories": {"default": {"entries": [...]}, ...}}``

        Returns:
            Delta counts ``{"default": 3, ...}``

        Dedup: by entry ``id``; if same id, keep the one with newer ``added_at``.
        """
        if not self._loaded:
            self.load()

        categories = remote_data.get("categories", remote_data)
        delta: Dict[str, int] = {}

        for cat_name, cat_data in categories.items():
            if not isinstance(cat_data, dict):
                continue
            remote_entries = cat_data.get("entries", [])
            if not isinstance(remote_entries, list):
                continue

            existing_cat = self._whitelist_data.get(cat_name, {})
            if not isinstance(existing_cat, dict):
                existing_cat = {}
            existing_entries = existing_cat.get("entries", [])

            # Build index by entry id
            entry_map: Dict[str, Any] = {}
            for entry in existing_entries:
                eid = entry.get("id", "")
                if eid:
                    entry_map[eid] = entry

            added = 0
            for entry in remote_entries:
                eid = entry.get("id", "")
                if not eid:
                    continue
                if eid in entry_map:
                    # Keep newer version
                    old_at = entry_map[eid].get("added_at", "")
                    new_at = entry.get("added_at", "")
                    if new_at > old_at:
                        entry_map[eid] = entry
                        added += 1
                else:
                    entry_map[eid] = entry
                    added += 1

            merged_cat = copy.deepcopy(existing_cat)
            merged_cat["entries"] = list(entry_map.values())
            if "version" in cat_data:
                merged_cat["version"] = cat_data["version"]
            self._whitelist_data[cat_name] = merged_cat
            delta[cat_name] = added

        logger.info("Whitelist 合并完成: %s", delta)
        return delta

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> bool:
        """Persist in-memory data back to the assets directory.

        Returns:
            True on success, False on failure.
        """
        try:
            self._save_ioc()
            self._save_whitelist()
            return True
        except (OSError, ValueError, TypeError) as exc:
            logger.error("Assets 保存失败: %s", exc)
            return False

    def _save_ioc(self) -> None:
        """Write IoC data to .b64 files (line-based-b64 v1) and update manifest."""
        os.makedirs(self.ioc_dir, exist_ok=True)
        total = 0

        # Header comments per type (v4 format)
        type_headers = {
            "ip_port": ["# sec-userspace IoC: ip_port", "# format: line-based-b64 v1",
                        "# tags: [c2] [mining] [whitelist] [cloud_metadata]", ""],
            "domain": ["# sec-userspace IoC: domain", "# format: line-based-b64 v1",
                       "# tags: [c2] [mining] [ddns]", ""],
            "url": ["# sec-userspace IoC: url", "# format: line-based-b64 v1",
                    "# tags: [webshell] [backdoor] [malware]", ""],
            "hash": ["# sec-userspace IoC: hash", "# format: line-based-b64 v1",
                     "# tags: [hash] [cve] [package]", ""],
        }

        for type_name, values in self._ioc_data.items():
            filepath = os.path.join(self.ioc_dir, f"{type_name}.b64")
            with open(filepath, "w", encoding="utf-8") as fh:
                # Write header if known type
                for hdr in type_headers.get(type_name, []):
                    fh.write(hdr + "\n")
                for val in sorted(values):
                    encoded = base64.b64encode(val.encode("utf-8")).decode("ascii")
                    fh.write(encoded + "\n")
            total += len(values)

        # Update manifest (v4 format)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        types_info = {}
        for k, v in self._ioc_data.items():
            types_info[k] = {
                "file": f"{k}.b64",
                "count": len(v),
            }
        self._ioc_manifest.update({
            "format": "line-based-b64",
            "format_version": 1,
            "total_entries": total,
            "updated": now,
            "types": types_info,
        })
        manifest_path = os.path.join(self.ioc_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(self._ioc_manifest, fh, indent=2, ensure_ascii=False)

        logger.info("IoC 保存完成: %d 类型, %d 条", len(self._ioc_data), total)

    def _save_whitelist(self) -> None:
        """Write whitelist data to multi-file format and update manifest."""
        os.makedirs(self.whitelist_dir, exist_ok=True)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Separate entries by type
        analyzer_rules_lines = [
            "# sec-userspace analyzer whitelist rules",
            "# format: line-based-b64 v1",
            "# each line: base64(json_rule)",
            "# lines starting with # are comments",
            f"# updated: {now}",
            "",
        ]
        ioc_type_entries: Dict[str, List[str]] = {
            "domain": [], "ip_port": [], "url": [], "hash": [],
        }
        total_analyzer = 0
        total_ioc: Dict[str, int] = {k: 0 for k in ioc_type_entries}

        for cat_name, cat_data in self._whitelist_data.items():
            if not isinstance(cat_data, dict):
                continue

            ioc_type = cat_data.get("type")
            if ioc_type in ioc_type_entries:
                # IoC-type entry: store as [tag]value
                for entry in cat_data.get("entries", []):
                    tag = entry.get("tag", "")
                    value = entry.get("value", "")
                    tagged = f"[{tag}]{value}" if tag else value
                    encoded = base64.b64encode(tagged.encode("utf-8")).decode("ascii")
                    ioc_type_entries[ioc_type].append(encoded)
                    total_ioc[ioc_type] += 1
            else:
                # Analyzer rule entry
                entries = cat_data.get("entries", [])
                for entry in entries:
                    rule = dict(entry)
                    rule["_category"] = cat_name
                    rule_json = json.dumps(rule, ensure_ascii=False, separators=(",", ":"))
                    rule_b64 = base64.b64encode(rule_json.encode("utf-8")).decode("ascii")
                    analyzer_rules_lines.append(rule_b64)
                    total_analyzer += 1

        # Save analyzer_rules.b64
        rules_path = os.path.join(self.whitelist_dir, "analyzer_rules.b64")
        with open(rules_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(analyzer_rules_lines) + "\n")

        # Save IoC-type whitelist files
        ioc_headers = {
            "domain": ["# Whitelisted domains - line-based-b64 v1", "# Format: base64([tag]value)", ""],
            "ip_port": ["# Whitelisted IP addresses and ports - line-based-b64 v1", "# Format: base64([tag]value)", ""],
            "url": ["# Whitelisted URLs - line-based-b64 v1", "# Format: base64([tag]value)", ""],
            "hash": ["# Whitelisted file hashes - line-based-b64 v1", "# Format: base64([tag]value)", ""],
        }
        for ioc_type, encoded_entries in ioc_type_entries.items():
            filepath = os.path.join(self.whitelist_dir, f"{ioc_type}.b64")
            with open(filepath, "w", encoding="utf-8") as fh:
                for hdr in ioc_headers.get(ioc_type, []):
                    fh.write(hdr + "\n")
                for encoded in encoded_entries:
                    fh.write(encoded + "\n")

        # Update manifest
        types_info = {}
        for ioc_type in ioc_type_entries:
            types_info[ioc_type] = {
                "file": f"{ioc_type}.b64",
                "count": total_ioc[ioc_type],
            }
        types_info["analyzer_rules"] = {
            "file": "analyzer_rules.b64",
            "count": total_analyzer,
        }

        self._whitelist_manifest.update({
            "format": "line-based-b64",
            "format_version": 1,
            "updated_at": now,
            "types": types_info,
            "total_entries": total_analyzer + sum(total_ioc.values()),
        })
        manifest_path = os.path.join(self.whitelist_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(self._whitelist_manifest, fh, indent=2, ensure_ascii=False)

        logger.info("Whitelist 保存完成: %d 类别, %d 分析器规则, %d IoC条目",
                    len(self._whitelist_data), total_analyzer, sum(total_ioc.values()))

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def restore_from_origin(self) -> bool:
        """Restore assets from assets-origin/ backup.

        Copies assets-origin/ioc/ → ioc/ and assets-origin/whitelist/ → whitelist/.

        Returns:
            True if restoration succeeded.
        """
        origin_ioc = os.path.join(self.origin_dir, "ioc")
        origin_wl = os.path.join(self.origin_dir, "whitelist")

        if not os.path.isdir(self.origin_dir):
            logger.error("Origin 备份目录不存在: %s", self.origin_dir)
            return False

        restored = False
        try:
            if os.path.isdir(origin_ioc):
                if os.path.isdir(self.ioc_dir):
                    shutil.rmtree(self.ioc_dir)
                shutil.copytree(origin_ioc, self.ioc_dir)
                logger.info("已从 origin 恢复 IoC 数据")
                restored = True

            if os.path.isdir(origin_wl):
                if os.path.isdir(self.whitelist_dir):
                    shutil.rmtree(self.whitelist_dir)
                shutil.copytree(origin_wl, self.whitelist_dir)
                logger.info("已从 origin 恢复 Whitelist 数据")
                restored = True
        except OSError as exc:
            logger.error("从 origin 恢复失败: %s", exc)
            return False

        return restored

    # ------------------------------------------------------------------
    # Display / Stats
    # ------------------------------------------------------------------

    def show(self, category: str = "all") -> str:
        """Return decoded plaintext data for debugging.

        Args:
            category: ``"all"``, ``"ioc"`` or ``"whitelist"``

        Returns:
            Formatted plaintext string.
        """
        if not self._loaded:
            self.load()

        parts: List[str] = []

        if category in ("all", "ioc"):
            parts.append("=== IoC Database ===")
            for type_name in sorted(self._ioc_data):
                values = self._ioc_data[type_name]
                parts.append(f"[{type_name}] ({len(values)} entries)")
                for val in sorted(values):
                    parts.append(f"  {val}")
            if not self._ioc_data:
                parts.append("  (empty)")

        if category in ("all", "whitelist"):
            parts.append("")
            parts.append("=== Whitelist Rules ===")
            for cat_name in sorted(self._whitelist_data):
                cat_data = self._whitelist_data[cat_name]
                if not isinstance(cat_data, dict):
                    continue
                entries = cat_data.get("entries", [])
                parts.append(f"[{cat_name}] ({len(entries)} entries)")
                for entry in entries:
                    eid = entry.get("id", "unknown")
                    analyzer = entry.get("analyzer", "")
                    field = entry.get("field", "")
                    pattern = entry.get("pattern", "")
                    parts.append(f"  {eid}: {analyzer} / {field} / {pattern}")
            if not self._whitelist_data:
                parts.append("  (empty)")

        return "\n".join(parts)

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics.

        Returns:
            ``{"ioc": {...}, "whitelist": {...}, "total_ioc": N, "total_whitelist": N}``
        """
        if not self._loaded:
            self.load()

        ioc_stats = {k: len(v) for k, v in self._ioc_data.items()}
        wl_stats = {}
        for cat_name, cat_data in self._whitelist_data.items():
            if isinstance(cat_data, dict):
                wl_stats[cat_name] = len(cat_data.get("entries", []))

        return {
            "ioc": ioc_stats,
            "whitelist": wl_stats,
            "total_ioc": sum(ioc_stats.values()),
            "total_whitelist": sum(wl_stats.values()),
        }

    # ------------------------------------------------------------------
    # IoC Whitelist Check & Add (Tasks 4 + 5)
    # ------------------------------------------------------------------

    def is_ioc_whitelisted(self, ioc_type: str, value: str) -> bool:
        """Check whether a given IoC value is whitelisted.

        Args:
            ioc_type: IoC type (domain, ip_port, url, hash).
            value: The IoC value to check (e.g. "evil.com", "10.0.0.1:8080").

        Returns:
            True if the value exists in the corresponding whitelist type file.
        """
        valid_types = {"domain", "ip_port", "url", "hash"}
        if ioc_type not in valid_types:
            logger.debug("Invalid ioc_type for whitelist check: %s", ioc_type)
            return False

        cat_name = f"ioc_{ioc_type}"
        cat_data = self._whitelist_data.get(cat_name)
        if not isinstance(cat_data, dict):
            return False

        for entry in cat_data.get("entries", []):
            if isinstance(entry, dict) and entry.get("value") == value:
                return True
        return False

    def add_ioc_whitelist(self, ioc_type: str, value: str, tag: str = "", reason: str = "") -> bool:
        """Add an IoC-type whitelist entry.

        Args:
            ioc_type: IoC type (domain, ip_port, url, hash).
            value: The whitelist value (e.g. "cdn.example.com", "10.0.0.1:8080").
            tag: Optional tag (e.g. "cdn", "internal").
            reason: Optional reason for whitelisting.

        Returns:
            True on success, False on invalid type or duplicate.

        Flow:
            1. Validate ioc_type.
            2. Check for duplicate entry.
            3. Append base64([tag]value) line to assets/whitelist/{ioc_type}.b64.
            4. Update in-memory data and manifest count.
        """
        valid_types = {"domain", "ip_port", "url", "hash"}
        if ioc_type not in valid_types:
            logger.warning("Invalid ioc_type for whitelist add: %s", ioc_type)
            return False

        # Check duplicate
        if self.is_ioc_whitelisted(ioc_type, value):
            logger.info("Duplicate whitelist entry skipped: %s/%s", ioc_type, value)
            return True  # idempotent

        cat_name = f"ioc_{ioc_type}"
        if cat_name not in self._whitelist_data:
            self._whitelist_data[cat_name] = {"entries": [], "type": ioc_type}

        entry = {"type": ioc_type, "value": value, "tag": tag, "source": "user"}
        if reason:
            entry["reason"] = reason
        self._whitelist_data[cat_name]["entries"].append(entry)

        # Persist to file
        filepath = os.path.join(self.whitelist_dir, f"{ioc_type}.b64")
        tagged = f"[{tag}]{value}" if tag else value
        encoded = base64.b64encode(tagged.encode("utf-8")).decode("ascii")
        with open(filepath, "a", encoding="utf-8") as fh:
            fh.write(encoded + "\n")

        logger.info("Added IoC whitelist: %s/%s (tag=%s)", ioc_type, value, tag)
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_b64_lines(filepath: str) -> Set[str]:
        """Decode a .b64 file where each line is a base64-encoded entry.

        Blank lines and lines starting with ``#`` are skipped.
        Supports both tagged (``[tag]value``) and plain value formats.
        """
        result: Set[str] = set()
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    decoded = base64.b64decode(line).decode("utf-8")
                    result.add(decoded)
                except ValueError as exc:
                    logger.debug("跳过无效 base64 行 in %s: %s", filepath, exc)
        return result

    @staticmethod
    def _decode_ioc_whitelist(filepath: str, ioc_type: str) -> List[dict]:
        """Decode an IoC-type whitelist .b64 file in [tag]value format.

        Each non-comment line is: base64([tag]value)
        Returns list of dicts with keys: type, value, tag, source.
        """
        result: List[dict] = []
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    decoded = base64.b64decode(line).decode("utf-8")
                    tag = ""
                    value = decoded
                    if decoded.startswith("[") and "]" in decoded:
                        bracket_end = decoded.index("]")
                        tag = decoded[1:bracket_end]
                        value = decoded[bracket_end + 1:]

                    result.append({
                        "type": ioc_type,
                        "value": value,
                        "tag": tag,
                        "source": "assets",
                    })
                except ValueError as exc:
                    logger.debug("跳过无效 base64 行 in %s: %s", filepath, exc)
        return result

    def _load_whitelist_b64(self, rules_path: str) -> Dict[str, Any]:
        """Load whitelist analyzer rules from a .b64 file.

        Format: each non-comment line is a base64-encoded JSON rule object.
        Lines starting with # are comments, empty lines are ignored.
        """
        with open(rules_path, "r", encoding="utf-8") as fh:
            raw = fh.read()

        stripped = raw.strip()
        if not stripped:
            return {}

        categories: Dict[str, Any] = {}
        for line in stripped.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rule_json = base64.b64decode(line).decode("utf-8")
                rule = json.loads(rule_json)
                cat_name = rule.pop("_category", "default")
                if cat_name not in categories:
                    categories[cat_name] = {"entries": []}
                categories[cat_name]["entries"].append(rule)
            except ValueError:
                continue
        return categories
# ======================================================================
# Module-level singleton
# ======================================================================

_instance: Optional[AssetManager] = None
_lock = threading.Lock()


def get_asset_manager(assets_dir: Optional[str] = None) -> AssetManager:
    """Return the AssetManager singleton (thread-safe, double-check locking).

    Args:
        assets_dir: Required on first call.  Subsequent calls may omit it.
    """
    global _instance
    if _instance is not None:
        return _instance

    with _lock:
        if _instance is not None:
            return _instance

        if assets_dir is None:
            from .path_resolver import get_asset_path
            assets_dir = get_asset_path()

        _instance = AssetManager(assets_dir)
    return _instance
