"""User-Defined Whitelist Configuration Loader

Supports multi-level configuration loading with priority:
1. Built-in whitelist (lowest priority)
2. Assets whitelist (ebpf-whitelist.json)
3. System-level user whitelist (/etc/sec-userspace/whitelist/)
4. Workspace-level user whitelist (./sec-userspace/whitelist/)
5. Override rules (highest priority)

This allows enterprise customers to add internal tools to whitelist
without modifying the codebase.
"""

import base64
import json
import os
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("sec-userspace")


# System-level whitelist directory
SYSTEM_WHITELIST_DIR = "/etc/sec-userspace/whitelist"

# Workspace-level whitelist directory (relative to workspace)
WORKSPACE_WHITELIST_DIR = "sec-userspace/whitelist"

# User whitelist file names
USER_WHITELIST_FILE = "user-whitelist.json"
OVERRIDE_RULES_FILE = "override-rules.json"
CUSTOM_PREFIXES_FILE = "custom-prefixes.json"


@dataclass
class UserWhitelistCategory:
    """User-defined whitelist category"""
    name: str
    tools: List[str] = field(default_factory=list)
    confidence_boost: float = 0.10
    description: str = ""
    created_by: str = ""
    created_at: str = ""


@dataclass
class TrustedPrefix:
    """Trusted prefix entry"""
    prefix: str
    reason: str
    created_by: str = ""
    created_at: str = ""


@dataclass
class OverrideRule:
    """Override rule for custom whitelist behavior"""
    id: str
    tool_pattern: str
    action: str  # "whitelist" | "blacklist" | "reduce_confidence"
    priority: int = 100
    reason: str = ""
    created_by: str = ""
    created_at: str = ""


@dataclass
class UserWhitelistConfig:
    """User whitelist configuration"""
    version: str = "1.0"
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""
    categories: Dict[str, UserWhitelistCategory] = field(default_factory=dict)
    trusted_prefixes: List[TrustedPrefix] = field(default_factory=list)
    override_rules: List[OverrideRule] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "version": self.version,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at or datetime.now(timezone.utc).isoformat(),
            "categories": {
                name: {
                    "tools": cat.tools,
                    "confidence_boost": cat.confidence_boost,
                    "description": cat.description,
                    "created_by": cat.created_by,
                    "created_at": cat.created_at
                }
                for name, cat in self.categories.items()
            },
            "trusted_prefixes": [
                {
                    "prefix": p.prefix,
                    "reason": p.reason,
                    "created_by": p.created_by,
                    "created_at": p.created_at
                }
                for p in self.trusted_prefixes
            ],
            "override_rules": [
                {
                    "id": r.id,
                    "tool_pattern": r.tool_pattern,
                    "action": r.action,
                    "priority": r.priority,
                    "reason": r.reason,
                    "created_by": r.created_by,
                    "created_at": r.created_at
                }
                for r in self.override_rules
            ]
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'UserWhitelistConfig':
        """Create from dictionary"""
        config = cls(
            version=data.get("version", "1.0"),
            created_by=data.get("created_by", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", "")
        )
        
        # Parse categories
        categories_data = data.get("categories", {})
        for name, cat_data in categories_data.items():
            config.categories[name] = UserWhitelistCategory(
                name=name,
                tools=cat_data.get("tools", []),
                confidence_boost=cat_data.get("confidence_boost", 0.10),
                description=cat_data.get("description", ""),
                created_by=cat_data.get("created_by", ""),
                created_at=cat_data.get("created_at", "")
            )
        
        # Parse trusted prefixes
        for prefix_data in data.get("trusted_prefixes", []):
            config.trusted_prefixes.append(TrustedPrefix(
                prefix=prefix_data.get("prefix", ""),
                reason=prefix_data.get("reason", ""),
                created_by=prefix_data.get("created_by", ""),
                created_at=prefix_data.get("created_at", "")
            ))
        
        # Parse override rules
        for rule_data in data.get("override_rules", []):
            config.override_rules.append(OverrideRule(
                id=rule_data.get("id", ""),
                tool_pattern=rule_data.get("tool_pattern", ""),
                action=rule_data.get("action", "whitelist"),
                priority=rule_data.get("priority", 100),
                reason=rule_data.get("reason", ""),
                created_by=rule_data.get("created_by", ""),
                created_at=rule_data.get("created_at", "")
            ))
        
        return config


class WhitelistLoader:
    """Multi-level whitelist configuration loader
    
    Loads whitelist configurations in priority order:
    1. Built-in whitelist (lowest)
    2. Assets whitelist
    3. System-level user whitelist
    4. Workspace-level user whitelist
    5. Override rules (highest)
    """
    
    def __init__(self, workspace_dir: str):
        """Initialize whitelist loader
        
        Args:
            workspace_dir: Workspace directory
        """
        self.workspace_dir = workspace_dir
        self.builtin_config: Optional[UserWhitelistConfig] = None
        self.assets_config: Optional[UserWhitelistConfig] = None
        self.system_user_config: Optional[UserWhitelistConfig] = None
        self.workspace_user_config: Optional[UserWhitelistConfig] = None
        self.override_config: Optional[UserWhitelistConfig] = None
        self.merged_config: Optional[UserWhitelistConfig] = None
        
        self._load_all()
    
    def _load_all(self) -> None:
        """Load all whitelist configurations"""
        logger.info("Loading multi-level whitelist configurations...")
        
        # 1. Load built-in whitelist (lowest priority)
        self._load_builtin()
        
        # 2. Load assets whitelist
        self._load_assets()
        
        # 3. Load system-level user whitelist
        self._load_system_user()
        
        # 4. Load workspace-level user whitelist
        self._load_workspace_user()
        
        # 5. Merge all configurations
        self._merge_configs()
        
        logger.info(f"Whitelist loader initialized: "
                   f"builtin={len(self.builtin_config.categories) if self.builtin_config else 0} categories, "
                   f"assets={len(self.assets_config.categories) if self.assets_config else 0} categories, "
                   f"system_user={len(self.system_user_config.categories) if self.system_user_config else 0} categories, "
                   f"workspace_user={len(self.workspace_user_config.categories) if self.workspace_user_config else 0} categories, "
                   f"overrides={len(self.override_config.override_rules) if self.override_config else 0} rules")
    
    def _load_builtin(self) -> None:
        """Load built-in whitelist (hardcoded defaults)"""
        # For now, use empty built-in config
        # Built-in FP patterns are handled by whitelist.py BUILTIN_FP_PATTERNS
        self.builtin_config = UserWhitelistConfig(
            version="1.0",
            created_by="sec-userspace",
            created_at=datetime.now(timezone.utc).isoformat(),
            categories={}
        )
        logger.debug("Loaded built-in whitelist configuration")
    
    def _load_assets(self) -> None:
        """Load assets whitelist from assets/whitelist/ using new multi-file format.

        Reads manifest.json to discover type files, then loads each:
          - IoC types (domain, ip_port, url, hash): [tag]value format
          - analyzer_rules: base64-encoded JSON objects (legacy format preserved)

        Falls back to legacy multi-file JSON format if manifest.json does not exist.
        """
        from .path_resolver import get_asset_path
        manifest_path = get_asset_path("whitelist", "manifest.json")

        if not os.path.isfile(manifest_path):
            # No manifest: fall back to legacy format
            self._load_assets_legacy()
            return

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            types_dict = manifest.get("types", {})
            if not types_dict:
                logger.warning("manifest.json has empty types dict, falling back to legacy")
                self._load_assets_legacy()
                return

            merged_categories: Dict[str, UserWhitelistCategory] = {}
            merged_prefixes: List[TrustedPrefix] = []
            total_rules = 0

            # IoC types that use [tag]value format
            ioc_types = {"domain", "ip_port", "url", "hash"}

            for type_name, type_info in types_dict.items():
                filename = type_info.get("file", "")
                if not filename:
                    continue

                filepath = get_asset_path("whitelist", filename)
                if not os.path.isfile(filepath):
                    logger.debug("Whitelist type file not found: %s, skipping", filepath)
                    continue

                if type_name in ioc_types:
                    # IoC-type: load [tag]value format
                    entries = self._load_tagged_b64_file(filepath, type_name)
                    # Convert to category entries
                    if entries:
                        cat_data = {"entries": entries}
                        file_config = self._convert_assets_format(cat_data)
                        merged_categories.update(file_config.categories)
                        merged_prefixes.extend(file_config.trusted_prefixes)
                        total_rules += len(entries)
                elif type_name == "analyzer_rules":
                    # Analyzer rules: base64-encoded JSON objects
                    rules = self._load_rules_b64_file(filepath)
                    cat_entries: Dict[str, list] = {}
                    for rule in rules:
                        cat_name = rule.pop("_category", "default")
                        cat_entries.setdefault(cat_name, []).append(rule)

                    for cat_name, entries in cat_entries.items():
                        cat_data = {"entries": entries}
                        file_config = self._convert_assets_format(cat_data)
                        merged_categories.update(file_config.categories)
                        merged_prefixes.extend(file_config.trusted_prefixes)
                    total_rules += len(rules)
                else:
                    logger.warning("Unknown whitelist type: %s, skipping", type_name)

            self.assets_config = UserWhitelistConfig(
                version="merged-assets-v5",
                created_by="sec-userspace-assets",
                created_at=datetime.now(timezone.utc).isoformat(),
                categories=merged_categories,
                trusted_prefixes=merged_prefixes,
            )
            logger.debug("Loaded assets whitelist from manifest (%d categories, %d rules)",
                        len(merged_categories), total_rules)
        except (OSError, ValueError) as e:
            logger.warning("Failed to load manifest, falling back to legacy: %s", e)
            self._load_assets_legacy()

    def _load_tagged_b64_file(self, filepath: str, type_name: str) -> List[dict]:
        """Load IoC-type whitelist entries from a [tag]value format .b64 file.

        Each non-comment line is: base64([tag]value)
        Returns list of dicts with keys: type, value, tag, source.
        """
        entries: List[dict] = []
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        decoded = base64.b64decode(line).decode("utf-8")
                        # Parse [tag]value format
                        tag = ""
                        value = decoded
                        if decoded.startswith("[") and "]" in decoded:
                            bracket_end = decoded.index("]")
                            tag = decoded[1:bracket_end]
                            value = decoded[bracket_end + 1:]

                        entries.append({
                            "type": type_name,
                            "value": value,
                            "tag": tag,
                            "source": "assets",
                        })
                    except ValueError:
                        continue  # skip malformed lines
        except OSError:
            pass
        return entries

    @staticmethod
    def _load_rules_b64_file(rules_path: str) -> List[dict]:
        """Load whitelist analyzer rules from a .b64 file.

        Format: each non-comment line is a base64-encoded JSON rule object.
        Lines starting with # are comments, empty lines are ignored.

        Returns:
            List of rule dicts (each rule has '_category' key preserved if present).
        """
        with open(rules_path, "r", encoding="utf-8") as fh:
            raw = fh.read()

        stripped = raw.strip()
        if not stripped:
            return []

        rules: List[dict] = []
        for line in stripped.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rule_json = base64.b64decode(line).decode("utf-8")
                rule = json.loads(rule_json)
                rules.append(rule)
            except ValueError:
                continue  # skip malformed lines
        return rules

    def _load_assets_legacy(self) -> None:
        """Load assets whitelist from legacy multi-file JSON format.

        Iterates over assets/whitelist/*.json (excluding manifest.json).
        """
        from .path_resolver import get_asset_path
        assets_dir = get_asset_path("whitelist")

        if not os.path.isdir(assets_dir):
            logger.debug("Assets whitelist directory not found: %s", assets_dir)
            self.assets_config = UserWhitelistConfig()
            return

        merged_categories: Dict[str, UserWhitelistCategory] = {}
        merged_prefixes: List[TrustedPrefix] = []
        for filename in sorted(os.listdir(assets_dir)):
            if not filename.endswith(".json") or filename == "manifest.json":
                continue
            filepath = os.path.join(assets_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    file_data = json.load(f)
                file_config = self._convert_assets_format(file_data)
                merged_categories.update(file_config.categories)
                merged_prefixes.extend(file_config.trusted_prefixes)
                logger.debug("Loaded assets whitelist: %s", filename)
            except (OSError, ValueError) as e:
                logger.warning("Failed to load assets whitelist %s: %s", filename, e)

        self.assets_config = UserWhitelistConfig(
            version="merged-assets",
            created_by="sec-userspace-assets",
            created_at=datetime.now(timezone.utc).isoformat(),
            categories=merged_categories,
            trusted_prefixes=merged_prefixes,
        )
        logger.debug("Loaded assets whitelist (legacy) from %s", assets_dir)
    
    def _convert_assets_format(self, data: dict) -> UserWhitelistConfig:
        """Convert asset category data to UserWhitelistConfig.

        The format has 'entries' (list of entry dicts) instead of 'categories'.

        Args:
            data: Category data dict (may contain 'categories', 'entries',
                  'tools', 'trusted_prefixes', etc.)

        Returns:
            UserWhitelistConfig object
        """
        config = UserWhitelistConfig(
            version=data.get("version", "1.0"),
            created_by="sec-userspace-assets",
            created_at=data.get("last_updated", datetime.now(timezone.utc).isoformat())
        )

        # New format: entries list inside a category
        entries = data.get("entries", [])
        if entries and isinstance(entries, list):
            # Extract tools from entries
            tools = []
            for entry in entries:
                if isinstance(entry, dict):
                    # Support various entry formats
                    tool = entry.get("tool") or entry.get("pattern") or entry.get("name", "")
                    if tool:
                        tools.append(tool)
                elif isinstance(entry, str):
                    tools.append(entry)
            if tools:
                cat_name = data.get("name", data.get("description", "assets"))
                config.categories[cat_name] = UserWhitelistCategory(
                    name=cat_name,
                    tools=tools,
                    confidence_boost=data.get("confidence_boost", 0.10),
                    description=data.get("description", "")
                )

        # Legacy format: categories dict
        categories_data = data.get("categories", {})
        for cat_name, cat_data in categories_data.items():
            config.categories[cat_name] = UserWhitelistCategory(
                name=cat_name,
                tools=cat_data.get("tools", []),
                confidence_boost=cat_data.get("confidence_boost", 0.10),
                description=cat_data.get("description", "")
            )

        # Direct tools list (simple format)
        direct_tools = data.get("tools", [])
        if direct_tools and not entries and not categories_data:
            cat_name = data.get("name", "default")
            config.categories[cat_name] = UserWhitelistCategory(
                name=cat_name,
                tools=direct_tools,
                confidence_boost=data.get("confidence_boost", 0.10),
                description=data.get("description", "")
            )

        # Convert trusted prefixes
        for prefix_data in data.get("trusted_prefixes", []):
            config.trusted_prefixes.append(TrustedPrefix(
                prefix=prefix_data.get("prefix", ""),
                reason=prefix_data.get("reason", "")
            ))

        return config
    
    def _load_system_user(self) -> None:
        """Load system-level user whitelist from /etc/sec-userspace/whitelist/"""
        self.system_user_config = self._load_user_directory(SYSTEM_WHITELIST_DIR)
        if self.system_user_config:
            logger.debug(f"Loaded system-level user whitelist from {SYSTEM_WHITELIST_DIR}")
        else:
            logger.debug("No system-level user whitelist found")
    
    def _load_workspace_user(self) -> None:
        """Load workspace-level user whitelist from ./sec-userspace/whitelist/"""
        workspace_whitelist_dir = os.path.join(self.workspace_dir, "whitelist")
        self.workspace_user_config = self._load_user_directory(workspace_whitelist_dir)
        if self.workspace_user_config:
            logger.debug(f"Loaded workspace-level user whitelist from {workspace_whitelist_dir}")
        else:
            logger.debug("No workspace-level user whitelist found")
    
    def _load_user_directory(self, directory: str) -> Optional[UserWhitelistConfig]:
        """Load user whitelist from specified directory
        
        Args:
            directory: Directory path containing user whitelist files
        
        Returns:
            UserWhitelistConfig or None if not found
        """
        if not os.path.exists(directory):
            return None
        
        config = UserWhitelistConfig()
        
        # Load user-whitelist.json
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        if os.path.exists(user_whitelist_path):
            try:
                with open(user_whitelist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                user_config = UserWhitelistConfig.from_dict(data)
                config.categories.update(user_config.categories)
                config.trusted_prefixes.extend(user_config.trusted_prefixes)
                logger.debug(f"Loaded {user_whitelist_path}")
            except (OSError, KeyError, TypeError, ValueError) as e:
                logger.warning(f"Failed to load {user_whitelist_path}: {e}")
        
        # Load override-rules.json
        override_path = os.path.join(directory, OVERRIDE_RULES_FILE)
        if os.path.exists(override_path):
            try:
                with open(override_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                override_config = UserWhitelistConfig.from_dict(data)
                config.override_rules.extend(override_config.override_rules)
                logger.debug(f"Loaded {override_path}")
            except (OSError, KeyError, TypeError, ValueError) as e:
                logger.warning(f"Failed to load {override_path}: {e}")
        
        # Load custom-prefixes.json
        prefixes_path = os.path.join(directory, CUSTOM_PREFIXES_FILE)
        if os.path.exists(prefixes_path):
            try:
                with open(prefixes_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                prefix_config = UserWhitelistConfig.from_dict(data)
                config.trusted_prefixes.extend(prefix_config.trusted_prefixes)
                logger.debug(f"Loaded {prefixes_path}")
            except (OSError, KeyError, TypeError, ValueError) as e:
                logger.warning(f"Failed to load {prefixes_path}: {e}")
        
        # Return None if no configuration loaded
        if not config.categories and not config.trusted_prefixes and not config.override_rules:
            return None
        
        return config
    
    def _load_learned_fp(self) -> Optional[UserWhitelistConfig]:
        """Load learned false positive entries from FPAutoLearner.
        
        Tries to load learned-fp.json from:
        1. /etc/sec-userspace/learned-fp.json (system level)
        2. {workspace_dir}/learned-fp.json (workspace level)
        
        Converts learned FP entries into a UserWhitelistConfig with
        a special 'learned_false_positives' category.
        
        Returns:
            UserWhitelistConfig with learned FP entries, or None
        """
        learned_paths = [
            "/etc/sec-userspace/learned-fp.json",
            os.path.join(self.workspace_dir, "learned-fp.json"),
        ]
        
        for fp_path in learned_paths:
            if not os.path.exists(fp_path):
                continue
            try:
                with open(fp_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                entries = data.get("entries", [])
                if not entries:
                    continue
                
                # Convert learned FP entries to whitelist tools list
                tools = []
                for entry in entries:
                    if not entry.get("enabled", True):
                        continue
                    pattern = entry.get("pattern", "")
                    if pattern:
                        tools.append(pattern)
                
                if not tools:
                    continue
                
                config = UserWhitelistConfig(
                    version="learned-fp-1.0",
                    created_by="fp-auto-learner",
                    created_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
                )
                config.categories["learned_false_positives"] = UserWhitelistCategory(
                    name="learned_false_positives",
                    tools=tools,
                    confidence_boost=0.15,
                    description="Auto-learned false positive patterns",
                )
                logger.debug("Loaded %d learned FP entries from %s", len(tools), fp_path)
                return config
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load learned FP file %s: %s", fp_path, e)
        
        return None

    def _merge_configs(self) -> None:
        """Merge all configurations with priority"""
        self.merged_config = UserWhitelistConfig(
            version="merged-1.0",
            created_by="sec-userspace-loader",
            created_at=datetime.now(timezone.utc).isoformat()
        )
        
        # Load learned FP entries
        learned_fp_config = self._load_learned_fp()
        
        # Priority order: builtin < assets < learned_fp < system_user < workspace_user < overrides
        configs = [
            self.builtin_config,
            self.assets_config,
            learned_fp_config,
            self.system_user_config,
            self.workspace_user_config,
        ]
        
        # Merge categories (later configs override earlier ones)
        for config in configs:
            if not config:
                continue
            for cat_name, category in config.categories.items():
                # Deep merge: tools are combined, confidence_boost uses highest value
                if cat_name in self.merged_config.categories:
                    existing = self.merged_config.categories[cat_name]
                    # Combine tools (unique)
                    existing.tools = list(set(existing.tools + category.tools))
                    # Use highest confidence_boost
                    existing.confidence_boost = max(
                        existing.confidence_boost, 
                        category.confidence_boost
                    )
                else:
                    self.merged_config.categories[cat_name] = category
        
        # Merge trusted prefixes (all combined)
        for config in configs:
            if not config:
                continue
            self.merged_config.trusted_prefixes.extend(config.trusted_prefixes)
        
        # Merge override rules (all combined)
        for config in configs:
            if not config:
                continue
            self.merged_config.override_rules.extend(config.override_rules)
        
        logger.debug(f"Merged whitelist: {len(self.merged_config.categories)} categories, "
                    f"{len(self.merged_config.trusted_prefixes)} trusted prefixes, "
                    f"{len(self.merged_config.override_rules)} override rules")
    
    def get_all_tools(self) -> List[str]:
        """Get all whitelisted tools across all categories
        
        Returns:
            List of tool names
        """
        if not self.merged_config:
            return []
        
        tools = []
        for category in self.merged_config.categories.values():
            tools.extend(category.tools)
        
        return list(set(tools))
    
    def get_categories(self) -> Dict[str, UserWhitelistCategory]:
        """Get all categories
        
        Returns:
            Dictionary of category name to category
        """
        return self.merged_config.categories if self.merged_config else {}
    
    def get_trusted_prefixes(self) -> List[TrustedPrefix]:
        """Get all trusted prefixes
        
        Returns:
            List of trusted prefixes
        """
        return self.merged_config.trusted_prefixes if self.merged_config else []
    
    def get_override_rules(self) -> List[OverrideRule]:
        """Get all override rules
        
        Returns:
            List of override rules
        """
        return self.merged_config.override_rules if self.merged_config else []
    
    def is_tool_whitelisted(self, tool_name: str) -> bool:
        """Check if a tool is whitelisted
        
        Args:
            tool_name: Tool name to check
        
        Returns:
            True if whitelisted
        """
        return tool_name in self.get_all_tools()
    
    def matches_trusted_prefix(self, value: str) -> Optional[TrustedPrefix]:
        """Check if a value matches a trusted prefix
        
        Args:
            value: Value to check
        
        Returns:
            Matching TrustedPrefix or None
        """
        for prefix in self.get_trusted_prefixes():
            if value.startswith(prefix.prefix):
                return prefix
        return None
    
    def save_user_config(self, config: UserWhitelistConfig, level: str = "workspace") -> str:
        """Save user configuration
        
        Args:
            config: Configuration to save
            level: "system" or "workspace"
        
        Returns:
            Path where configuration was saved
        """
        if level == "system":
            directory = SYSTEM_WHITELIST_DIR
        else:
            directory = os.path.join(self.workspace_dir, "whitelist")
        
        # Ensure directory exists
        os.makedirs(directory, exist_ok=True)
        
        # Save user-whitelist.json
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        with open(user_whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved user whitelist to {user_whitelist_path}")
        return user_whitelist_path
    
    def merge_remote_whitelist(self, remote_data: dict) -> dict:
        """Merge remote whitelist data from sec-server.

        Args:
            remote_data: Remote whitelist payload, expected structure:
                {"categories": {"default": {"entries": [...]}, ...}}

        Returns:
            Incremental statistics: {"<category_name>": <new_entries_count>, ...}
        """
        if not self.merged_config:
            self.merged_config = UserWhitelistConfig()

        stats: Dict[str, int] = {}
        categories = remote_data.get("categories", {})
        for cat_name, cat_data in categories.items():
            remote_config = self._convert_assets_format(cat_data)
            for rc_name, rc_cat in remote_config.categories.items():
                if rc_name in self.merged_config.categories:
                    existing = self.merged_config.categories[rc_name]
                    old_count = len(existing.tools)
                    existing.tools = list(set(existing.tools + rc_cat.tools))
                    new_count = len(existing.tools) - old_count
                    existing.confidence_boost = max(
                        existing.confidence_boost, rc_cat.confidence_boost
                    )
                else:
                    self.merged_config.categories[rc_name] = rc_cat
                    new_count = len(rc_cat.tools)
                stats[rc_name] = stats.get(rc_name, 0) + new_count

        logger.debug("Merged remote whitelist: %s", stats)
        return stats

    def validate_config(self, config: dict) -> Tuple[bool, str]:
        """Validate user configuration
        
        Args:
            config: Configuration dictionary to validate
        
        Returns:
            (is_valid, error_message)
        """
        try:
            # Check required fields
            if not isinstance(config, dict):
                return False, "Configuration must be a dictionary"
            
            # Validate categories
            categories = config.get("categories", {})
            if not isinstance(categories, dict):
                return False, "'categories' must be a dictionary"
            
            for cat_name, cat_data in categories.items():
                if not isinstance(cat_data, dict):
                    return False, f"Category '{cat_name}' must be a dictionary"
                
                if "tools" not in cat_data:
                    return False, f"Category '{cat_name}' missing required field 'tools'"
                
                if not isinstance(cat_data["tools"], list):
                    return False, f"Category '{cat_name}' tools must be a list"
                
                if "confidence_boost" in cat_data:
                    boost = cat_data["confidence_boost"]
                    if not isinstance(boost, (int, float)) or not (0 <= boost <= 1):
                        return False, f"Category '{cat_name}' confidence_boost must be between 0 and 1"
            
            # Validate trusted_prefixes
            prefixes = config.get("trusted_prefixes", [])
            if not isinstance(prefixes, list):
                return False, "'trusted_prefixes' must be a list"
            
            for i, prefix in enumerate(prefixes):
                if not isinstance(prefix, dict):
                    return False, f"Trusted prefix {i} must be a dictionary"
                if "prefix" not in prefix or "reason" not in prefix:
                    return False, f"Trusted prefix {i} missing required fields"
            
            # Validate override_rules
            overrides = config.get("override_rules", [])
            if not isinstance(overrides, list):
                return False, "'override_rules' must be a list"
            
            for i, rule in enumerate(overrides):
                if not isinstance(rule, dict):
                    return False, f"Override rule {i} must be a dictionary"
                if "id" not in rule or "tool_pattern" not in rule or "action" not in rule:
                    return False, f"Override rule {i} missing required fields"
                if rule.get("action") not in ["whitelist", "blacklist", "reduce_confidence"]:
                    return False, f"Override rule {i} invalid action: {rule.get('action')}"
            
            return True, ""
            
        except (TypeError, KeyError, ValueError) as e:
            return False, f"Validation error: {e}"


# Global singleton (lazy initialization)
_whitelist_loader: Optional[WhitelistLoader] = None
_whitelist_loader_lock = threading.Lock()


def get_whitelist_loader(workspace_dir: str) -> WhitelistLoader:
    """Get whitelist loader singleton

    Args:
        workspace_dir: Workspace directory

    Returns:
        WhitelistLoader instance
    """
    global _whitelist_loader

    if _whitelist_loader is None:
        with _whitelist_loader_lock:
            if _whitelist_loader is None:
                _whitelist_loader = WhitelistLoader(workspace_dir)

    return _whitelist_loader


def reset_whitelist_loader() -> None:
    """Reset whitelist loader singleton (for testing)"""
    global _whitelist_loader
    with _whitelist_loader_lock:
        _whitelist_loader = None
