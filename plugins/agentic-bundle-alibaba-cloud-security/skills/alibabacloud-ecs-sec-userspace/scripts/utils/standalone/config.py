"""Configuration Management Module."""

import os
import logging
import yaml
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


logger = logging.getLogger("sec-userspace")


CONFIG_DIR = Path.home() / ".sec-userspace"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


@dataclass
class APIConfig:
    """API configuration."""
    provider: str = "bailian"
    model: str = "qwen-max"
    api_key: Optional[str] = None
    base_url: Optional[str] = None

    def get_base_url(self) -> str:
        """Get base URL for the API provider."""
        if self.base_url:
            return self.base_url

        urls = {
            "bailian": "https://bailian.aliyuncs.com/v1",
            "openai": "https://api.openai.com/v1",
            "anthropic": "https://api.anthropic.com",
            "deepseek": "https://api.deepseek.com/v1",
        }
        return urls.get(self.provider, "")


@dataclass
class SkillAnalyzerThresholds:
    """Skill analyzer detection thresholds."""
    unicode_density_medium: float = 1.0   # 1% threshold for MEDIUM severity
    unicode_density_high: float = 5.0     # 5% threshold for HIGH severity

    def validate(self) -> bool:
        """Validate threshold values are within acceptable range."""
        if self.unicode_density_medium < 0 or self.unicode_density_medium > 100:
            return False
        if self.unicode_density_high < 0 or self.unicode_density_high > 100:
            return False
        if self.unicode_density_medium >= self.unicode_density_high:
            return False
        return True


@dataclass
class SkillConfig:
    """Skill configuration."""
    auto_install: bool = True
    auto_detect: bool = True
    thresholds: SkillAnalyzerThresholds = field(default_factory=SkillAnalyzerThresholds)


@dataclass
class ToolsConfig:
    """Tools configuration."""
    preferred: Optional[str] = None


@dataclass
class Config:
    """Main configuration class."""
    api: APIConfig = field(default_factory=APIConfig)
    skill: SkillConfig = field(default_factory=SkillConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        config = cls()

        api_key = os.environ.get("SEC_INSPECT_API_KEY")
        if api_key:
            config.api.api_key = api_key

        provider = os.environ.get("SEC_INSPECT_PROVIDER")
        if provider:
            config.api.provider = provider

        model = os.environ.get("SEC_INSPECT_MODEL")
        if model:
            config.api.model = model

        base_url = os.environ.get("SEC_INSPECT_BASE_URL")
        if base_url:
            config.api.base_url = base_url

        # Load skill analyzer thresholds from environment
        try:
            medium_val = os.environ.get("SKILL_UNICODE_DENSITY_MEDIUM")
            if medium_val is not None:
                val = float(medium_val)
                if 0 <= val <= 100:
                    config.skill.thresholds.unicode_density_medium = val
                else:
                    logger.warning(
                        f"Invalid config value for SKILL_UNICODE_DENSITY_MEDIUM: {val}. "
                        f"Must be between 0 and 100. Using default: 1.0"
                    )
        except (ValueError, TypeError):
            logger.warning(
                f"Invalid config value for SKILL_UNICODE_DENSITY_MEDIUM: {medium_val}. "
                f"Must be a valid number. Using default: 1.0"
            )

        try:
            high_val = os.environ.get("SKILL_UNICODE_DENSITY_HIGH")
            if high_val is not None:
                val = float(high_val)
                if 0 <= val <= 100:
                    config.skill.thresholds.unicode_density_high = val
                else:
                    logger.warning(
                        f"Invalid config value for SKILL_UNICODE_DENSITY_HIGH: {val}. "
                        f"Must be between 0 and 100. Using default: 5.0"
                    )
        except (ValueError, TypeError):
            logger.warning(
                f"Invalid config value for SKILL_UNICODE_DENSITY_HIGH: {high_val}. "
                f"Must be a valid number. Using default: 5.0"
            )

        return config

    @classmethod
    def from_file(cls, config_path: Path = CONFIG_FILE) -> "Config":
        """Load configuration from file."""
        config = cls()

        if not config_path.exists():
            return config

        try:
            with open(config_path, "r", encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                return config

            if "api" in data:
                api_data = data["api"]
                config.api.provider = api_data.get("provider", "bailian")
                config.api.model = api_data.get("model", "qwen-max")
                config.api.api_key = api_data.get("api_key")
                config.api.base_url = api_data.get("base_url")

            if "skill" in data:
                skill_data = data["skill"]
                config.skill.auto_install = skill_data.get("auto_install", True)
                config.skill.auto_detect = skill_data.get("auto_detect", True)

                # Load skill analyzer thresholds if present
                if "thresholds" in skill_data:
                    threshold_data = skill_data["thresholds"]
                    if "unicode_density_medium" in threshold_data:
                        try:
                            val = float(threshold_data["unicode_density_medium"])
                            if 0 <= val <= 100:
                                config.skill.thresholds.unicode_density_medium = val
                            else:
                                logger.warning(
                                    f"Invalid config value for unicode_density_medium: {val}. "
                                    f"Must be between 0 and 100. Using default: 1.0"
                                )
                        except (ValueError, TypeError):
                            logger.warning(
                                f"Invalid config value for unicode_density_medium: {threshold_data['unicode_density_medium']}. "
                                f"Must be a valid number. Using default: 1.0"
                            )
                    if "unicode_density_high" in threshold_data:
                        try:
                            val = float(threshold_data["unicode_density_high"])
                            if 0 <= val <= 100:
                                config.skill.thresholds.unicode_density_high = val
                            else:
                                logger.warning(
                                    f"Invalid config value for unicode_density_high: {val}. "
                                    f"Must be between 0 and 100. Using default: 5.0"
                                )
                        except (ValueError, TypeError):
                            logger.warning(
                                f"Invalid config value for unicode_density_high: {threshold_data['unicode_density_high']}. "
                                f"Must be a valid number. Using default: 5.0"
                            )

            if "tools" in data:
                tools_data = data["tools"]
                config.tools.preferred = tools_data.get("preferred")

        except (yaml.YAMLError, OSError):
            pass

        return config

    def save(self, config_path: Path = CONFIG_FILE) -> None:
        """Save configuration to file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "api": {
                "provider": self.api.provider,
                "model": self.api.model,
                "api_key": self.api.api_key,
                "base_url": self.api.base_url,
            },
            "skill": {
                "auto_install": self.skill.auto_install,
                "auto_detect": self.skill.auto_detect,
                "thresholds": {
                    "unicode_density_medium": self.skill.thresholds.unicode_density_medium,
                    "unicode_density_high": self.skill.thresholds.unicode_density_high,
                },
            },
            "tools": {
                "preferred": self.tools.preferred,
            },
        }

        with open(config_path, "w", encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False)

    def merge_with_env(self) -> "Config":
        """Merge file config with environment variables (env takes priority)."""
        env_config = self.from_env()

        if env_config.api.api_key:
            self.api.api_key = env_config.api.api_key
        if env_config.api.provider != "bailian":
            self.api.provider = env_config.api.provider
        if env_config.api.model != "qwen-max":
            self.api.model = env_config.api.model
        if env_config.api.base_url:
            self.api.base_url = env_config.api.base_url

        # Merge skill analyzer thresholds (env overrides file)
        if env_config.skill.thresholds.unicode_density_medium != 1.0:
            self.skill.thresholds.unicode_density_medium = env_config.skill.thresholds.unicode_density_medium
        if env_config.skill.thresholds.unicode_density_high != 5.0:
            self.skill.thresholds.unicode_density_high = env_config.skill.thresholds.unicode_density_high

        return self


def load_config() -> Config:
    """Load configuration from file and environment."""
    config = Config.from_file()
    merged_config = config.merge_with_env()

    # Log configuration summary at DEBUG level
    logger.debug(
        f"Configuration loaded:\n"
        f"  - Skill analyzer thresholds: MEDIUM={merged_config.skill.thresholds.unicode_density_medium}%, "
        f"HIGH={merged_config.skill.thresholds.unicode_density_high}%\n"
        f"  - Source: environment variables (overrides config file)"
    )

    return merged_config


def is_configured() -> bool:
    """Check if configuration exists and has API key."""
    config = load_config()
    return bool(config.api.api_key)
