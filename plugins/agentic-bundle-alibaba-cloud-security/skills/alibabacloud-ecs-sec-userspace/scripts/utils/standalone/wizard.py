"""Interactive Wizard for First-Time Setup."""

import getpass
from typing import Optional
from .config import Config


PROVIDERS = {
    "1": {"name": "Bailian (Aliyun)", "default_model": "qwen-max"},
    "2": {"name": "OpenAI", "default_model": "gpt-4o"},
    "3": {"name": "Anthropic (Claude)", "default_model": "claude-3-sonnet-20240229"},
    "4": {"name": "DeepSeek", "default_model": "deepseek-chat"},
}

BALIAN_MODELS = ["qwen-max", "qwen-plus", "qwen-turbo"]
OPENAI_MODELS = ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]
ANTHROPIC_MODELS = ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"]
DEEPSEEK_MODELS = ["deepseek-chat", "deepseek-coder"]


def print_banner():
    """Print welcome banner."""
    print()
    print("=" * 60)
    print("           sec-userspace - Linux Security Detection Tool")
    print("=" * 60)
    print()


def select_provider() -> str:
    """Select API provider."""
    print("Please select API provider:")
    for key, value in PROVIDERS.items():
        print(f"  {key}. {value['name']}")
    print()

    while True:
        choice = input("Enter option [1-4]: ").strip()
        if choice in PROVIDERS:
            return choice
        print("Invalid option, please try again.")


def get_api_key(provider: str) -> str:
    """Get API key from user."""
    provider_name = PROVIDERS[provider]["name"]
    print()
    print(f"Please enter API Key for {provider_name}:")
    print("(Input will be hidden)")
    print()

    while True:
        api_key = getpass.getpass("API Key: ")
        if api_key.strip():
            return api_key.strip()
        print("API Key cannot be empty, please try again.")


def select_model(provider: str) -> str:
    """Select model for the provider."""
    if provider == "1":
        models = BALIAN_MODELS
    elif provider == "2":
        models = OPENAI_MODELS
    elif provider == "3":
        models = ANTHROPIC_MODELS
    elif provider == "4":
        models = DEEPSEEK_MODELS
    else:
        models = []

    print()
    print("Please select model:")
    for i, model in enumerate(models, 1):
        recommended = " (Recommended)" if i == 1 else ""
        print(f"  {i}. {model}{recommended}")
    print()

    while True:
        choice = input(f"Enter option [1-{len(models)}]: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                return models[idx]
        except ValueError:
            pass
        print("Invalid option, please try again.")


def configure_base_url(provider: str) -> Optional[str]:
    """Configure custom base URL."""
    print()
    print("Do you want to configure a custom API base URL?")
    choice = input("Default URL will be used if skipped [y/N]: ").strip().lower()

    if choice in ["y", "yes"]:
        url = input("Enter base URL: ").strip()
        return url if url else None
    return None


def run_wizard() -> Config:
    """Run the interactive setup wizard."""
    print_banner()

    print("[INFO] This is your first time running sec-userspace.")
    print("[INFO] Let's configure your API settings.\n")

    # Select provider
    provider_choice = select_provider()
    provider_map = {
        "1": "bailian",
        "2": "openai",
        "3": "anthropic",
        "4": "deepseek",
    }
    provider = provider_map[provider_choice]
    PROVIDERS[provider_choice]["default_model"]

    # Get API key
    api_key = get_api_key(provider_choice)

    # Select model
    model = select_model(provider_choice)

    # Configure base URL
    base_url = configure_base_url(provider_choice)

    # Create config
    config = Config()
    config.api.provider = provider
    config.api.model = model
    config.api.api_key = api_key
    config.api.base_url = base_url

    # Save config
    config.save()

    print()
    print("=" * 60)
    print("[INFO] Configuration saved to ~/.sec-userspace/config.yaml")
    print("[INFO] You can reconfigure at any time with --configure option")
    print("=" * 60)
    print()

    return config


def quick_configure(
    provider: str = "bailian",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Config:
    """Quick configuration without interactive prompts."""
    config = Config()
    config.api.provider = provider
    config.api.model = model or PROVIDERS.get(
        {"bailian": "1", "openai": "2", "anthropic": "3", "deepseek": "4"}.get(
            provider, "1"
        ),
        {}).get("default_model", "qwen-max")
    config.api.api_key = api_key
    config.api.base_url = base_url

    if api_key:
        config.save()

    return config
