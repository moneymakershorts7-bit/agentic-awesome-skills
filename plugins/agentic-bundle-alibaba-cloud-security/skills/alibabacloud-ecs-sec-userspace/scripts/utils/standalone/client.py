"""Built-in Interactive Client."""

import subprocess
from pathlib import Path
from typing import Optional

from .config import Config
from .llm import LLMClient, BailianClient, OpenAIClient, AnthropicClient


def get_skill_path() -> str:
    """Get the path to sec-userspace skill directory."""
    current_file = Path(__file__).resolve()
    scripts_dir = current_file.parent.parent
    return str(scripts_dir)


class StandaloneClient:
    """Built-in interactive client for sec-userspace."""

    def __init__(self, config: Config):
        self.config = config
        self.llm: Optional[LLMClient] = None
        self.skill_installed = False
        self._init_llm()

    def _init_llm(self):
        """Initialize LLM client based on configuration."""
        provider = self.config.api.provider
        api_key = self.config.api.api_key
        model = self.config.api.model
        base_url = self.config.api.get_base_url()

        if not api_key:
            raise ValueError("API key is required")

        if provider == "bailian":
            self.llm = BailianClient(
                api_key=api_key,
                model=model or "qwen-max",
                base_url=base_url
            )
        elif provider == "openai":
            self.llm = OpenAIClient(
                api_key=api_key,
                model=model or "gpt-4o",
                base_url=base_url
            )
        elif provider == "anthropic":
            self.llm = AnthropicClient(
                api_key=api_key,
                model=model or "claude-3-sonnet-20240229",
                base_url=base_url
            )
        elif provider == "deepseek":
            self.llm = OpenAIClient(
                api_key=api_key,
                model=model or "deepseek-chat",
                base_url=base_url or "https://api.deepseek.com/v1"
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def test_connection(self) -> bool:
        """Test connection to LLM API."""
        try:
            response = self.llm.simple_chat("Hello, are you there?")
            return bool(response)
        except (OSError, ValueError, RuntimeError) as e:
            print(f"[ERROR] Connection test failed: {e}")
            return False

    def install_skill(self) -> bool:
        """
        Install sec-userspace skill.

        In standalone mode, the skill is already part of the codebase,
        so we just need to verify it exists.
        """
        skill_path = get_skill_path()
        skill_file = Path(skill_path) / "SKILL.md"

        if not skill_file.exists():
            print(f"[ERROR] SKILL.md not found at {skill_path}")
            return False

        self.skill_installed = True
        print(f"[INFO] Skill verified at {skill_path}")
        return True

    def run_detection(self, prompt: Optional[str] = None) -> str:
        """
        Execute security detection.

        Args:
            prompt: Custom detection prompt. If None, uses default.

        Returns:
            Detection result as string.
        """
        if not self.skill_installed:
            raise RuntimeError("Skill not installed")

        default_prompt = """
You are a Linux security expert using sec-userspace tool.

Please execute the following security detection tasks:
1. Check for suspicious processes and connections
2. Look for signs of unauthorized access
3. Check for rootkits and backdoors
4. Analyze system logs for anomalies
5. Check user accounts and permissions
6. Look for credential leaks
7. Check for crypto mining activity

Run the sec-userspace analysis and provide a comprehensive security report.
"""

        prompt = prompt or default_prompt

        print("[INFO] Executing security detection...")
        print("[INFO] This may take a few minutes...\n")

        # For standalone mode, we directly call the detection modules
        # instead of going through an AI agent
        result = self._run_local_detection()

        # Ask LLM to analyze the results
        analysis_prompt = f"""
Based on the following security detection results, provide a comprehensive analysis:

{result}

Please provide:
1. Summary of findings
2. Severity assessment
3. Evidence chain
4. Remediation recommendations
"""

        try:
            response = self.llm.simple_chat(analysis_prompt)
            return response
        except (OSError, ValueError, RuntimeError) as e:
            return f"Detection completed but LLM analysis failed: {e}\n\nRaw results:\n{result}"

    def _run_local_detection(self) -> str:
        """Run local detection modules."""
        import sys

        # Import detection modules
        sys.path.insert(0, str(Path(__file__).parent.parent))

        results = []

        try:
            # Run system profiler
            from profiler.env_profiler import EnvironmentProfiler
            profiler = EnvironmentProfiler()
            profile = profiler.profile()
            results.append("=== System Profile ===")
            results.append(str(profile))
        except (ImportError, OSError, ValueError) as e:
            results.append(f"System profiling error: {e}")

        try:
            # Run process collector
            from collector.process import ProcessCollector
            collector = ProcessCollector()
            processes = collector.collect()
            results.append("\n=== Process Information ===")
            results.append(f"Collected {len(processes)} processes")
        except (ImportError, OSError, ValueError) as e:
            results.append(f"Process collection error: {e}")

        try:
            # Run network collector
            from collector.network import NetworkCollector
            collector = NetworkCollector()
            connections = collector.collect()
            results.append("\n=== Network Connections ===")
            results.append(f"Collected {len(connections)} connections")
        except (ImportError, OSError, ValueError) as e:
            results.append(f"Network collection error: {e}")

        try:
            # Run log collector
            from collector.log import LogCollector
            collector = LogCollector()
            logs = collector.collect()
            results.append("\n=== Log Analysis ===")
            results.append(f"Collected {len(logs)} log entries")
        except (ImportError, OSError, ValueError) as e:
            results.append(f"Log collection error: {e}")

        return "\n".join(results)

    def interactive_chat(self):
        """Start interactive chat session."""
        print("\n" + "=" * 60)
        print("sec-userspace Interactive Mode")
        print("Type 'exit' or 'quit' to end the session")
        print("=" * 60 + "\n")

        while True:
            try:
                user_input = input("sec-userspace> ").strip()

                if not user_input:
                    continue

                if user_input.lower() in ["exit", "quit"]:
                    print("[INFO] Ending session.")
                    break

                if user_input.lower() == "help":
                    self._print_help()
                    continue

                # Send to LLM
                try:
                    response = self.llm.simple_chat(user_input)
                    print(f"\n{response}\n")
                except (OSError, ValueError, RuntimeError) as e:
                    print(f"[ERROR] {e}")

            except KeyboardInterrupt:
                print("\n[INFO] Session interrupted.")
                break
            except EOFError:
                print("\n[INFO] Session ended.")
                break

    def _print_help(self):
        """Print help information."""
        print("""
Available commands:
  exit, quit  - End the session
  help        - Show this help message
  detect      - Run security detection
  profile     - Show system profile

You can also ask security-related questions directly.
""")


def run_with_installed_tool(tool_name: str, skill_path: str, prompt: str) -> int:
    """
    Run sec-userspace using an installed AI tool.

    Args:
        tool_name: Name of the AI tool (claude, opencode, etc.)
        skill_path: Path to skill directory
        prompt: Prompt to execute

    Returns:
        Exit code from the tool execution.
    """
    import shutil

    tool_path = shutil.which(tool_name)
    if not tool_path:
        print(f"[ERROR] Tool '{tool_name}' not found")
        return 1

    # Build command based on tool
    if tool_name == "claude":
        cmd = ["claude", "--add-dir", skill_path, "-p", prompt]
    elif tool_name == "qodercli":
        cmd = ["qodercli", "--yolo", "-w", skill_path, "-p", prompt]
    elif tool_name == "opencode":
        cmd = ["opencode", "run", prompt, "--dir", skill_path]
    elif tool_name == "cursor":
        cmd = ["cursor", "--dir", skill_path, "-p", prompt]
    elif tool_name == "windsurf":
        cmd = ["windsurf", "--dir", skill_path, "-p", prompt]
    else:
        print(f"[ERROR] Unsupported tool: {tool_name}")
        return 1

    print(f"[INFO] Running with {tool_name}: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, timeout=600)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("[ERROR] Tool execution timed out (10 minutes)")
        return 1
    except OSError as e:
        print(f"[ERROR] Failed to execute tool: {e}")
        return 1
