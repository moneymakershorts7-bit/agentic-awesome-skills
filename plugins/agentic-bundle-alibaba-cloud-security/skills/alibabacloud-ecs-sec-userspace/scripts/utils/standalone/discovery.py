"""AI Tools Discovery Module."""

import shutil
import subprocess
from typing import Optional, List


class AITool:
    """Represents an installed AI tool."""

    def __init__(self, name: str, path: str, version: Optional[str] = None):
        self.name = name
        self.path = path
        self.version = version

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "version": self.version
        }

    def __repr__(self) -> str:
        return f"AITool(name={self.name}, version={self.version})"


SUPPORTED_TOOLS = [
    "claude",      # Claude Code
    "opencode",    # OpenCode
    "qodercli",    # QoderCLI
    "cursor",      # Cursor CLI
    "windsurf",    # Windsurf CLI
]


def get_tool_version(tool_name: str) -> Optional[str]:
    """Get version of an AI tool."""
    try:
        if tool_name == "claude":
            result = subprocess.run(
                ["claude", "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            return result.stdout.strip() or result.stderr.strip()
        elif tool_name == "opencode":
            result = subprocess.run(
                ["opencode", "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            return result.stdout.strip()
        elif tool_name == "qodercli":
            result = subprocess.run(
                ["qodercli", "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            return result.stdout.strip()
        elif tool_name == "cursor":
            result = subprocess.run(
                ["cursor", "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            return result.stdout.strip()
        elif tool_name == "windsurf":
            result = subprocess.run(
                ["windsurf", "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def discover_ai_tools() -> List[AITool]:
    """
    Discover AI tools installed in the system.

    Returns:
        List of discovered AI tools with their information.
    """
    tools = []

    for tool_name in SUPPORTED_TOOLS:
        tool_path = shutil.which(tool_name)
        if tool_path:
            version = get_tool_version(tool_name)
            tools.append(AITool(
                name=tool_name,
                path=tool_path,
                version=version
            ))

    return tools


def get_preferred_tool(tools: List[AITool]) -> Optional[AITool]:
    """
    Get the preferred AI tool from discovered tools.

    Priority: claude > opencode > qodercli > cursor > windsurf

    Args:
        tools: List of discovered AI tools.

    Returns:
        The preferred AI tool, or None if no tools found.
    """
    priority_order = ["claude", "opencode", "qodercli", "cursor", "windsurf"]

    for tool_name in priority_order:
        for tool in tools:
            if tool.name == tool_name:
                return tool

    return None


def build_command(tool: AITool, skill_path: str, prompt: str) -> List[str]:
    """
    Build command to execute skill with specified AI tool.

    Args:
        tool: The AI tool to use.
        skill_path: Path to the skill directory.
        prompt: Prompt to execute.

    Returns:
        Command as a list of strings.
    """
    if tool.name == "claude":
        return ["claude", "--add-dir", skill_path, "-p", prompt]
    elif tool.name == "qodercli":
        return ["qodercli", "--yolo", "-w", skill_path, "-p", prompt]
    elif tool.name == "opencode":
        return ["opencode", "run", prompt, "--dir", skill_path]
    elif tool.name == "cursor":
        return ["cursor", "--dir", skill_path, "-p", prompt]
    elif tool.name == "windsurf":
        return ["windsurf", "--dir", skill_path, "-p", prompt]

    raise ValueError(f"Unsupported AI tool: {tool.name}")


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
    except (subprocess.SubprocessError, OSError) as e:
        print(f"[ERROR] Failed to execute tool: {e}")
        return 1
