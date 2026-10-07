"""
KernelVersionCompareTool

SupportVariousKernelVersionFormatParseandCompare:
- "6.8.0"
- "6.8.0-31-generic"
- "5.15.0-1007-aws"
- "6.12.0-124.el10"
"""
import re
from typing import Tuple


def parse_kernel_version(version_str: str) -> Tuple[int, ...]:
    """
    Parse kernel version String as comparable tuple

    Args:
        version_str: KernelVersionString (e.g. "6.8.0-31-generic", "2.6.17.5")

    Returns:
        Version tuple (e.g. (6, 8, 0) or (2, 6, 17, 5))
    """
    # Match all numeric components before any non-numeric suffix
    match = re.match(r'(\d+(?:\.\d+)*)', version_str)
    if match:
        return tuple(int(x) for x in match.group(1).split('.'))
    return (0, 0, 0)


def version_in_range(version: str, min_version: str,
                     max_version: str = None,
                     fixed_version: str = None) -> bool:
    """
    Check if kernel version is in affected rangeIn

    Args:
        version: CurrentKernelVersion
        min_version: Minimum Version introduced by Vulnerability (inclusive)
        max_version: 受Impact最高Version（inclusive）- Optional
        fixed_version: 修复Version（notinclusive）- 优先Usefor

    Returns:
        True such asResultVersion is in affected range
    """
    v = parse_kernel_version(version)
    v_min = parse_kernel_version(min_version)

    if v < v_min:
        return False

    if fixed_version:
        v_fixed = parse_kernel_version(fixed_version)
        return v < v_fixed

    if max_version:
        v_max = parse_kernel_version(max_version)
        return v <= v_max

    # such asResult没has上界，认asAll大At min Versionall受Impact
    return True


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare两个KernelVersion

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    t1 = parse_kernel_version(v1)
    t2 = parse_kernel_version(v2)

    if t1 < t2:
        return -1
    elif t1 > t2:
        return 1
    return 0


def get_major_minor(version: str) -> str:
    """Get主Version号 (e.g. '6.8.0-31-generic' -> '6.8')"""
    parts = parse_kernel_version(version)
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return ""
