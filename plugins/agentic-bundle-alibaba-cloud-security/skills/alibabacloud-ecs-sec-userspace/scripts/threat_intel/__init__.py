"""
Threat Intelligence Module - 统一 IoC 加载与查询

提供基于 base64 编码的本地 IoC 冷启动加载和 sec-server 远程热更新能力。
"""

from .ioc_loader import IoCLoader, IoCEntry, get_loader, reset_loader

__all__ = [
    "IoCLoader",
    "IoCEntry",
    "get_loader",
    "reset_loader",
]
