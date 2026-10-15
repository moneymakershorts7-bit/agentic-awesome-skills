"""误报自动学习器 - 实现误报本地自动记录，保证下次不再误报

工作原理：
1. 当告警被判定为误报时，调用 record_and_learn()
2. 误报信息立即写入本地 learned-fp.json 文件
3. 下次扫描时 WhitelistLoader 自动加载 learned-fp.json
4. 同一误报不再出现

存储位置优先级：
1. /etc/sec-userspace/learned-fp.json（系统级，跨扫描持久化）
2. {output_dir}/learned-fp.json（扫描级，随输出目录）
"""

import json
import logging
import os
import threading
import time
from typing import Dict, List, Optional

logger = logging.getLogger("sec-userspace")

# Default paths for learned FP file
SYSTEM_LEARNED_FP_PATH = "/etc/sec-userspace/learned-fp.json"


class FPAutoLearner:
    """误报自动学习器

    当告警被判定为误报时，自动记录到本地文件。
    下次扫描时 WhitelistLoader 自动加载已学习的误报记录，
    使同一误报不再出现。

    线程安全：所有写操作由 _lock 保护。
    """

    _lock = threading.Lock()

    def __init__(self, output_dir: Optional[str] = None):
        """初始化误报自动学习器

        Args:
            output_dir: 扫描输出目录，用于 learned-fp.json 的备选存储路径
        """
        self._system_path = SYSTEM_LEARNED_FP_PATH
        self._local_path = (
            os.path.join(output_dir, "learned-fp.json") if output_dir else None
        )
        self._fp_file = self._resolve_path()
        self._entries: List[Dict] = self._load()

    def _resolve_path(self) -> str:
        """确定存储路径，优先系统级路径"""
        sys_dir = os.path.dirname(self._system_path)
        if os.path.isdir(sys_dir) and os.access(sys_dir, os.W_OK):
            return self._system_path
        # 尝试创建系统目录
        try:
            os.makedirs(sys_dir, exist_ok=True)
            return self._system_path
        except OSError:
            pass
        # 降级到本地路径
        if self._local_path:
            local_dir = os.path.dirname(self._local_path)
            if local_dir:
                try:
                    os.makedirs(local_dir, exist_ok=True)
                except OSError:
                    pass
            return self._local_path
        return self._system_path

    def _load(self) -> List[Dict]:
        """加载已学习的误报记录"""
        if not os.path.exists(self._fp_file):
            return []
        try:
            with open(self._fp_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("entries", [])
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("加载误报学习文件失败: %s", e)
            return []

    def _save(self) -> None:
        """持久化误报记录"""
        data = {
            "version": "1.0",
            "description": "误报自动学习记录 - 由 sec-userspace 自动维护",
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "entries": self._entries,
        }
        try:
            with open(self._fp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.error("保存误报学习文件失败: %s", e)

    def record_and_learn(
        self,
        module: str,
        evidence_title: str,
        evidence_value: str,
        reason: str = "自动学习",
    ) -> None:
        """记录误报并立即写入本地白名单

        Args:
            module: 产生误报的分析器模块名
            evidence_title: 告警标题
            evidence_value: 告警具体值（用于匹配）
            reason: 误报原因说明
        """
        with self._lock:
            # 去重检查
            for entry in self._entries:
                if (
                    entry.get("module") == module
                    and entry.get("pattern") == evidence_value
                ):
                    # 已存在，更新计数
                    entry["count"] = entry.get("count", 1) + 1
                    entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    self._save()
                    return

            # 新增条目
            new_entry = {
                "id": "learned-fp-%04d" % (len(self._entries) + 1),
                "module": module,
                "type": "evidence_pattern",
                "pattern": evidence_value,
                "title": evidence_title,
                "reason": reason,
                "added_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "count": 1,
                "source": "auto_learned",
                "enabled": True,
            }
            self._entries.append(new_entry)
            self._save()
            logger.info("已学习新误报: [%s] %s", module, evidence_title)

    def is_learned_fp(self, module: str, evidence_value: str) -> bool:
        """检查是否是已学习的误报"""
        with self._lock:
            for entry in self._entries:
                if not entry.get("enabled", True):
                    continue
                if (
                    entry.get("module") == module
                    and entry.get("pattern") == evidence_value
                ):
                    return True
        return False

    def get_learned_entries(self) -> List[Dict]:
        """获取所有已学习的条目（供 WhitelistLoader 使用）"""
        with self._lock:
            return [e for e in self._entries if e.get("enabled", True)]

    def get_stats(self) -> Dict:
        """获取统计信息"""
        with self._lock:
            total = len(self._entries)
            enabled = sum(1 for e in self._entries if e.get("enabled", True))
            return {"total": total, "enabled": enabled, "file": self._fp_file}


# Global singleton (lazy initialization)
_learner_instance: Optional[FPAutoLearner] = None
_learner_lock = threading.Lock()


def get_fp_auto_learner(
    output_dir: Optional[str] = None,
) -> FPAutoLearner:
    """Get or create the global FPAutoLearner instance.

    Args:
        output_dir: Optional output directory for local storage

    Returns:
        FPAutoLearner instance
    """
    global _learner_instance
    if _learner_instance is None:
        with _learner_lock:
            if _learner_instance is None:
                _learner_instance = FPAutoLearner(output_dir=output_dir)
    return _learner_instance


def reset_fp_auto_learner() -> None:
    """Reset FPAutoLearner singleton (for testing)"""
    global _learner_instance
    with _learner_lock:
        _learner_instance = None
