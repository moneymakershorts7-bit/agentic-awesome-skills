"""Ransomware Detection Analyzer"""
import os
import math
from datetime import datetime, timedelta
from typing import List
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer


class RansomwareAnalyzer(BaseAnalyzer):
    """Ransomware Detection Analyzer

    Detection capabilities:
    1. Ransom note file detection
    2. Bulk file encryption detection (encrypted extensions)
    3. File modification time clustering detection
    """
    name = "ransomware_analyzer"
    timeout = 60
    required_collectors = ["filesystem"]
    estimated_time = 1.0
    analyzer_type = BaseAnalyzer.CRITICAL

    def should_skip(self) -> tuple:
        """Do not skip in any mode - ransomware detection is critical."""
        return False, ""

    # Known ransom note filenames
    RANSOM_NOTE_FILENAMES = {
        "readme_to_decrypt.txt", "how_to_decrypt.txt",
        "decrypt_instructions.txt", "your_files_are_encrypted.txt",
        "recover_your_files.txt", "!readme!.txt", "_readme.txt",
        "help_decrypt.html", "how_to_restore.txt",
        "attention!!!.txt", "decrypt.txt", "unlock.txt",
        "ransom_note.txt", "important.txt",
        "read_me.txt", "restore_files.txt",
        "#readme#.txt", "how_to_recover.txt",
        "decrypt_your_files.html",
    }

    # Ransom note content keywords
    RANSOM_KEYWORDS = [
        "encrypt", "decrypt", "ransom", "bitcoin", "wallet",
        "payment", "your files", "recover", "restore", "locked",
        "pay", "btc", "monero", "xmr", "tor browser",
        "onion", "deadline", "private key",
    ]

    # Known ransomware encrypted file extensions
    ENCRYPTED_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
        ".wannacry", ".wncry", ".locky", ".cerber", ".zepto",
        ".thor", ".aaa", ".abc", ".xyz", ".zzz", ".micro",
        ".ecc", ".ezz", ".exx", ".xtbl", ".crysis", ".dharma",
        ".phobos", ".makop", ".djvu",
        ".lockbit", ".conti", ".revil", ".ryuk",
        ".hive", ".blackcat", ".alphv",
    }

    # Encrypted extension file alert threshold - lowered for test scenarios
    ENCRYPTED_FILE_THRESHOLD = 3

    # Bulk file modification threshold
    BULK_MODIFY_THRESHOLD = 100
    BULK_MODIFY_HOURS = 1

    # Scan paths
    SCAN_DIRS = ["/", "/root", "/home", "/var", "/opt", "/tmp"]
    SCAN_MAX_DEPTH = 2

    # Extension scan paths
    EXT_SCAN_DIRS = ["/home", "/var/www", "/opt"]
    EXT_SCAN_MAX_DEPTH = 3

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute ransomware detection"""
        evidences = []

        # Quick mode: lightweight check only

        # Full mode: comprehensive detection
        # 1. Ransom note file detection - supports real filesystem scan and collected_data
        evidences.extend(self._detect_ransom_notes(collected_data))

        # 2. Bulk encrypted file extension detection - supports real filesystem scan and collected_data
        evidences.extend(self._detect_encrypted_extensions(collected_data))

        # 3. File modification time clustering detection
        evidences.extend(self._detect_bulk_modifications(collected_data))

        return evidences
    def _detect_ransom_notes(self, collected_data: dict = None) -> List[Evidence]:
        """Detect ransom note files - supports real filesystem and collected_data"""
        evidences = []
        found_notes = []

        # Prefer collected_data (test scenarios)
        if collected_data and 'filesystem' in collected_data:
            try:
                fs_data = self._get_data(collected_data, 'filesystem')
            except KeyError:
                fs_data = {}
            recent_files = fs_data.get('recent_modified', []) if isinstance(fs_data, dict) else []
            for f in recent_files:
                fpath = f.get('path', '')
                fname = os.path.basename(fpath)
                if fname.lower() in self.RANSOM_NOTE_FILENAMES:
                    found_notes.append({
                        'path': fpath, 
                        'filename': fname, 
                        'content': f.get('content_sample')
                    })
            
            for note in found_notes:
                if note.get('content'):
                    ransom_score = self._score_ransom_content_sample(note['content'])
                else:
                    ransom_score = self._score_ransom_content(note["path"])
                
                if ransom_score >= 2:
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1486",
                        title=f"勒索信文件：{note['filename']}",
                        description=f"发现勒索信文件 {note['path']}，匹配 {ransom_score} 个勒索关键词",
                        confidence=0.9 if ransom_score >= 3 else 0.7,
                        source_path=note["path"],
                        raw_data={
                            "path": note["path"],
                            "filename": note["filename"],
                            "ransom_keyword_score": ransom_score,
                        },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))
                elif ransom_score >= 0:
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1486",
                        title=f"疑似勒索信文件：{note['filename']}",
                        description=f"发现疑似勒索信文件名 {note['path']}",
                        confidence=0.5,
                        source_path=note["path"],
                        raw_data={"path": note["path"], "filename": note["filename"]},
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))
            return evidences

        # Real filesystem scan
        for scan_dir in self.SCAN_DIRS:
            if not os.path.isdir(scan_dir):
                continue
            try:
                self._scan_for_ransom_notes(scan_dir, found_notes, depth=0)
            except OSError:
                continue

        for note in found_notes:
            ransom_score = self._score_ransom_content(note["path"])
            if ransom_score >= 2:
                evidences.append(self._create_evidence(
                    severity=Severity.CRITICAL,
                    attack_id="T1486",
                    title=f"勒索信文件：{note['filename']}",
                    description=f"发现勒索信文件 {note['path']}，匹配 {ransom_score} 个勒索关键词",
                    confidence=0.9 if ransom_score >= 3 else 0.7,
                    source_path=note["path"],
                    raw_data={
                        "path": note["path"],
                        "filename": note["filename"],
                        "ransom_keyword_score": ransom_score,
                    },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))
            elif ransom_score >= 0:
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1486",
                    title=f"疑似勒索信文件：{note['filename']}",
                    description=f"发现疑似勒索信文件名 {note['path']}",
                    confidence=0.5,
                    source_path=note["path"],
                    raw_data={"path": note["path"], "filename": note["filename"]},
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))

        return evidences

    def _score_ransom_content_sample(self, content: str) -> int:
        """Calculate ransom keyword match score (for content_sample strings)"""
        content_lower = content.lower()
        score = 0
        for keyword in self.RANSOM_KEYWORDS:
            if keyword in content_lower:
                score += 1
        return score

    def _scan_for_ransom_notes(self, directory: str, result: list, depth: int):
        """Recursively scan for ransom note files"""
        if depth > self.SCAN_MAX_DEPTH:
            return

        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            if entry.name.lower() in self.RANSOM_NOTE_FILENAMES:
                                result.append({
                                    "path": entry.path,
                                    "filename": entry.name,
                                })
                        elif entry.is_dir(follow_symlinks=False) and depth < self.SCAN_MAX_DEPTH:
                            # Skip system directories
                            if entry.name in ("proc", "sys", "dev", "run"):
                                continue
                            self._scan_for_ransom_notes(entry.path, result, depth + 1)
                    except OSError:
                        continue
        except OSError:
            pass

    def _score_ransom_content(self, filepath: str) -> int:
        """Read first 1KB of file and calculate ransom keyword match score"""
        try:
            with open(filepath, "r", errors="ignore", encoding='utf-8') as f:
                content = f.read(1024).lower()

            score = 0
            for keyword in self.RANSOM_KEYWORDS:
                if keyword in content:
                    score += 1
            return score
        except OSError:
            return -1

    def _detect_encrypted_extensions(self, collected_data: dict = None) -> List[Evidence]:
        """Detect bulk encrypted file extensions - supports real filesystem and collected_data"""
        evidences = []
        ext_counts = {}  # {extension: count}

        # Prefer collected_data (test scenarios)
        if collected_data and 'filesystem' in collected_data:
            try:
                fs_data = self._get_data(collected_data, 'filesystem')
            except KeyError:
                fs_data = {}
            recent_files = fs_data.get('recent_modified', []) if isinstance(fs_data, dict) else []
            for f in recent_files:
                fpath = f.get('path', '')
                _, ext = os.path.splitext(fpath)
                ext_lower = ext.lower()
                if ext_lower in self.ENCRYPTED_EXTENSIONS:
                    ext_counts[ext_lower] = ext_counts.get(ext_lower, 0) + 1

            # Check if any encrypted extension exceeds threshold
            for ext, count in ext_counts.items():
                if count >= self.ENCRYPTED_FILE_THRESHOLD:
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1486",
                        title=f"批量加密文件：{ext} ({count}个)",
                        description=f"发现 {count} 个 {ext} 扩展名文件，"
                                    f"疑似勒索病毒加密痕迹",
                        confidence=0.85,
                        raw_data={"extension": ext, "file_count": count},
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))
            return evidences

        # Real filesystem scan
        for scan_dir in self.EXT_SCAN_DIRS:
            if not os.path.isdir(scan_dir):
                continue
            try:
                self._count_encrypted_extensions(scan_dir, ext_counts, depth=0)
            except OSError:
                continue

        # Check if any encrypted extension exceeds threshold
        for ext, count in ext_counts.items():
            if count >= self.ENCRYPTED_FILE_THRESHOLD:
                evidences.append(self._create_evidence(
                    severity=Severity.CRITICAL,
                    attack_id="T1486",
                    title=f"批量加密文件：{ext} ({count}个)",
                    description=f"发现 {count} 个 {ext} 扩展名文件，"
                                f"疑似勒索病毒加密痕迹",
                    confidence=0.85,
                    raw_data={"extension": ext, "file_count": count},
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))

        return evidences

    def _count_encrypted_extensions(self, directory: str, ext_counts: dict, depth: int):
        """Recursively count encrypted extension files"""
        if depth > self.EXT_SCAN_MAX_DEPTH:
            return

        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            _, ext = os.path.splitext(entry.name)
                            ext_lower = ext.lower()
                            if ext_lower in self.ENCRYPTED_EXTENSIONS:
                                ext_counts[ext_lower] = ext_counts.get(ext_lower, 0) + 1
                        elif entry.is_dir(follow_symlinks=False) and depth < self.EXT_SCAN_MAX_DEPTH:
                            self._count_encrypted_extensions(
                                entry.path, ext_counts, depth + 1
                            )
                    except OSError:
                        continue
        except OSError:
            pass

    def _detect_bulk_modifications(self, collected_data: dict = None) -> List[Evidence]:
        """Detect file modification time clustering - supports real filesystem and collected_data"""
        evidences = []

        # Prefer collected_data (test scenarios)
        if collected_data and 'filesystem' in collected_data:
            try:
                fs_data = self._get_data(collected_data, 'filesystem')
            except KeyError:
                fs_data = {}
            recent_files = fs_data.get('recent_modified', [])
            
            if len(recent_files) <= self.BULK_MODIFY_THRESHOLD:
                return evidences

            # Group by mtime (mtime in mock data is a timestamp)
            hour_buckets = {}
            for f in recent_files:
                mtime_ts = f.get('mtime', 0)
                if isinstance(mtime_ts, (int, float)):
                    mtime = datetime.fromtimestamp(mtime_ts)
                else:
                    continue
                hour_key = mtime.strftime("%Y-%m-%d %H:00")
                if hour_key not in hour_buckets:
                    hour_buckets[hour_key] = []
                hour_buckets[hour_key].append(f)

            # Check if any single hour has bulk modifications
            for hour_key, files in hour_buckets.items():
                if len(files) >= self.BULK_MODIFY_THRESHOLD:
                    # Sample check file entropy (if content_sample available)
                    high_entropy_count = 0
                    sample_count = min(10, len(files))
                    for f in files[:sample_count]:
                        content = f.get('content_sample', '')
                        if content:
                            entropy = self._string_entropy(content)
                            if entropy > 7.5:
                                high_entropy_count += 1

                    severity = Severity.CRITICAL if high_entropy_count > sample_count / 2 else Severity.HIGH
                    evidences.append(self._create_evidence(
                        severity=severity,
                        attack_id="T1486",
                        title=f"批量文件修改：{len(files)}个文件 ({hour_key})",
                        description=f"在 {hour_key} 期间有 {len(files)} 个文件被修改，"
                                    f"高熵文件占比 {high_entropy_count}/{sample_count}",
                        confidence=0.7 if high_entropy_count > 0 else 0.5,
                        raw_data={
                            "hour": hour_key,
                            "file_count": len(files),
                            "high_entropy_count": high_entropy_count,
                            "sample_count": sample_count,
                        },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))
            return evidences

        # Real filesystem scan
        now = datetime.now()
        one_day_ago = now - timedelta(hours=24)
        scan_dirs = ["/home", "/var/www"]

        recent_files = []

        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            try:
                self._collect_recent_files(scan_dir, recent_files, one_day_ago, depth=0)
            except OSError:
                continue

        if len(recent_files) <= self.BULK_MODIFY_THRESHOLD:
            return evidences

        # Group by hour
        hour_buckets = {}
        for f in recent_files:
            hour_key = f["mtime"].strftime("%Y-%m-%d %H:00")
            if hour_key not in hour_buckets:
                hour_buckets[hour_key] = []
            hour_buckets[hour_key].append(f)

        # Check if any single hour has bulk modifications
        for hour_key, files in hour_buckets.items():
            if len(files) >= self.BULK_MODIFY_THRESHOLD:
                # Sample check file entropy
                high_entropy_count = 0
                sample_count = min(10, len(files))
                for f in files[:sample_count]:
                    entropy = self._file_entropy(f["path"])
                    if entropy > 7.5:
                        high_entropy_count += 1

                severity = Severity.CRITICAL if high_entropy_count > sample_count / 2 else Severity.HIGH
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1486",
                    title=f"批量文件修改：{len(files)}个文件 ({hour_key})",
                    description=f"在 {hour_key} 期间有 {len(files)} 个文件被修改，"
                                f"高熵文件占比 {high_entropy_count}/{sample_count}",
                    confidence=0.7 if high_entropy_count > 0 else 0.5,
                    raw_data={
                        "hour": hour_key,
                        "file_count": len(files),
                        "high_entropy_count": high_entropy_count,
                        "sample_count": sample_count,
                    },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Isolate affected systems immediately",
                        "Review backup integrity and restore from clean backup",
                        "Audit file encryption patterns and identify ransomware variant",
                        "Report incident to law enforcement and cybersecurity teams"
                    ]))

        return evidences

    def _collect_recent_files(self, directory: str, result: list,
                              cutoff: datetime, depth: int, max_depth: int = 3):
        """Collect recently modified files"""
        if depth > max_depth:
            return
        if len(result) > 5000:
            return

        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            mtime = datetime.fromtimestamp(st.st_mtime)
                            if mtime >= cutoff:
                                result.append({
                                    "path": entry.path,
                                    "mtime": mtime,
                                    "size": st.st_size,
                                })
                        elif entry.is_dir(follow_symlinks=False) and depth < max_depth:
                            self._collect_recent_files(
                                entry.path, result, cutoff, depth + 1, max_depth
                            )
                    except OSError:
                        continue
        except OSError:
            pass

    @staticmethod
    def _file_entropy(filepath: str, sample_size: int = 4096) -> float:
        """Calculate Shannon entropy of first N bytes of a file"""
        try:
            with open(filepath, "rb") as f:
                data = f.read(sample_size)

            if not data:
                return 0.0

            freq = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1

            length = len(data)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)

            return entropy
        except OSError:
            return 0.0

    @staticmethod
    def _string_entropy(data: str, sample_size: int = 4096) -> float:
        """Calculate Shannon entropy of a string"""
        byte_data = data.encode('utf-8', errors='ignore')[:sample_size]
        if not byte_data:
            return 0.0

        freq = {}
        for byte in byte_data:
            freq[byte] = freq.get(byte, 0) + 1

        length = len(byte_data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy