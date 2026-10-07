"""Webshell Detection Analyzer"""
import os
import re
import math
from collections import Counter
from typing import List, Dict, Tuple, Optional
from .base import BaseAnalyzer
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

class WebshellAnalyzer(BaseAnalyzer):
    """Webshell Detection Analyzer"""
    name = "webshell_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 60)

    required_collectors = ["filesystem", "cron", "process"]
    estimated_time = 2.0
    analyzer_type = BaseAnalyzer.CRITICAL

    @property
    def WEB_DIRECTORIES(self):
        cfg = self._get_config("web_directories")
        if cfg:
            return cfg
        return ['/var/www', '/usr/share/nginx', '/opt/nginx']

    # Safe installation paths for system tools and compilers
    SAFE_PATHS = [
        '/usr/lib/python',
        '/usr/local/lib/python',
        '/opt/python',
        '/usr/share/clang',
        '/usr/lib/llvm',
        '/opt/alibaba-cloud-compiler',
        '/usr/share/gcc',
        '/usr/lib/gcc',
        '/usr/share/cmake',
        '/usr/lib/cmake',
        '/usr/share/maven',
        '/usr/lib/maven',
        '/opt/homebrew',
        '/usr/local/opt',
        '/snap',
        # Conda package cache and environments
        '/opt/conda/pkgs/',
        '/opt/conda/envs/',
        '/root/.conda/pkgs/',
        '/root/.conda/envs/',
        '/home/.conda/pkgs/',
        '/home/.conda/envs/',
        '/usr/local/conda/pkgs/',
        '/usr/local/conda/envs/',
    ]

    # Python site-packages paths (virtual environments and custom installs)
    PYTHON_SITE_PATHS = [
        '/usr/lib/python',
        '/usr/local/lib/python',
        '/opt/python',
        '/usr/share/python',
    ]

    # PHP dangerous function patterns
    PHP_PATTERNS = [
        re.compile(r'\beval\s*\('),
        re.compile(r'\bsystem\s*\('),
        re.compile(r'\bexec\s*\('),
        re.compile(r'\bpassthru\s*\('),
        re.compile(r'\bshell_exec\s*\('),
        re.compile(r'\bpopen\s*\('),
        re.compile(r'\bproc_open\s*\('),
        re.compile(r'\bassert\s*\('),
        re.compile(r'\$_(?:GET|POST|REQUEST|COOKIE)\s*\['),
    ]

    # Python dangerous patterns
    PYTHON_PATTERNS = [
        re.compile(r'\bexec\s*\('),
        re.compile(r'\beval\s*\('),
        re.compile(r'__import__\s*\('),
        re.compile(r'subprocess\.(?:call|Popen|run)'),
    ]

    # JSP dangerous patterns
    JSP_PATTERNS = [
        re.compile(r'Runtime\.getRuntime\(\)\.exec\('),
        re.compile(r'ProcessBuilder'),
    ]

    # Cookie-based authentication patterns (2026 threat intelligence)
    COOKIE_PATTERNS = [
        re.compile(r'\$_COOKIE\s*\[\s*[\'"](?:auth|token|key|session|cmd|pass)[\'"]', re.IGNORECASE),
        re.compile(r'setcookie\s*\(.*\$_(?:GET|POST)', re.IGNORECASE),
        re.compile(r'if\s*\(\s*isset\s*\(\s*\$_COOKIE'),
        re.compile(r'header\s*\(.*Set-Cookie.*(md5|sha256|hash)', re.IGNORECASE),
        re.compile(r'\$_COOKIE\s*\[.*\]\s*===?\s*[\'"][a-f0-9]{32,}[\'"]', re.IGNORECASE),
        re.compile(r'md5\s*\(\s*\$_COOKIE', re.IGNORECASE),
        re.compile(r'sha256\s*\(\s*\$_COOKIE', re.IGNORECASE),
    ]

    # Multi-layer obfuscation patterns (2026 techniques)
    OBFUSCATION_PATTERNS = [
        re.compile(r'base64_decode\s*\(\s*(?:gzinflate|str_rot13)'),
        re.compile(r'eval\s*\(\s*gzinflate\s*\(\s*base64_decode'),
        re.compile(r'preg_replace\s*\(\s*[\'"].*\/e[\'"]'),
        re.compile(r'create_function\s*\('),
        re.compile(r'array_map\s*\(\s*[\'"](?:eval|assert|system)[\'"]'),
        re.compile(r'(?:call_user_func|array_filter|array_walk).*\$_(?:GET|POST|REQUEST|COOKIE)'),
    ]

    # php-fpm socket paths
    PHP_FPM_SOCKET_PATHS = [
        '/run/php/php*-fpm.sock',
        '/var/run/php-fpm/*.sock',
        '/tmp/php-fpm*.sock',
    ]

    # Legitimate web server processes that can access php-fpm
    LEGITIMATE_WEBSERVERS = ['nginx', 'apache', 'httpd', 'lighttpd', 'caddy']

    # Entropy thresholds by file type (normal range vs suspicious range)
    ENTROPY_THRESHOLDS = {
        '.php': {'normal_max': 5.5, 'suspicious': 6.0, 'critical': 7.0},
        '.jsp': {'normal_max': 5.8, 'suspicious': 6.2, 'critical': 7.2},
        '.asp': {'normal_max': 5.5, 'suspicious': 6.0, 'critical': 7.0},
        '.aspx': {'normal_max': 5.8, 'suspicious': 6.2, 'critical': 7.2},
        '.py': {'normal_max': 5.2, 'suspicious': 5.8, 'critical': 6.8},
        '.cgi': {'normal_max': 5.2, 'suspicious': 5.8, 'critical': 6.8},
        '.pl': {'normal_max': 5.2, 'suspicious': 5.8, 'critical': 6.8},
    }

    # Character frequency thresholds for suspicious files
    CHAR_FREQ_THRESHOLDS = {
        'printable_ratio_min': 0.6,  # Normal files have > 60% printable chars
        'special_char_ratio_max': 0.3,  # Normal files have < 30% special chars
        'null_byte_ratio_max': 0.05,  # Normal files have < 5% null bytes
    }

    # Base64 detection thresholds
    BASE64_THRESHOLDS = {
        'ratio_threshold': 0.5,  # 50% base64 content is suspicious
        'min_length': 100,  # Minimum base64 string length to consider
        'min_occurrences': 3,  # Minimum number of base64 strings
    }

    # Encoding function patterns for depth calculation
    ENCODING_FUNCTIONS = [
        (re.compile(r'base64_decode\s*\('), 'base64_decode'),
        (re.compile(r'gzinflate\s*\('), 'gzinflate'),
        (re.compile(r'str_rot13\s*\('), 'str_rot13'),
        (re.compile(r'gzuncompress\s*\('), 'gzuncompress'),
        (re.compile(r'gzdecode\s*\('), 'gzdecode'),
        (re.compile(r'rawurldecode\s*\('), 'rawurldecode'),
        (re.compile(r'urldecode\s*\('), 'urldecode'),
    ]

    # Web directories to check in quick mode (loaded from config via property at line 37)

    # Known webshell filenames (common malware filenames)
    KNOWN_WEBSHELL_NAMES = [
        'cmd.php', 'shell.php', 'webshell.php', 'c99.php', 'r57.php',
        'backdoor.php', 'bypass.php', 'config.bak.php', 'upload.php',
        'test.php', 'info.php', 'debug.php', '1.php', 'x.php',
        'cmd.jsp', 'shell.jsp', 'cmd.py', 'shell.py',
    ]

    def should_skip(self) -> tuple:
        """Never skip - webshell detection is critical for all scan modes"""
        return False, ""

    def _find_pattern_matches_with_lines(self, content: str, patterns: list) -> Tuple[List[str], int, List[str], List[str]]:
        """Find pattern matches with line numbers and context.
        
        Args:
            content: File content to search
            patterns: List of compiled regex patterns
            
        Returns:
            Tuple of (matched_pattern_names, first_match_line, context_before, context_after)
        """
        lines = content.split('\n')
        matched_patterns = []
        first_match_line = None
        context_before = []
        context_after = []

        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    matched_patterns.append(pattern.pattern)
                    if first_match_line is None:
                        first_match_line = line_num
                        context_before = lines[max(0, line_num-4):line_num-1]
                        context_after = lines[line_num:min(len(lines), line_num+3)]
                    break

        return matched_patterns, first_match_line, context_before, context_after
    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute webshell detection analysis"""
        evidences = []
        fs_data = self._get_data(collected_data, "filesystem")
        if not fs_data:
            return evidences

        # Quick mode: lightweight check only

        webroot_files = fs_data.get("webroot_files", [])

        # Enhancement 1: Cookie-based authentication detection
        evidences.extend(self._check_cookie_auth(webroot_files))

        # Enhancement 2: Multi-layer obfuscation detection
        evidences.extend(self._check_multi_layer_obfuscation(webroot_files))

        # Enhancement 3: Cron job correlation (if cron data available)
        cron_data = self._get_data(collected_data, "cron")
        if cron_data:
            evidences.extend(self._check_webshell_persistence(webroot_files, cron_data))

        # Enhancement 4: php-fpm abuse detection
        process_data = self._get_data(collected_data, "process")
        if process_data:
            evidences.extend(self._check_phpfpm_abuse(process_data))

        # Existing checks
        evidences.extend(self._check_dangerous_functions(webroot_files))
        evidences.extend(self._check_entropy(webroot_files))
        evidences.extend(self._check_base64_content(webroot_files))
        evidences.extend(self._check_file_time_anomaly(webroot_files))

        return evidences

    def _check_dangerous_functions(self, webroot_files: list) -> List[Evidence]:
        """Detect dangerous functions"""
        evidences = []

        for file_info in webroot_files:
            filepath = file_info.get("path", "")
            ext = file_info.get("extension", "").lower()

            # If no extension field, infer from path
            if not ext:
                ext = os.path.splitext(filepath)[1].lower()

            # Select pattern set based on extension
            patterns = []
            if ext == ".php":
                patterns = self.PHP_PATTERNS
            elif ext in [".py", ".cgi", ".pl"]:
                patterns = self.PYTHON_PATTERNS
            elif ext in [".jsp", ".asp", ".aspx"]:
                patterns = self.JSP_PATTERNS

            if not patterns:
                continue

            # Skip files in safe paths
            if self._is_safe_path(filepath):
                continue

            # Prefer content_sample (supports mock testing), otherwise read file
            content = file_info.get("content_sample", "")
            if not content:
                try:
                    with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                        content = f.read(65536)
                except OSError:
                    continue

            if not content:
                continue

            # Match dangerous functions with line numbers and context
            matched_patterns, match_line, context_before, context_after = self._find_pattern_matches_with_lines(
                content, patterns
            )

            if matched_patterns:
                evidences.append(self._create_evidence(
                    title=f"Webshell危险函数匹配: {filepath}",
                    description=f"文件 {filepath} 匹配 {len(matched_patterns)} 个危险pattern: {', '.join(matched_patterns[:3])}",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    attack_id="T1505.003",
                    source_path=filepath,
                    raw_data={"path": filepath, "matched_patterns": matched_patterns[:5]},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"Matched {len(matched_patterns)} dangerous patterns",
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))

        return evidences

    def _check_entropy(self, webroot_files: list) -> List[Evidence]:
        """Check file information entropy with file-type specific thresholds"""
        evidences = []

        for file_info in webroot_files:
            filepath = file_info.get("path", "")
            ext = file_info.get("extension", "").lower()

            # If no extension field, infer from path
            if not ext:
                ext = os.path.splitext(filepath)[1].lower()

            # Only calculate entropy for script files
            if ext not in self.ENTROPY_THRESHOLDS:
                continue

            # Skip safe paths
            if self._is_safe_path(filepath):
                continue

            # Get file content for analysis
            content_bytes = self._get_file_content_bytes(file_info, filepath)
            if content_bytes is None:
                continue

            # Calculate entropy
            entropy = self._calculate_entropy(content_bytes)

            # Get file-type specific thresholds
            thresholds = self.ENTROPY_THRESHOLDS[ext]

            # Check entropy against thresholds
            if entropy > thresholds['critical']:
                evidences.append(self._create_evidence(
                    title=f"Webshell高熵检测: {filepath}",
                    description=f"文件 {filepath} 信息熵={entropy:.2f}，超过临界值{thresholds['critical']:.1f}，高度疑似加密/混淆webshell",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    attack_id="T1505.003",
                    source_path=filepath,
                    raw_data={
                        "path": filepath,
                        "entropy": round(entropy, 2),
                        "threshold_critical": thresholds['critical'],
                        "file_type": ext
                    },
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"High entropy: {entropy:.2f}",
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))
            elif entropy > thresholds['suspicious']:
                # Perform additional analysis for suspicious files
                char_analysis = self._analyze_character_frequency(content_bytes)
                
                # Increase confidence if character analysis is also suspicious
                confidence = 0.5
                if char_analysis.get('suspicious', False):
                    confidence = 0.65

                evidences.append(self._create_evidence(
                    title=f"Webshell可疑熵检测: {filepath}",
                    description=(
                        f"文件 {filepath} 信息熵={entropy:.2f}，超过阈值{thresholds['suspicious']:.1f}，"
                        f"可能为混淆/加密脚本文件{'，字符频率分析异常' if char_analysis.get('suspicious', False) else ''}"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    attack_id="T1027",
                    source_path=filepath,
                    raw_data={
                        "path": filepath,
                        "entropy": round(entropy, 2),
                        "threshold_suspicious": thresholds['suspicious'],
                        "file_type": ext,
                        "char_frequency_analysis": char_analysis
                    },
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"Suspicious entropy: {entropy:.2f}",
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))

        return evidences

    def _analyze_character_frequency(self, data: bytes) -> Dict:
        """Analyze character frequency distribution for anomaly detection"""
        if not data:
            return {"suspicious": False, "reason": "empty_data"}

        total_bytes = len(data)
        if total_bytes == 0:
            return {"suspicious": False, "reason": "empty_data"}

        # Count character categories
        printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (10, 13, 9))
        null_count = sum(1 for b in data if b == 0)
        special_count = sum(1 for b in data if not (32 <= b <= 126) and b not in (10, 13, 9))

        # Calculate ratios
        printable_ratio = printable_count / total_bytes
        null_ratio = null_count / total_bytes
        special_ratio = special_count / total_bytes

        # Calculate byte value distribution (uniform distribution is suspicious)
        byte_counter = Counter(data)
        unique_bytes = len(byte_counter)
        
        # For random data, most byte values appear with similar frequency
        # Calculate coefficient of variation (CV) of byte frequencies
        if unique_bytes > 0:
            frequencies = list(byte_counter.values())
            mean_freq = sum(frequencies) / len(frequencies)
            if mean_freq > 0:
                variance = sum((f - mean_freq) ** 2 for f in frequencies) / len(frequencies)
                std_dev = variance ** 0.5
                cv = std_dev / mean_freq
            else:
                cv = 0
        else:
            cv = 0

        # Determine if suspicious
        suspicious = False
        reasons = []

        thresholds = self.CHAR_FREQ_THRESHOLDS
        if printable_ratio < thresholds['printable_ratio_min']:
            suspicious = True
            reasons.append(f"low_printable_ratio: {printable_ratio:.2f}")
        
        if null_ratio > thresholds['null_byte_ratio_max']:
            suspicious = True
            reasons.append(f"high_null_ratio: {null_ratio:.2f}")
        
        if special_ratio > thresholds['special_char_ratio_max']:
            suspicious = True
            reasons.append(f"high_special_ratio: {special_ratio:.2f}")

        # Low CV indicates uniform distribution (random/encrypted data)
        if cv < 0.5 and unique_bytes > 100:
            suspicious = True
            reasons.append(f"uniform_distribution: cv={cv:.2f}")

        return {
            "suspicious": suspicious,
            "printable_ratio": round(printable_ratio, 3),
            "null_ratio": round(null_ratio, 3),
            "special_ratio": round(special_ratio, 3),
            "unique_bytes": unique_bytes,
            "coefficient_of_variation": round(cv, 3),
            "reasons": reasons
        }

    def _get_file_content_bytes(self, file_info: dict, filepath: str) -> Optional[bytes]:
        """Get file content as bytes, with fallback to file read"""
        content_sample = file_info.get("content_sample", "")
        if content_sample:
            return content_sample.encode('utf-8', errors='ignore')
        
        try:
            with open(filepath, 'rb') as f:
                return f.read(65536)
        except OSError as e:
            _get_logger().warning(f"Cannot read file {filepath}: {e}")
            return None

    def _check_file_time_anomaly(self, webroot_files: list) -> List[Evidence]:
        """Check file time anomalies"""
        evidences = []

        for file_info in webroot_files:
            filepath = file_info.get("path", "")

            # Prefer timestamps from file info (supports mock testing)
            mtime = file_info.get("mtime")
            ctime = file_info.get("ctime")

            if mtime is None or ctime is None:
                try:
                    st = os.stat(filepath)
                    mtime = st.st_mtime
                    ctime = st.st_ctime
                except OSError:
                    continue

            # Skip files in safe paths
            if self._is_safe_path(filepath):
                continue

            # If mtime < ctime, timestamp may have been tampered with
            if mtime < ctime:
                evidences.append(self._create_evidence(
                    title=f"Webshell时间戳异常: {filepath}",
                    description=f"文件 {filepath} mtime < ctime，时间戳可能被篡改",
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    attack_id="T1070.006",
                    source_path=filepath,
                    raw_data={"path": filepath, "mtime": mtime, "ctime": ctime},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"Timestamp anomaly: mtime < ctime",
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))

        return evidences

    def _check_cookie_auth(self, webroot_files: list) -> List[Evidence]:
        """Detect cookie-based authentication patterns in PHP files"""
        evidences = []

        for file_info in webroot_files:
            filepath = file_info.get("path", "")
            ext = file_info.get("extension", "").lower()

            if not ext:
                ext = os.path.splitext(filepath)[1].lower()

            # Only check PHP files for cookie auth
            if ext != ".php":
                continue

            # Skip safe paths
            if self._is_safe_path(filepath):
                continue

            # Read file content
            content = file_info.get("content_sample", "")
            if not content:
                try:
                    with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                        content = f.read(65536)
                except OSError:
                    continue

            # Check for cookie authentication patterns
            matched_patterns, match_line, context_before, context_after = self._find_pattern_matches_with_lines(
                content, self.COOKIE_PATTERNS
            )

            if matched_patterns:
                # Higher confidence if multiple patterns match
                confidence = min(0.7 + (len(matched_patterns) - 1) * 0.1, 0.95)

                evidences.append(self._create_evidence(
                    title=f"Cookie-Controlled Webshell Detected: {filepath}",
                    description=(
                        f"File {filepath} contains {len(matched_patterns)} cookie-based "
                        f"authentication pattern(s): {', '.join(m[:40] for m in matched_patterns[:2])}"
                    ),
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    attack_id="T1505.003",
                    source_path=filepath,
                    raw_data={"path": filepath, "matched_patterns": matched_patterns[:5]},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"Cookie auth: {len(matched_patterns)} patterns",
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))

        return evidences

    def _check_multi_layer_obfuscation(self, webroot_files: list) -> List[Evidence]:
        """Detect multi-layer obfuscation techniques"""
        evidences = []

        for file_info in webroot_files:
            filepath = file_info.get("path", "")
            ext = file_info.get("extension", "").lower()

            if not ext:
                ext = os.path.splitext(filepath)[1].lower()

            # Check script files
            if ext not in [".php", ".py", ".jsp", ".asp", ".aspx"]:
                continue

            # Skip safe paths
            if self._is_safe_path(filepath):
                continue

            # Read file content
            content = file_info.get("content_sample", "")
            if not content:
                try:
                    with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                        content = f.read(65536)
                except OSError:
                    continue

            # Check for obfuscation patterns
            matched_patterns, match_line, context_before, context_after = self._find_pattern_matches_with_lines(
                content, self.OBFUSCATION_PATTERNS
            )

            # Calculate encoding depth
            encoding_depth = self._calculate_encoding_depth(content)

            if matched_patterns or encoding_depth >= 3:
                severity = Severity.HIGH if encoding_depth >= 3 else Severity.MEDIUM
                confidence = min(0.6 + (len(matched_patterns) * 0.15) + ((encoding_depth - 2) * 0.1 if encoding_depth > 2 else 0), 0.95)

                evidences.append(self._create_evidence(
                    title=f"Multi-Layer Obfuscation Detected: {filepath}",
                    description=(
                        f"File {filepath} contains {len(matched_patterns)} obfuscation pattern(s) "
                        f"with encoding depth {encoding_depth}. "
                        f"Patterns: {', '.join(m[:40] for m in matched_patterns[:2])}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    attack_id="T1027",
                    source_path=filepath,
                    raw_data={
                        "path": filepath,
                        "matched_patterns": matched_patterns[:5],
                        "encoding_depth": encoding_depth
                    },
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"Obfuscation: {len(matched_patterns)} patterns, depth {encoding_depth}",
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))

        return evidences

    def _calculate_encoding_depth(self, content: str) -> int:
        """Calculate nested encoding depth"""
        depth = 0
        current = content

        # Check for nested encoding patterns
        while True:
            found_encoding = False

            for pattern, _ in self.ENCODING_FUNCTIONS:
                if pattern.search(current):
                    found_encoding = True
                    break

            # If no encoding function found, break
            if not found_encoding:
                break

            # Count all encoding functions at current level
            encoding_count = 0
            for pattern, _ in self.ENCODING_FUNCTIONS:
                if pattern.search(current):
                    encoding_count += 1

            depth += encoding_count

            # Find innermost encoding call and extract its argument
            match = re.search(
                r'(?:base64_decode|gzinflate|str_rot13|gzuncompress|gzdecode|rawurldecode|urldecode)\s*\(([^)]+)\)',
                current
            )
            if match:
                current = match.group(1)
            else:
                break

        return max(depth, 0)

    def _check_phpfpm_abuse(self, process_data: dict) -> List[Evidence]:
        """Detect unauthorized php-fpm socket access"""
        evidences = []

        for proc in process_data.get("processes", []):
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            ppid = proc.get("ppid", 0)
            exe = proc.get("exe", "")
            uid = proc.get("uid", -1)

            if not cmdline:
                continue

            # Check for php-fpm processes
            if 'php-fpm' in cmdline or 'php-fpm' in exe.lower():
                # Get parent process name
                parent_name = ""
                try:
                    with open(f'/proc/{ppid}/comm', 'r', errors='ignore', encoding='utf-8') as f:
                        parent_name = f.read().strip()
                except OSError:
                    pass

                # If parent is not a legitimate web server, flag it
                is_legitimate = any(
                    ws in parent_name.lower() or ws in cmdline.lower()
                    for ws in self.LEGITIMATE_WEBSERVERS
                )

                # Also check if running as root (suspicious for php-fpm workers)
                is_root = (uid == 0)

                if not is_legitimate:
                    severity = Severity.CRITICAL if is_root else Severity.HIGH
                    confidence = 0.75 if is_root else 0.65

                    evidences.append(self._create_evidence(
                        title=f"Unauthorized php-fpm Process Detected: PID {pid}",
                        description=(
                            f"Process {exe} (PID: {pid}) appears to be using php-fpm "
                            f"but parent process ({parent_name or 'unknown'}) is not "
                            f"a recognized web server. Running as: {'root' if is_root else f'UID {uid}'}."
                        ),
                        severity=severity,
                        confidence=confidence,
                        attack_id="T1505.003",
                        source_path=exe,
                        raw_data={
                            "pid": pid,
                            "ppid": ppid,
                            "exe": exe,
                            "cmdline": cmdline,
                            "parent_process": parent_name,
                            "uid": uid,
                            "is_root": is_root
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=cmdline[:500] if cmdline else None,
                            executable=exe if exe else None,
                        ),
                        remediation_commands=[
                            f"kill -9 {pid}",
                            f"cat /proc/{pid}/cmdline",
                            "Scan for other webshells",
                            "Review web server logs"
                        ]
                    ))

        return evidences

    def _check_webshell_persistence(self, webroot_files: list, cron_data: dict) -> List[Evidence]:
        """Correlate webshells with cron-based persistence"""
        evidences = []

        # Build list of all cron commands
        cron_commands = []

        # System crontab
        for entry in cron_data.get("system_crontab", []):
            cron_commands.append({
                "command": entry.get("command", ""),
                "schedule": entry.get("schedule", ""),
                "user": entry.get("user", "root"),
                "source": entry.get("source", "")
            })

        # Cron.d entries
        for entry in cron_data.get("cron_d_entries", []):
            cron_commands.append({
                "command": entry.get("command", ""),
                "schedule": entry.get("schedule", ""),
                "user": entry.get("user", ""),
                "source": entry.get("file", "")
            })

        # User crontabs
        for user_entry in cron_data.get("user_crontabs", []):
            user = user_entry.get("user", "unknown")
            for entry in user_entry.get("entries", []):
                cron_commands.append({
                    "command": entry.get("command", ""),
                    "schedule": entry.get("schedule", ""),
                    "user": user,
                    "source": f"user_crontab:{user}"
                })

        # Check if any webroot file is referenced in cron jobs
        for file_info in webroot_files:
            filepath = file_info.get("path", "")
            if not filepath:
                continue

            for cron_job in cron_commands:
                command = cron_job.get("command", "")
                if filepath in command:
                    # Web file executed by cron = high suspicion
                    evidences.append(self._create_evidence(
                        title=f"Webshell Persistence via Cron: {filepath}",
                        description=(
                            f"Web-accessible file {filepath} is executed by cron job "
                            f"(schedule: {cron_job['schedule']}, user: {cron_job['user']}, "
                            f"source: {cron_job['source']}). This indicates potential "
                            f"persistence mechanism."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=0.85,
                        attack_id="T1053.003",
                        source_path=filepath,
                        raw_data={
                            "webshell_path": filepath,
                            "cron_schedule": cron_job["schedule"],
                            "cron_user": cron_job["user"],
                            "cron_source": cron_job["source"],
                            "cron_command": command
                        },
                        evidence_details=EvidenceDetail(
                            file_path=filepath,
                            content=f"Cron persistence: {cron_job['schedule']}",
                        ),
                        remediation_commands=[
                            f"rm -f {filepath}",
                            "Scan for other webshells",
                            "Review web server logs",
                            "Patch web application vulnerabilities"
                        ]
                    ))

        return evidences

    def _check_base64_content(self, webroot_files: list) -> List[Evidence]:
        """Detect files with excessive base64-encoded content"""
        evidences = []
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')

        for file_info in webroot_files:
            filepath = file_info.get("path", "")
            ext = file_info.get("extension", "").lower()

            if not ext:
                ext = os.path.splitext(filepath)[1].lower()

            if ext not in self.ENTROPY_THRESHOLDS:
                continue

            if self._is_safe_path(filepath):
                continue

            content = file_info.get("content_sample", "")
            if not content:
                try:
                    with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                        content = f.read(65536)
                except OSError:
                    continue

            if not content:
                continue

            total_length = len(content)
            base64_matches = base64_pattern.findall(content)
            base64_length = sum(len(m) for m in base64_matches)
            base64_ratio = base64_length / total_length if total_length > 0 else 0

            thresholds = self.BASE64_THRESHOLDS
            long_matches = [m for m in base64_matches if len(m) >= thresholds['min_length']]

            if (base64_ratio > thresholds['ratio_threshold'] and
                len(long_matches) >= thresholds['min_occurrences']):

                # Find first base64 string line number and context
                first_base64_line = None
                context_before = []
                context_after = []
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    if base64_pattern.search(line):
                        first_base64_line = line_num
                        context_before = lines[max(0, line_num-4):line_num-1]
                        context_after = lines[line_num:min(len(lines), line_num+3)]
                        break

                evidences.append(self._create_evidence(
                    title=f"Webshell Base64 Content Detected: {filepath}",
                    description=(
                        f"File {filepath} contains {len(long_matches)} long base64 strings "
                        f"({base64_ratio:.1%} of file content). This may indicate "
                        f"encoded malicious payload."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    attack_id="T1027",
                    source_path=filepath,
                    raw_data={
                        "path": filepath,
                        "base64_ratio": round(base64_ratio, 3),
                        "long_base64_count": len(long_matches),
                        "total_base64_count": len(base64_matches),
                        "file_type": ext
                    },
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        content=f"Base64 content: {base64_ratio:.1%}",
                        line_number=first_base64_line,
                        context_before=context_before,
                        context_after=context_after,
                    ),
                    remediation_commands=[
                        f"rm -f {filepath}",
                        "Scan for other webshells",
                        "Review web server logs",
                        "Patch web application vulnerabilities"
                    ]
                ))

        return evidences

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy

    def _is_safe_path(self, filepath: str) -> bool:
        """Check if file is in a known safe installation path."""
        normalized_path = os.path.realpath(filepath)

        # Check standard safe paths
        if any(normalized_path.startswith(safe) for safe in self.SAFE_PATHS):
            return True

        # Check for Python site-packages paths
        if self._is_python_site_package(normalized_path):
            return True

        return False

    def _is_python_site_package(self, filepath: str) -> bool:
        """Check if file belongs to Python site-packages or standard library."""
        normalized = filepath

        # Check known Python paths
        if any(normalized.startswith(p) for p in self.PYTHON_SITE_PATHS):
            return True

        # Check for site-packages or dist-packages in path
        if '/site-packages/' in normalized or '/dist-packages/' in normalized:
            return True

        if re.search(r'/conda/pkgs/python-[\d.]+-[a-z0-9_]+/lib/python\d+\.\d+/', normalized):
            return True

        # Check for Python standard library path pattern: lib/pythonX.XX/
        # This catches stdlib files that are NOT in site-packages
        if re.search(r'/lib/python\d+\.\d+/(?!site-packages|dist-packages)', normalized):
            # Verify it's not in a web-accessible directory
            if not any(normalized.startswith(p) for p in ['/var/www/', '/usr/share/nginx/', '/usr/share/apache2/']):
                return True

        # Check against Python base prefix (for virtual environments)
        # Only match if it's clearly a Python installation path
        try:
            import sys
            base_prefix = getattr(sys, 'base_prefix', sys.prefix)
            if base_prefix and '/lib/python' in normalized and normalized.startswith(base_prefix):
                return True
        except (OSError, UnicodeDecodeError):
            pass

        return False
