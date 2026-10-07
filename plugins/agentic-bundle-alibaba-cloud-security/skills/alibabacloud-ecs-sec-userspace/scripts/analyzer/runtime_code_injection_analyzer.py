"""Runtime Code Injection Detection Analyzer"""
import re
import logging
from typing import List, Dict
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer
from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp
from ..utils.i18n import get_attack_tactic_name

logger = logging.getLogger("sec-userspace")


class RuntimeCodeInjectionAnalyzer(BaseAnalyzer):
    """Runtime Code Injection Detection Analyzer
    
    Detects:
    - Dynamic library loading from suspicious paths (LD_PRELOAD, LD_LIBRARY_PATH)
    - Runtime code generation and eval() abuse
    - Memory-based code execution (/dev/shm, memfd_create)
    - Process injection and runtime patching
    - Import hook manipulation
    """
    name = "runtime_code_injection_analyzer"
    timeout = 30
    required_collectors = ["process"]
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    estimated_time = 2.5
    analyzer_type = BaseAnalyzer.IMPORTANT

    # Dynamic library loading patterns
    DYNAMIC_LIB_PATTERNS = [
        re.compile(r'LD_PRELOAD\s*=\s*/tmp/', re.IGNORECASE),
        re.compile(r'LD_PRELOAD\s*=\s*/dev/shm/', re.IGNORECASE),
        re.compile(r'LD_PRELOAD\s*=\s*/var/tmp/', re.IGNORECASE),
        re.compile(r'LD_LIBRARY_PATH\s*=.*:/tmp/', re.IGNORECASE),
        re.compile(r'LD_LIBRARY_PATH\s*=.*:/dev/shm/', re.IGNORECASE),
        re.compile(r'dlopen\s*\(\s*["\']\/(tmp|dev\/shm|var\/tmp)', re.IGNORECASE),
        re.compile(r'ctypes\.CDLL\s*\(\s*["\']\/(tmp|dev\/shm|var\/tmp)', re.IGNORECASE),
        re.compile(r'ctypes\.cdll\.LoadLibrary\s*\(\s*["\']\/(tmp|dev\/shm|var\/tmp)', re.IGNORECASE),
    ]

    # Runtime code generation patterns
    CODE_GEN_PATTERNS = [
        # Python eval/exec with dynamic input
        (re.compile(r'eval\s*\(\s*(input|sys\.stdin|os\.environ)', re.IGNORECASE), 
         "eval() with user input"),
        (re.compile(r'exec\s*\(\s*compile\s*\(', re.IGNORECASE),
         "exec() with compile()"),
        (re.compile(r'types\.FunctionType\s*\(', re.IGNORECASE),
         "Dynamic function creation via types.FunctionType"),
        
        # Node.js
        (re.compile(r'new\s+Function\s*\(', re.IGNORECASE),
         "Dynamic Function constructor"),
        (re.compile(r'eval\s*\(\s*Buffer\.from', re.IGNORECASE),
         "eval() with Buffer content"),
        
        # General dynamic import
        (re.compile(r'__import__\s*\(\s*(input|sys\.argv|os\.environ)', re.IGNORECASE),
         "Dynamic __import__ with user input"),
        (re.compile(r'importlib\.import_module\s*\(\s*(input|sys\.argv)', re.IGNORECASE),
         "importlib.import_module with user input"),
    ]

    # Memory-based execution indicators
    MEMORY_EXECUTION_INDICATORS = [
        (re.compile(r'/dev/shm/.*\.(so|py|js|elf|bin)', re.IGNORECASE),
         "Executable file in shared memory"),
        (re.compile(r'memfd_create', re.IGNORECASE),
         "memfd_create syscall (fileless execution)"),
        (re.compile(r'anonymous.*PROT_EXEC', re.IGNORECASE),
         "Anonymous executable memory mapping"),
        (re.compile(r'/proc/\d+/mem.*write', re.IGNORECASE),
         "Direct process memory write"),
    ]

    # Runtime patching detection patterns
    PATCHING_INDICATORS = [
        (re.compile(r'ptrace\s*\(\s*PTRACE_POKETEXT', re.IGNORECASE),
         "ptrace POKETEXT (code injection)"),
        (re.compile(r'ptrace\s*\(\s*PTRACE_POKEDATA', re.IGNORECASE),
         "ptrace POKEDATA (data injection)"),
        (re.compile(r'mprotect\s*\(.*PROT_EXEC', re.IGNORECASE),
         "mprotect with PROT_EXEC (memory permission change)"),
        (re.compile(r'mmap\s*\(.*PROT_EXEC', re.IGNORECASE),
         "mmap with PROT_EXEC (executable mapping)"),
        (re.compile(r'/proc/\d+/mem\s+write', re.IGNORECASE),
         "Process memory modification"),
    ]

    # Import hook manipulation patterns
    IMPORT_HOOK_PATTERNS = [
        (re.compile(r'sys\.meta_path\s*=', re.IGNORECASE),
         "sys.meta_path manipulation"),
        (re.compile(r'sys\.meta_path\.(append|insert)', re.IGNORECASE),
         "Import hook registration via meta_path"),
        (re.compile(r'importlib\.abc\.MetaPathFinder', re.IGNORECASE),
         "Custom MetaPathFinder implementation"),
        (re.compile(r'importlib\.abc\.Loader', re.IGNORECASE),
         "Custom Loader implementation"),
        (re.compile(r'sys\.modules\s*\[.*\]\s*=', re.IGNORECASE),
         "sys.modules manipulation"),
    ]

    # Legitimate development tools whitelist
    LEGITIMATE_DEV_TOOLS = {
        'gdb', 'lldb', 'strace', 'ltrace', 'valgrind',
        'python3', 'python', 'node', 'npm', 'ipython',
        'pytest', 'unittest', 'coverage',
    }

    # Standard library paths (not suspicious)
    STANDARD_LIB_PATHS = {
        '/usr/lib/python3',
        '/usr/local/lib/python3',
        '/usr/lib/node_modules',
        '/usr/local/lib/node_modules',
    }

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute runtime code injection analysis"""
        evidences = []
        
        tracker = get_tracker()
        tracker.record_detection('runtime_code_injection_analyzer', 1)

        process_data = self._get_data(collected_data, "process")
        if not process_data:
            return evidences

        processes = process_data.get("processes", [])

        # 1. Dynamic library loading detection
        evidences.extend(self._detect_dynamic_lib_loading(processes))

        # 2. Runtime code generation detection
        evidences.extend(self._detect_runtime_code_gen(processes))

        # 3. Memory-based execution detection
        evidences.extend(self._detect_memory_execution(processes))

        # 4. Runtime patching detection
        evidences.extend(self._detect_runtime_patching(processes))

        # 5. Import hook abuse detection
        evidences.extend(self._detect_import_hook_abuse(processes))

        return evidences

    def _is_legitimate_process(self, proc: Dict) -> bool:
        """Check if process is a legitimate development tool"""
        comm = proc.get("comm", "").lower()
        exe = proc.get("exe", "").lower()
        proc.get("cmdline", "").lower()

        # Check against whitelist
        if comm in self.LEGITIMATE_DEV_TOOLS:
            return True

        # Check if running from standard library paths
        for lib_path in self.STANDARD_LIB_PATHS:
            if exe.startswith(lib_path):
                return True

        return False

    def _detect_dynamic_lib_loading(self, processes: List[Dict]) -> List[Evidence]:
        """Detect dynamic library loading from suspicious paths"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_process(proc):
                continue

            cmdline = proc.get("cmdline", "")
            environ = proc.get("environ", {})
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")

            # Check environment variables
            ld_preload = environ.get("LD_PRELOAD", "")
            ld_library_path = environ.get("LD_LIBRARY_PATH", "")

            # Check LD_PRELOAD
            if ld_preload:
                suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/']
                if any(ld_preload.startswith(path) for path in suspicious_paths):
                    context = f"{comm} PID={pid} LD_PRELOAD={ld_preload}"
                    if is_false_positive('runtime_code_injection_analyzer', 'dynamic_lib_loading', context=context):
                        record_fp('runtime_code_injection_analyzer', 'dynamic_lib_loading',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1574.006",
                            attack_tactic=get_attack_tactic_name("T1574.006"),
                            title="Suspicious LD_PRELOAD from temporary directory",
                            description=f"Process {comm} (PID {pid}) loading library from suspicious path: {ld_preload}",
                            confidence=0.85,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "LD_PRELOAD": ld_preload,
                                "cmdline": cmdline[:500]
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))

            # Check LD_LIBRARY_PATH for suspicious entries
            if ld_library_path:
                suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/']
                paths = ld_library_path.split(':')
                suspicious_entries = [p for p in paths if any(p.startswith(sp) for sp in suspicious_paths)]
                
                if suspicious_entries:
                    context = f"{comm} PID={pid} LD_LIBRARY_PATH={ld_library_path}"
                    if is_false_positive('runtime_code_injection_analyzer', 'dynamic_lib_loading', context=context):
                        record_fp('runtime_code_injection_analyzer', 'dynamic_lib_loading',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.MEDIUM,
                            attack_id="T1574.006",
                            attack_tactic=get_attack_tactic_name("T1574.006"),
                            title="Suspicious LD_LIBRARY_PATH entry",
                            description=f"Process {comm} (PID {pid}) has suspicious library paths: {suspicious_entries}",
                            confidence=0.7,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "LD_LIBRARY_PATH": ld_library_path,
                                "suspicious_paths": suspicious_entries
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))

            # Check cmdline for dlopen or ctypes usage
            for pattern in self.DYNAMIC_LIB_PATTERNS:
                if pattern.search(cmdline):
                    context = f"{comm} PID={pid} pattern={pattern.pattern}"
                    if is_false_positive('runtime_code_injection_analyzer', 'dynamic_lib_loading', context=context):
                        record_fp('runtime_code_injection_analyzer', 'dynamic_lib_loading',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1055.002",
                            attack_tactic=get_attack_tactic_name("T1055.002"),
                            title="Dynamic library loading from suspicious path",
                            description=f"Process {comm} (PID {pid}) executing: {cmdline[:200]}",
                            confidence=0.75,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cmdline": cmdline[:500],
                                "matched_pattern": pattern.pattern
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                        break

        return evidences

    def _detect_runtime_code_gen(self, processes: List[Dict]) -> List[Evidence]:
        """Detect runtime code generation patterns"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_process(proc):
                continue

            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")

            for pattern, desc in self.CODE_GEN_PATTERNS:
                if pattern.search(cmdline):
                    context = f"{comm} PID={pid} pattern={desc}"
                    if is_false_positive('runtime_code_injection_analyzer', 'runtime_code_gen', context=context):
                        record_fp('runtime_code_injection_analyzer', 'runtime_code_gen',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1059.006",
                            attack_tactic=get_attack_tactic_name("T1059.006"),
                            title=f"Runtime code generation detected: {desc}",
                            description=f"Process {comm} (PID {pid}) using {desc}: {cmdline[:200]}",
                            confidence=0.75,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cmdline": cmdline[:500],
                                "pattern_description": desc
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                        break

        return evidences

    def _detect_memory_execution(self, processes: List[Dict]) -> List[Evidence]:
        """Detect memory-based code execution"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_process(proc):
                continue

            cmdline = proc.get("cmdline", "")
            cwd = proc.get("cwd", "")
            exe = proc.get("exe", "")
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")

            # Check for execution from /dev/shm
            for path_field in [exe, cwd, cmdline]:
                if '/dev/shm/' in path_field:
                    # Check if it's an executable or script
                    if any(path_field.endswith(ext) for ext in ['.so', '.py', '.js', '.elf', '.bin', '.sh']):
                        context = f"{comm} PID={pid} path={path_field}"
                        if is_false_positive('runtime_code_injection_analyzer', 'memory_execution', context=context):
                            record_fp('runtime_code_injection_analyzer', 'memory_execution',
                                     context=f'Suppressed: {context}')
                        else:
                            evidences.append(self._create_evidence(
                                severity=Severity.CRITICAL,
                                attack_id="T1620",
                                attack_tactic=get_attack_tactic_name("T1620"),
                                title="Execution from shared memory (/dev/shm)",
                                description=f"Process {comm} (PID {pid}) executing from shared memory: {path_field[:200]}",
                                confidence=0.85,
                                raw_data={
                                    "pid": pid,
                                    "comm": comm,
                                    "exe": exe,
                                    "cwd": cwd,
                                    "cmdline": cmdline[:500]
                                },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                            break

            # Check for memfd_create or other memory execution indicators
            for pattern, desc in self.MEMORY_EXECUTION_INDICATORS:
                if pattern.search(cmdline):
                    context = f"{comm} PID={pid} indicator={desc}"
                    if is_false_positive('runtime_code_injection_analyzer', 'memory_execution', context=context):
                        record_fp('runtime_code_injection_analyzer', 'memory_execution',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1620",
                            attack_tactic=get_attack_tactic_name("T1620"),
                            title=f"Memory-based execution indicator: {desc}",
                            description=f"Process {comm} (PID {pid}): {cmdline[:200]}",
                            confidence=0.7,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cmdline": cmdline[:500],
                                "indicator": desc
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                        break

        return evidences

    def _detect_runtime_patching(self, processes: List[Dict]) -> List[Evidence]:
        """Detect runtime code patching"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_process(proc):
                continue

            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")

            for pattern, desc in self.PATCHING_INDICATORS:
                if pattern.search(cmdline):
                    context = f"{comm} PID={pid} indicator={desc}"
                    if is_false_positive('runtime_code_injection_analyzer', 'runtime_patching', context=context):
                        record_fp('runtime_code_injection_analyzer', 'runtime_patching',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1055",
                            attack_tactic=get_attack_tactic_name("T1055"),
                            title=f"Runtime code patching detected: {desc}",
                            description=f"Process {comm} (PID {pid}) performing {desc}: {cmdline[:200]}",
                            confidence=0.8,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cmdline": cmdline[:500],
                                "patching_indicator": desc
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                        break

        return evidences

    def _detect_import_hook_abuse(self, processes: List[Dict]) -> List[Evidence]:
        """Detect import hook manipulation"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_process(proc):
                continue

            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")

            for pattern, desc in self.IMPORT_HOOK_PATTERNS:
                if pattern.search(cmdline):
                    context = f"{comm} PID={pid} indicator={desc}"
                    if is_false_positive('runtime_code_injection_analyzer', 'import_hook_abuse', context=context):
                        record_fp('runtime_code_injection_analyzer', 'import_hook_abuse',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.MEDIUM,
                            attack_id="T1059.006",
                            attack_tactic=get_attack_tactic_name("T1059.006"),
                            title=f"Import hook manipulation detected: {desc}",
                            description=f"Process {comm} (PID {pid}) manipulating import system: {cmdline[:200]}",
                            confidence=0.65,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cmdline": cmdline[:500],
                                "hook_type": desc
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                        break

        return evidences
