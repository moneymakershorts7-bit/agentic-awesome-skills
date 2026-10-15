"""AI Agent Memory Inspection Analyzer

Detection capabilities:
1. Vector database access anomaly detection (ChromaDB, Pinecone, Weaviate, Qdrant, Milvus)
2. Context window manipulation and memory poisoning detection
3. AI session cache inspection (Redis, Memcached)
4. Conversation history log analysis for sensitive data exposure
5. Temporary file creation with AI context data
6. Bulk embedding extraction patterns
7. Memory persistence attack detection

ATT&CK mapping:
- T1530 - Data from Cloud Storage Object
- T1565.001 - Data Manipulation: Stored Data Manipulation
- T1005 - Data from Local System
- T1039 - Data from Network Shared Drive
- T1566.004 - Spearphishing Content: Credential Harvesting
"""
import os
import re
import time
import logging
from typing import List, Dict
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from ..utils.remediation_generator import generate_process_remediation, generate_generic_remediation
from .base import BaseAnalyzer
logger = logging.getLogger('sec-userspace')
_VECTOR_DB_MEMORY_INDICATORS = {'chromadb': {'processes': ['chroma', 'chromadb'], 'ports': [8000, 8001], 'data_dirs': ['/chroma/data', '/var/lib/chroma', '.chroma'], 'file_patterns': ['*.sqlite', '*.bin', 'chroma.sqlite3'], 'python_packages': ['chromadb', 'chroma-hnswlib']}, 'pinecone': {'processes': [], 'ports': [], 'data_dirs': [], 'file_patterns': [], 'python_packages': ['pinecone-client', 'pinecone'], 'env_indicators': ['PINECONE_API_KEY', 'PINECONE_ENVIRONMENT']}, 'weaviate': {'processes': ['weaviate'], 'ports': [8080, 50051], 'data_dirs': ['/var/lib/weaviate', 'weaviate_data'], 'file_patterns': ['*.hdf5', '*.lsm'], 'python_packages': ['weaviate-client']}, 'qdrant': {'processes': ['qdrant'], 'ports': [6333, 6334], 'data_dirs': ['/qdrant/storage', '/var/lib/qdrant'], 'file_patterns': ['*.snap', '*.wal'], 'python_packages': ['qdrant-client']}, 'milvus': {'processes': ['milvus', 'milvus-server'], 'ports': [19530, 19121], 'data_dirs': ['/var/lib/milvus', '/milvus/data'], 'file_patterns': ['*.idx', '*.bin'], 'python_packages': ['pymilvus']}, 'faiss': {'processes': [], 'ports': [], 'data_dirs': [], 'file_patterns': ['*.index', '*.faiss', '*.bin'], 'python_packages': ['faiss', 'faiss-cpu', 'faiss-gpu']}}
_CACHE_SYSTEM_INDICATORS = {'redis': {'processes': ['redis-server', 'redis-cli'], 'ports': [6379, 6380], 'data_dirs': ['/var/lib/redis', '/redis-data'], 'file_patterns': ['dump.rdb', 'appendonly.aof'], 'keys_patterns': ['session:*', 'ai:*', 'context:*', 'conversation:*']}, 'memcached': {'processes': ['memcached'], 'ports': [11211], 'data_dirs': [], 'file_patterns': [], 'keys_patterns': ['session', 'cache', 'ai_context']}}
_MEMORY_POISONING_PATTERNS = [(re.compile('(?:remember|note|important)[\\s:]+\\s*(?:from\\s+)?(?:now\\s+on|going\\s+forward|always)', re.IGNORECASE), 'Memory injection instruction detected', Severity.HIGH, 'T1565.001'), (re.compile('(?:from\\s+this\\s+point|from\\s+now\\s+on|henceforth)[,\\s]+(?:you\\s+)?(?:must|should|will)', re.IGNORECASE), 'Persistent behavioral override attempt', Severity.HIGH, 'T1059'), (re.compile('(?:system\\s+)?(?:rule|policy|constraint)[\\s:]+\\s*(?:ignore|bypass|override)', re.IGNORECASE), 'Fabricated policy rule injection', Severity.CRITICAL, 'T1565.001'), (re.compile('<\\|(?:memory|context|state)\\|>', re.IGNORECASE), 'Context/memory delimiter injection', Severity.MEDIUM, 'T1059'), (re.compile('<!--\\s*(?:system|memory|context|instruction).*?-->', re.IGNORECASE | re.DOTALL), 'Hidden instruction in HTML comment', Severity.MEDIUM, 'T1565.001'), (re.compile('(?:bulk|batch)\\s*(?:upsert|insert|embed).*?(?:vector|embedding)', re.IGNORECASE), 'Bulk vector upsert operation detected', Severity.HIGH, 'T1565.001'), (re.compile('(?:modify|alter|update)\\s*(?:embedding|vector|index).*?(?:without|bypass)\\s*(?:auth|validation)', re.IGNORECASE), 'Unauthorized vector index modification', Severity.CRITICAL, 'T1565.001'), (re.compile('(?:ingest|scrape|fetch).*(?:poisoned|malicious|compromised)', re.IGNORECASE), 'RAG ingestion from suspicious source', Severity.HIGH, 'T1565.001'), (re.compile('(?:document|knowledge).*?(?:inject|insert).*(?:trigger|payload)', re.IGNORECASE), 'Knowledge base injection attempt', Severity.HIGH, 'T1565.001'), (re.compile('(?:share|bleed|leak).*(?:memory|context|session).*?(?:between|across)', re.IGNORECASE), 'Cross-session memory contamination', Severity.HIGH, 'T1565.001'), (re.compile('(?:global|shared).*(?:memory|cache|context).*?(?:overwrite|corrupt)', re.IGNORECASE), 'Shared memory store manipulation', Severity.HIGH, 'T1565.001'), (re.compile('(?:when|if).*(?:see|hear|read).*(?:phrase|trigger|code).*?(?:then|activate|execute)', re.IGNORECASE), 'Delayed activation trigger insertion', Severity.CRITICAL, 'T1565.001'), (re.compile('(?:extract|retrieve|leak).*(?:system|prompt|instruction).*(?:from|via).*(?:memory|context)', re.IGNORECASE), 'System prompt extraction via memory', Severity.CRITICAL, 'T1566.004')]
_SENSITIVE_DATA_PATTERNS = [(re.compile('(?:api[_-]?key|apikey|token|bearer)[\\s]*[=:]\\s*["\\\']?[a-zA-Z0-9_\\-]{20,}', re.IGNORECASE), 'API key or token in AI memory', Severity.CRITICAL, 'T1566.004'), (re.compile('AKIA[0-9A-Z]{16}'), 'AWS Access Key ID in AI memory', Severity.CRITICAL, 'T1566.004'), (re.compile('-----BEGIN\\s+(?:RSA\\s+)?PRIVATE\\s+KEY-----'), 'Private key in AI memory/cache', Severity.CRITICAL, 'T1566.004'), (re.compile('(?:mongodb|postgres|mysql|redis)://[^\\s"\\\']+:[^\\s"\\\']+@', re.IGNORECASE), 'Database connection string with credentials', Severity.HIGH, 'T1566.004'), (re.compile('\\b(?:SSN|social\\s+security)[\\s:]*\\d{3}-\\d{2}-\\d{4}\\b', re.IGNORECASE), 'Social Security Number in AI memory', Severity.CRITICAL, 'T1566.004')]
_MEMORY_DUMP_EXTENSIONS = {'.mem', '.dmp', '.dump', '.core', '.ckpt', '.pt', '.pth', '.bin'}
_CONVERSATION_LOG_PATTERNS = ['*conversation*.log', '*chat*.log', '*dialog*.log', '*history*.json', '*session*.json', '*memory*.json', 'conversation_history*', 'chat_history*']

def _matches_conversation_pattern(filename: str, pattern: str) -> bool:
    """Check if filename matches conversation log pattern
    
    Args:
        filename: Lowercase filename to check
        pattern: Glob-style pattern (e.g., '*conversation*.log')
    
    Returns:
        bool: True if matches
    """
    import fnmatch
    return fnmatch.fnmatch(filename, pattern)

class MemoryInspectionAnalyzer(BaseAnalyzer):
    """AI Agent Memory Inspection Analyzer
    
    Detects attacks and vulnerabilities related to AI agent memory:
    - Vector database access anomalies
    - Memory poisoning attempts
    - Session cache data exposure
    - Conversation history sensitive data leaks
    - Context window manipulation
    """
    name = 'memory_inspection_analyzer'
    timeout = 90
    required_collectors = ['process', 'filesystem', 'network']

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute memory inspection analysis"""
        evidences = []
        try:
            process_data = self._get_data(collected_data, 'process')
        except KeyError:
            process_data = {}
        try:
            filesystem_data = self._get_data(collected_data, 'filesystem')
        except KeyError:
            filesystem_data = {}
        try:
            network_data = self._get_data(collected_data, 'network')
        except KeyError:
            network_data = {}
        try:
            log_data = self._get_data(collected_data, 'log')
        except KeyError:
            log_data = {}
        evidences.extend(self._detect_vector_db_anomalies(process_data, filesystem_data, network_data))
        evidences.extend(self._scan_memory_poisoning(filesystem_data))
        evidences.extend(self._detect_cache_data_exposure(filesystem_data, process_data))
        evidences.extend(self._detect_suspicious_memory_dumps(filesystem_data))
        evidences.extend(self._analyze_context_manipulation(filesystem_data))
        evidences.extend(self._detect_vector_db_poisoning(filesystem_data, process_data))
        evidences.extend(self._detect_rag_contamination(filesystem_data))
        evidences.extend(self._detect_cross_session_attacks(filesystem_data, log_data))
        return evidences

    def _detect_vector_db_anomalies(self, process_data: Dict, filesystem_data: Dict, network_data: Dict) -> List[Evidence]:
        """Detect unauthorized vector database access and bulk extraction"""
        evidences = []
        processes = process_data.get('processes', [])
        files = filesystem_data.get('files', [])
        connections = network_data.get('connections', [])
        vector_db_access = {}
        for db_name, indicators in _VECTOR_DB_MEMORY_INDICATORS.items():
            detected_via = []
            for proc in processes:
                cmdline = proc.get('cmdline', '')
                exe = proc.get('exe', '')
                proc_name = os.path.basename(exe) if exe else ''
                for proc_pattern in indicators['processes']:
                    if proc_pattern in proc_name.lower() or proc_pattern in cmdline.lower():
                        detected_via.append(f"process: {proc_name or cmdline[:80]} (PID {proc.get('pid', '?')})")
                        pid = proc.get('pid')
                        if pid:
                            vector_db_access[pid] = {'db': db_name, 'type': 'process'}
                        break
            for conn in connections:
                local_port = conn.get('local_port', 0)
                if local_port in indicators['ports']:
                    local_addr = conn.get('local_addr', '')
                    detected_via.append(f'port: {local_addr}:{local_port}')
            for file_info in files:
                filepath = file_info.get('path', '')
                filename = os.path.basename(filepath).lower()
                for pattern in indicators['file_patterns']:
                    if pattern.startswith('*'):
                        if filename.endswith(pattern[1:]):
                            detected_via.append(f'file: {filepath}')
                            vector_db_access[filepath] = {'db': db_name, 'type': 'file_access'}
                            break
                    elif pattern.lower() in filepath.lower():
                        detected_via.append(f'file: {filepath}')
                        vector_db_access[filepath] = {'db': db_name, 'type': 'file_access'}
                        break
                if filepath.endswith('.py'):
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(10000)
                            for pkg in indicators.get('python_packages', []):
                                if re.search(f'(?:import|from)\\s+{re.escape(pkg)}', content):
                                    detected_via.append(f'package_import: {pkg} in {filepath}')
                                    break
                    except OSError:
                        pass
            if detected_via:
                is_exposed = any(('0.0.0.0' in via for via in detected_via))
                severity = Severity.HIGH if is_exposed else Severity.MEDIUM
                evidences.append(self._create_evidence(title=f'Vector Database Access Detected: {db_name.capitalize()}', description=f"Vector database '{db_name}' access detected. Detection methods: {'; '.join(detected_via[:5])}", severity=severity, confidence=0.65, attack_id='T1530', attack_tactic='Collection', source_path=detected_via[0].split(': ', 1)[-1] if detected_via else '', raw_data={'db_name': db_name, 'detected_via': detected_via[:10], 'is_exposed': is_exposed}, remediation=f'Verify that {db_name} access is authorized. Check for bulk embedding extraction attempts. Ensure proper authentication and access controls.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=detected_via[0].split(': ', 1)[-1] if detected_via else ''), remediation_commands=generate_generic_remediation(attack_id='1530', context={'analyzer': 'memory_inspection_analyzer'})))
        current_time = time.time()
        recent_accesses = []
        for file_info in files:
            filepath = file_info.get('path', '')
            mtime = file_info.get('mtime', 0)
            if current_time - mtime < 3600:
                for db_indicator in _VECTOR_DB_MEMORY_INDICATORS.values():
                    for pattern in db_indicator.get('file_patterns', []):
                        if pattern.startswith('*') and filepath.endswith(pattern[1:]):
                            recent_accesses.append(filepath)
                            break
        if len(recent_accesses) >= 5:
            evidences.append(self._create_evidence(title='Bulk Vector Database File Access Detected', description=f'Detected {len(recent_accesses)} vector database files accessed within the last hour. This may indicate unauthorized embedding extraction.', severity=Severity.HIGH, confidence=0.7, attack_id='T1530', attack_tactic='Collection', source_path=recent_accesses[0] if recent_accesses else '', raw_data={'access_count': len(recent_accesses), 'sample_files': recent_accesses[:10]}, remediation='Investigate the process responsible for bulk file access. Check for unauthorized data exfiltration. Review access logs and audit trails.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=recent_accesses[0] if recent_accesses else ''), remediation_commands=generate_generic_remediation(attack_id='1530', context={'analyzer': 'memory_inspection_analyzer'})))
        return evidences

    def _scan_memory_poisoning(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan conversation logs and memory files for poisoning patterns"""
        evidences = []
        files = filesystem_data.get('files', [])
        for file_info in files:
            filepath = file_info.get('path', '')
            filename = os.path.basename(filepath).lower()
            is_conversation_log = any((_matches_conversation_pattern(filename, pattern) for pattern in _CONVERSATION_LOG_PATTERNS))
            if not is_conversation_log:
                continue
            file_size = file_info.get('size', 0)
            if file_size > 10 * 1024 * 1024:
                continue
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(100000)
                for pattern, desc, severity, attack_id in _MEMORY_POISONING_PATTERNS:
                    match = pattern.search(content)
                    if match:
                        matched_text = match.group(0)[:150]
                        if self._check_whitelist(filepath):
                            continue
                        evidences.append(self._create_evidence(title=f'Memory Poisoning Pattern: {desc}', description=f"File '{filepath}' contains memory poisoning pattern: {matched_text}", severity=severity, confidence=0.75, attack_id=attack_id, attack_tactic='Impact', source_path=filepath, raw_data={'pattern_type': desc, 'matched_text': matched_text, 'file_size': file_size}, remediation='Review the conversation log for malicious injections. Clear affected memory/context. Implement input validation for conversation data.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'memory_inspection_analyzer'})))
                        break
            except OSError:
                pass
        return evidences

    def _detect_cache_data_exposure(self, filesystem_data: Dict, process_data: Dict) -> List[Evidence]:
        """Detect sensitive data exposure in AI session caches"""
        evidences = []
        files = filesystem_data.get('files', [])
        processes = process_data.get('processes', [])
        cache_files = []
        for file_info in files:
            filepath = file_info.get('path', '')
            filename = os.path.basename(filepath).lower()
            for cache_name, indicators in _CACHE_SYSTEM_INDICATORS.items():
                for pattern in indicators['file_patterns']:
                    if filename == pattern.lower():
                        cache_files.append({'path': filepath, 'cache': cache_name})
                        break
        for cache_file in cache_files:
            filepath = cache_file['path']
            cache_name = cache_file['cache']
            try:
                with open(filepath, 'rb') as f:
                    content = f.read(500000)
                    try:
                        text_content = content.decode('utf-8', errors='ignore')
                    except (UnicodeDecodeError, AttributeError):
                        text_content = ''
                    for pattern, desc, severity, attack_id in _SENSITIVE_DATA_PATTERNS:
                        match = pattern.search(text_content)
                        if match:
                            matched_text = match.group(0)[:100]
                            if self._check_whitelist(filepath):
                                continue
                            evidences.append(self._create_evidence(title=f'Sensitive Data in {cache_name.capitalize()} Cache', description=f"Cache file '{filepath}' contains {desc}: {matched_text}", severity=severity, confidence=0.8, attack_id=attack_id, attack_tactic='Credential Access', source_path=filepath, raw_data={'cache_type': cache_name, 'data_type': desc, 'matched_text': matched_text}, remediation=f'Clear {cache_name} cache immediately. Rotate exposed credentials. Implement encryption for cache data.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'memory_inspection_analyzer'})))
                            break
            except OSError:
                pass
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            if not cmdline:
                continue
            if re.search('redis-cli.*(?:SAVE|BGSAVE|DUMP)', cmdline, re.IGNORECASE):
                pid = proc.get('pid', 0)
                exe = proc.get('exe', '')
                evidences.append(self._create_evidence(title='Redis Cache Dump Command Detected', description=f'Process PID={pid} ({exe}) is executing a cache dump command. This may indicate data exfiltration.', severity=Severity.HIGH, confidence=0.7, attack_id='T1530', attack_tactic='Collection', source_path=f'/proc/{pid}/cmdline', raw_data={'pid': pid, 'exe': exe, 'cmdline': cmdline[:200]}, remediation='Verify the cache dump operation is authorized. Monitor destination of dumped data.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', pid=pid, cmdline=cmdline[:200], file_path=f'/proc/{pid}/cmdline'), remediation_commands=generate_generic_remediation(attack_id='1530', context={'analyzer': 'memory_inspection_analyzer'})))
        return evidences

    def _detect_suspicious_memory_dumps(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect suspicious memory dump files"""
        evidences = []
        files = filesystem_data.get('files', [])
        sensitive_locations = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/']
        for file_info in files:
            filepath = file_info.get('path', '')
            ext = os.path.splitext(filepath)[1].lower()
            filename = os.path.basename(filepath).lower()
            if ext not in _MEMORY_DUMP_EXTENSIONS:
                continue
            path_lower = filepath.lower()
            in_sensitive_location = any((path_lower.startswith(loc) for loc in sensitive_locations))
            memory_keywords = ['memory', 'context', 'session', 'embedding', 'vector', 'model', 'cache']
            has_memory_keyword = any((kw in filename for kw in memory_keywords))
            if in_sensitive_location or has_memory_keyword:
                file_size = file_info.get('size', 0)
                mtime = file_info.get('mtime', 0)
                age_hours = (time.time() - mtime) / 3600
                severity = Severity.MEDIUM
                if in_sensitive_location and has_memory_keyword:
                    severity = Severity.HIGH
                evidences.append(self._create_evidence(title='Suspicious Memory Dump File Detected', description=f"Memory dump file '{filepath}' found. Size: {file_size / 1024 / 1024:.2f}MB, Age: {age_hours:.1f} hours", severity=severity, confidence=0.6, attack_id='T1005', attack_tactic='Collection', source_path=filepath, raw_data={'path': filepath, 'extension': ext, 'size_bytes': file_size, 'age_hours': age_hours, 'in_sensitive_location': in_sensitive_location}, remediation='Investigate the origin of this memory dump file. Check if it contains sensitive AI context or credentials. Securely delete if unauthorized.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='1005', context={'analyzer': 'memory_inspection_analyzer'})))
        return evidences

    def _analyze_context_manipulation(self, filesystem_data: Dict) -> List[Evidence]:
        """Analyze files for context window manipulation attempts"""
        evidences = []
        files = filesystem_data.get('files', [])
        dir_file_groups = {}
        for file_info in files:
            filepath = file_info.get('path', '')
            ext = os.path.splitext(filepath)[1].lower()
            if ext not in {'.json', '.txt', '.log', '.md'}:
                continue
            parent_dir = os.path.dirname(filepath)
            path_lower = filepath.lower()
            ai_indicators = ['context', 'prompt', 'conversation', 'chat', 'memory', 'session']
            if not any((indicator in path_lower for indicator in ai_indicators)):
                continue
            if parent_dir not in dir_file_groups:
                dir_file_groups[parent_dir] = []
            dir_file_groups[parent_dir].append(file_info)
        current_time = time.time()
        for dir_path, dir_files in dir_file_groups.items():
            if len(dir_files) < 3:
                continue
            recent_files = [f for f in dir_files if current_time - f.get('mtime', 0) < 1800]
            if len(recent_files) >= 3:
                evidences.append(self._create_evidence(title='Bulk Context File Modification Detected', description=f"Directory '{dir_path}' has {len(recent_files)} context-related files modified within the last 30 minutes. This may indicate automated context window poisoning.", severity=Severity.HIGH, confidence=0.65, attack_id='T1565.001', attack_tactic='Impact', source_path=dir_path, raw_data={'directory': dir_path, 'recent_count': len(recent_files), 'total_count': len(dir_files), 'sample_files': [f['path'] for f in recent_files[:5]]}, remediation='Investigate the source of bulk modifications. Check file timestamps and responsible processes. Verify context data integrity.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=dir_path), remediation_commands=generate_generic_remediation(attack_id='1565.001', context={'analyzer': 'memory_inspection_analyzer'})))
        return evidences

    def _detect_vector_db_poisoning(self, filesystem_data: Dict, process_data: Dict) -> List[Evidence]:
        """Detect vector database poisoning attacks

        Detects malicious embeddings injected into vector stores,
        suspicious bulk upsert operations, and unauthorized modifications.
        """
        evidences = []
        files = filesystem_data.get('files', [])
        processes = process_data.get('processes', [])
        poison_patterns = [(re.compile('upsert.*?(?:malicious|poison|trigger)', re.IGNORECASE), 'Malicious vector upsert operation'), (re.compile('embedding.*?(?:inject|insert).*(?:trigger|backdoor)', re.IGNORECASE), 'Embedding injection with trigger pattern'), (re.compile('(?:chroma|pinecone|weaviate|qdrant).*?(?:bulk|batch).*?(?:insert|upsert)', re.IGNORECASE), 'Bulk vector database operation'), (re.compile('vector.*?(?:modify|alter).*(?:without|bypass).*(?:auth|valid)', re.IGNORECASE), 'Unauthorized vector modification')]
        for file_info in files:
            filepath = file_info.get('path', '')
            if not filepath.endswith('.py'):
                continue
            file_size = file_info.get('size', 0)
            if file_size > 5 * 1024 * 1024:
                continue
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)
                for pattern, description in poison_patterns:
                    match = pattern.search(content)
                    if match:
                        vector_db_indicators = ['chroma', 'pinecone', 'weaviate', 'qdrant', 'faiss', 'milvus', 'vector', 'embedding']
                        has_vector_context = any((ind in content.lower() for ind in vector_db_indicators))
                        if not has_vector_context:
                            continue
                        severity = Severity.HIGH if 'malicious' in description.lower() or 'backdoor' in description.lower() else Severity.MEDIUM
                        evidences.append(self._create_evidence(title=f'Vector DB Poisoning: {description}', description=f"File '{filepath}' contains potential vector database poisoning code", severity=severity, confidence=0.65 if has_vector_context else 0.5, attack_id='T1565.001', attack_tactic='Impact', source_path=filepath, raw_data={'filepath': filepath, 'pattern_type': description, 'matched_sample': match.group(0)[:150]}, remediation='Review vector database operations for unauthorized modifications. Implement access controls for embedding upserts. Monitor for bulk injection operations.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='1565.001', context={'analyzer': 'memory_inspection_analyzer'})))
                        break
            except OSError:
                pass
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            pid = proc.get('pid', 0)
            for pattern, description in poison_patterns:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(title=f'Vector DB Poisoning in Process: {description}', description=f'Process PID={pid} shows vector DB poisoning indicators', severity=Severity.HIGH, confidence=0.7, attack_id='T1565.001', attack_tactic='Impact', source_path=f'/proc/{pid}/cmdline', raw_data={'pid': pid, 'cmdline_sample': cmdline[:300]}, remediation='Investigate the process and its vector database operations', evidence_details=EvidenceDetail(pid=pid), remediation_commands=generate_process_remediation(attack_id='T1565.001', context={'analyzer': 'memory_inspection'})))
                    break
        return evidences

    def _detect_rag_contamination(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect RAG (Retrieval-Augmented Generation) source contamination

        Identifies compromised document ingestion, malicious PDF/text processing,
        and knowledge graph manipulation.
        """
        evidences = []
        files = filesystem_data.get('files', [])
        rag_poison_patterns = [(re.compile('(?:document|pdf|text).*?(?:inject|insert).*(?:instruction|payload)', re.IGNORECASE), 'Document injection with embedded instructions'), (re.compile('(?:scrape|fetch|download).*(?:poisoned|malicious).*(?:source|content)', re.IGNORECASE), 'Ingestion from compromised source'), (re.compile('knowledge.*?(?:graph|base).*(?:manipulate|corrupt|poison)', re.IGNORECASE), 'Knowledge base manipulation'), (re.compile('(?:rag|retrieval).*(?:context|embedding).*(?:poison|inject)', re.IGNORECASE), 'RAG context poisoning'), (re.compile('(?:chunk|embed).*(?:malicious|trigger|backdoor)', re.IGNORECASE), 'Malicious chunk/embedding creation')]
        rag_file_patterns = ['*rag*.py', '*retrieval*.py', '*embedding*.py', '*ingest*.py', '*knowledge*.json', '*document*.json', '*chunk*.json']
        for file_info in files:
            filepath = file_info.get('path', '')
            filename = os.path.basename(filepath).lower()
            is_rag_file = any((_matches_conversation_pattern(filename, pattern) for pattern in rag_file_patterns))
            is_relevant_ext = filepath.endswith(('.py', '.json', '.yaml', '.log'))
            if not (is_rag_file or is_relevant_ext):
                continue
            file_size = file_info.get('size', 0)
            if file_size > 5 * 1024 * 1024:
                continue
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)
                rag_indicators = ['rag', 'retrieval', 'embedding', 'chunk', 'document', 'ingest', 'knowledge']
                has_rag_context = any((ind in content.lower() for ind in rag_indicators))
                if not has_rag_context:
                    continue
                for pattern, description in rag_poison_patterns:
                    match = pattern.search(content)
                    if match:
                        evidences.append(self._create_evidence(title=f'RAG Contamination: {description}', description=f"File '{filepath}' contains RAG contamination indicators", severity=Severity.HIGH, confidence=0.65, attack_id='T1565.001', attack_tactic='Impact', source_path=filepath, raw_data={'filepath': filepath, 'contamination_type': description, 'matched_sample': match.group(0)[:150]}, remediation='Review document ingestion pipeline. Sanitize all content before embedding. Implement content validation for RAG sources.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='1565.001', context={'analyzer': 'memory_inspection_analyzer'})))
                        break
            except OSError:
                pass
        return evidences

    def _detect_cross_session_attacks(self, filesystem_data: Dict, log_data: Dict) -> List[Evidence]:
        """Detect cross-session contamination attacks

        Identifies memory bleeding between users/sessions,
        shared context pollution, and cache poisoning.
        """
        evidences = []
        files = filesystem_data.get('files', [])
        cross_session_patterns = [(re.compile('(?:share|bleed|leak).*(?:memory|context|session).*(?:between|across)', re.IGNORECASE), 'Cross-session memory bleeding', Severity.HIGH), (re.compile('(?:global|shared).*(?:memory|cache|context).*(?:pollute|corrupt)', re.IGNORECASE), 'Shared memory pollution', Severity.HIGH), (re.compile('(?:session|user).*(?:data|context).*(?:mix|leak|expose)', re.IGNORECASE), 'Session data leakage', Severity.CRITICAL), (re.compile('cache.*?(?:poison|inject).*(?:global|shared)', re.IGNORECASE), 'Global cache poisoning', Severity.HIGH)]
        session_file_patterns = ['*session*.json', '*cache*.json', '*memory*.json', '*context*.json', '*session*.log', '*cache*.log']
        for file_info in files:
            filepath = file_info.get('path', '')
            filename = os.path.basename(filepath).lower()
            is_session_file = any((_matches_conversation_pattern(filename, pattern) for pattern in session_file_patterns))
            if not is_session_file:
                continue
            file_size = file_info.get('size', 0)
            if file_size > 5 * 1024 * 1024:
                continue
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)
                for pattern, description, severity in cross_session_patterns:
                    match = pattern.search(content)
                    if match:
                        evidences.append(self._create_evidence(title=f'Cross-Session Attack: {description}', description=f"File '{filepath}' contains cross-session attack indicators", severity=severity, confidence=0.7, attack_id='T1565.001', attack_tactic='Impact', source_path=filepath, raw_data={'filepath': filepath, 'attack_type': description, 'matched_sample': match.group(0)[:150]}, remediation='Implement strict session isolation. Add session identifiers to all memory operations. Review shared cache access controls.', evidence_details=self._create_evidence_details(service_type='memory_inspection', content='Memory inspection anomaly detected', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='1565.001', context={'analyzer': 'memory_inspection_analyzer'})))
                        break
            except OSError:
                pass
        app_logs = log_data.get('application', [])
        for log_entry in app_logs:
            message = log_entry.get('message') or ''
            for pattern, description, severity in cross_session_patterns:
                if pattern.search(message):
                    evidences.append(self._create_evidence(title=f'Cross-Session Attack in Log: {description}', description=f'Log entry contains cross-session attack indicators', severity=severity, confidence=0.6, attack_id='T1565.001', attack_tactic='Impact', source_path='application_log', raw_data={'log_message_sample': message[:300], 'attack_type': description}, remediation='Investigate the source of cross-session contamination', evidence_details=EvidenceDetail(content=message[:300]), remediation_commands=['Audit memory access patterns and permissions', 'Review process memory for sensitive data exposure', 'Implement memory protection and access controls', 'Monitor for unauthorized memory inspection']))
                    break
        return evidences