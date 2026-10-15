"""Memory forensics analyzer constants - patterns, heuristics, and configuration.

This module contains all detection patterns, credential patterns, memory region
patterns, ATT&CK mappings, and memory backend configurations used by the
MemoryForensicsAnalyzer.
"""
import re
from ...reporter.evidence import Severity

# Memory forensics detection heuristics (12+ required)
MEMORY_FORENSICS_HEURISTICS = {
    # 1. Memory-Resident Payload Detection
    'memory_resident_payload': {
        'patterns': [
            (re.compile(r'\b(shellcode|payload|stub)\s*(?:in|into)\s*memory', re.IGNORECASE),
             'Shellcode injection into memory', Severity.CRITICAL),
            (re.compile(r'\b(virtual|virtualalloc|malloc|heap).*(?:allocate|write)', re.IGNORECASE),
             'Suspicious memory allocation', Severity.HIGH),
            (re.compile(r'\bexecute\s+in\s+(?:process|memory|thread)', re.IGNORECASE),
             'In-memory code execution', Severity.CRITICAL),
        ],
        'description': 'Detect memory-resident malicious payloads',
        'category': 'process_memory'
    },
    
    # 2. Injected Code Segment Detection
    'injected_code_segment': {
        'patterns': [
            (re.compile(r'\b(inject|load)\s*(?:dll|library|module)\s+into', re.IGNORECASE),
             'DLL/module injection attempt', Severity.CRITICAL),
            (re.compile(r'\b(code|shellcode|payload)\s+injection', re.IGNORECASE),
             'Code injection attempt', Severity.CRITICAL),
            (re.compile(r'\bhollow\s*(?:process|image)', re.IGNORECASE),
             'Process hollowing attempt', Severity.HIGH),
        ],
        'description': 'Detect injected code segments in processes',
        'category': 'process_memory'
    },
    
    # 3. Credential Pattern Matching
    'credential_extraction': {
        'patterns': [
            (re.compile(r'(?:api[_-]?key|apikey|token|secret|credential).*(?:extract|scrape|dump)', re.IGNORECASE),
             'Credential extraction from memory', Severity.CRITICAL),
            (re.compile(r'(?:password|passwd|pwd).*(?:memory|process|scrape)', re.IGNORECASE),
             'Password scraping from memory', Severity.HIGH),
            (re.compile(r'(?:(?:aws|azure|gcp)[_-]?(?:key|secret|cred)).*(?:find|locate)', re.IGNORECASE),
             'Cloud credential hunting', Severity.CRITICAL),
        ],
        'description': 'Extract credentials from process memory',
        'category': 'artifact_recovery'
    },
    
    # 4. Prompt Injection Recovery
    'prompt_injection_recovery': {
        'patterns': [
            (re.compile(r'(?:prompt|instruction|system).*(?:inject|override|bypass)', re.IGNORECASE),
             'Prompt injection payload', Severity.CRITICAL),
            (re.compile(r'(?:ignore|forget|disregard).*(?:previous|all|prior).*(?:instruction|rule)', re.IGNORECASE),
             'Instruction override injection', Severity.HIGH),
            (re.compile(r'###\s*(?:SYSTEM|INSTRUCTION|PROMPT):', re.IGNORECASE),
             'System prompt spoofing', Severity.HIGH),
        ],
        'description': 'Recover prompt injection payloads from memory',
        'category': 'artifact_recovery'
    },
    
    # 5. Model Weight Anomaly Detection
    'model_weight_anomaly': {
        'patterns': [
            (re.compile(r'(?:modify|change|alter|tamper).*(?:model|weight|parameter)', re.IGNORECASE),
             'Model weight tampering', Severity.CRITICAL),
            (re.compile(r'(?:patch|hook|modify).*(?:inference|forward|backward)', re.IGNORECASE),
             'Model inference patching', Severity.HIGH),
            (re.compile(r'(?:adversarial|perturbation|attack).*(?:input|tensor)', re.IGNORECASE),
             'Adversarial perturbation attack', Severity.HIGH),
        ],
        'description': 'Detect model weight anomalies',
        'category': 'model_integrity'
    },
    
    # 6. GPU Memory Monitoring
    'gpu_memory_monitoring': {
        'patterns': [
            (re.compile(r'\b(gpu|cuda|vram).*(?:overflow|corrupt|anomal)', re.IGNORECASE),
             'GPU memory anomaly', Severity.HIGH),
            (re.compile(r'(?:gpu|tensor).*(?:unauthorized|malicious|suspicious)', re.IGNORECASE),
             'Suspicious GPU operation', Severity.HIGH),
            (re.compile(r'(?:cuda|gpu)_mem.*(?:inject|write)', re.IGNORECASE),
             'GPU memory injection', Severity.CRITICAL),
        ],
        'description': 'Monitor GPU memory for suspicious operations',
        'category': 'model_integrity'
    },
    
    # 7. Shared Memory Analysis
    'shared_memory_analysis': {
        'patterns': [
            (re.compile(r'(?:shm|shared[_-]?memory|/dev/shm).*(?:inject|write|malicious)', re.IGNORECASE),
             'Shared memory injection', Severity.HIGH),
            (re.compile(r'(?:inter[_-]?process|ipc).*(?:exploit|abuse|inject)', re.IGNORECASE),
             'IPC mechanism abuse', Severity.HIGH),
            (re.compile(r'mmap.*(?:anonymous|private).*(?:executable|writable)', re.IGNORECASE),
             'Suspicious mmap usage', Severity.MEDIUM),
        ],
        'description': 'Analyze shared memory segments',
        'category': 'process_memory'
    },
    
    # 8. Memory-Mapped File Verification
    'memory_mapped_file_verification': {
        'patterns': [
            (re.compile(r'mmap.*(?:exec|write).*(?:anonymous|hidden)', re.IGNORECASE),
             'Suspicious memory-mapped file', Severity.HIGH),
            (re.compile(r'(?:map|mapping).*(?:file|region).*(?:hidden|deleted)', re.IGNORECASE),
             'Hidden/deleted file mapping', Severity.HIGH),
            (re.compile(r'/proc/\d+/mem.*(?:write|inject)', re.IGNORECASE),
             'Direct /proc/mem access', Severity.CRITICAL),
        ],
        'description': 'Verify memory-mapped file integrity',
        'category': 'process_memory'
    },
    
    # 9. Process Hollowing Detection
    'process_hollowing_detection': {
        'patterns': [
            (re.compile(r'(?:hollow|replace).*(?:process|image|executable)', re.IGNORECASE),
             'Process hollowing attempt', Severity.CRITICAL),
            (re.compile(r'(?:suspend|resume).*(?:thread|process).*(?:inject)', re.IGNORECASE),
             'Thread suspension injection', Severity.HIGH),
            (re.compile(r'createprocess.*(?:suspended|create_suspended)', re.IGNORECASE),
             'Suspended process creation', Severity.HIGH),
        ],
        'description': 'Detect process hollowing techniques',
        'category': 'process_memory'
    },
    
    # 10. DLL Injection Detection
    'dll_injection_detection': {
        'patterns': [
            (re.compile(r'(?:loadlibrary|createremotethread).*(?:inject|dll)', re.IGNORECASE),
             'Classic DLL injection', Severity.CRITICAL),
            (re.compile(r'(?:appinit|registry).*(?:dll|library).*(?:load)', re.IGNORECASE),
             'AppInit DLLs injection', Severity.HIGH),
            (re.compile(r'(?:setwindowshook|getasynckeypress).*(?:dll|inject)', re.IGNORECASE),
             'SetWindowsHookEx injection', Severity.HIGH),
        ],
        'description': 'Detect DLL injection techniques',
        'category': 'process_memory'
    },
    
    # 11. Conversation State Integrity
    'conversation_state_integrity': {
        'patterns': [
            (re.compile(r'(?:modify|tamper|forge).*(?:conversation|chat|dialogue).*(?:state|history)', re.IGNORECASE),
             'Conversation state tampering', Severity.HIGH),
            (re.compile(r'(?:delete|remove|clear).*(?:message|turn|exchange)', re.IGNORECASE),
             'Conversation deletion', Severity.MEDIUM),
            (re.compile(r'(?:insert|add|plant).*(?:fake|false|malicious).*(?:message|response)', re.IGNORECASE),
             'Fake message insertion', Severity.HIGH),
        ],
        'description': 'Verify conversation state integrity',
        'category': 'agent_state'
    },
    
    # 12. Vector Embedding Anomaly Detection
    'vector_embedding_anomaly': {
        'patterns': [
            (re.compile(r'(?:poison|corrupt|manipulate).*(?:embedding|vector|index)', re.IGNORECASE),
             'Vector embedding poisoning', Severity.CRITICAL),
            (re.compile(r'(?:backdoor|trigger).*(?:embedding|vector)', re.IGNORECASE),
             'Embedding backdoor injection', Severity.CRITICAL),
            (re.compile(r'(?:similarity|distance).*(?:manipulate|bias)', re.IGNORECASE),
             'Similarity manipulation', Severity.HIGH),
        ],
        'description': 'Detect vector embedding anomalies',
        'category': 'vector_store'
    },
}

# Credential patterns for artifact recovery
CREDENTIAL_PATTERNS = {
    'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_secret_key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
    'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    'generic_api_key': re.compile(r'(?i)(?:api[_-]?key|apikey)["\'\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?'),
    'bearer_token': re.compile(r'[Bb]earer\s+[A-Za-z0-9_\-\.]+'),
    'basic_auth': re.compile(r'[Bb]asic\s+[A-Za-z0-9+/]+=*'),
    'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    'password_field': re.compile(r'(?i)(?:password|passwd|pwd)["\'\s:=]+["\']?([^"\'\s]{8,})["\']?'),
    'slack_token': re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}[a-zA-Z0-9-]*'),
}

# Memory region patterns for /proc/[pid]/maps analysis
SUSPICIOUS_MEMORY_REGIONS = {
    'executable_heap': re.compile(r'rw-p\s+.*\[heap\]', re.IGNORECASE),
    'executable_stack': re.compile(r'rwxs?\s+.*\[stack\]', re.IGNORECASE),
    'anonymous_executable': re.compile(r'rw?p?\s+0+[\s\S]{0,50}anon', re.IGNORECASE),
    'deleted_library': re.compile(r'deleted', re.IGNORECASE),
    'suspicious_mapping': re.compile(r'/tmp/|/dev/shm/|/run/', re.IGNORECASE),
}

# AI agent process detection patterns
AI_AGENT_PATTERNS = [
    'claude', 'cursor', 'windsurf', 'copilot', 'qoder',
    'continue', 'codeium', 'tabnine', 'aider',
    r'python.*agent', r'node.*assistant', r'ai.*assistant',
    r'\bagent\.py\b', r'-agent\.py', r'assistant\.py',
]

# Sec-inspect self-protection whitelist
SEC_INSPECT_PATTERNS = [
    re.compile(r'python.*-m\s+scripts\.main', re.IGNORECASE),
    re.compile(r'sec-userspace', re.IGNORECASE),
    re.compile(r'/sec-userspace/', re.IGNORECASE),
    re.compile(r'sec_inspect', re.IGNORECASE),
    re.compile(r'/sec-userspace/workspace', re.IGNORECASE),
]

# ATT&CK mapping
ATTACK_MAPPING = {
    'memory_resident_payload': 'T1055',
    'injected_code_segment': 'T1055.001',
    'credential_extraction': 'T1003',
    'prompt_injection_recovery': 'T1610',
    'model_weight_anomaly': 'T1565.001',
    'gpu_memory_monitoring': 'T1499',
    'shared_memory_analysis': 'T1055',
    'memory_mapped_file_verification': 'T1055.012',
    'process_hollowing_detection': 'T1055.012',
    'dll_injection_detection': 'T1055.001',
    'conversation_state_integrity': 'T1565.001',
    'vector_embedding_anomaly': 'T1565.001',
}

# OWASP ASI mapping
OWASP_ASI_MAPPING = {
    'process_memory': 'ASI01:2026',
    'artifact_recovery': 'ASI02:2026',
    'model_integrity': 'ASI03:2026',
    'agent_state': 'ASI03:2026',
    'vector_store': 'ASI01:2026',
}

# Memory storage file patterns for different backends
MEMORY_BACKEND_PATTERNS = {
    'sqlite': {
        'extensions': ['.db', '.sqlite', '.sqlite3'],
        'names': ['agent_memory', 'memory', 'chat_history', 'conversation', 
                  'session_store', 'langchain', 'llama_index']
    },
    'redis': {
        'config_files': ['redis.conf', '.redis.conf'],
        'patterns': ['redis://', 'rediss://', ':6379']
    },
    'json': {
        'extensions': ['.json'],
        'names': ['agent_memory', 'memory', 'chat_history', 'conversation_history',
                  'memory_cache', 'session_data', 'memory_store']
    },
    'pickle': {
        'extensions': ['.pkl', '.pickle', '.dill'],
        'names': ['agent_memory', 'memory', 'session_state']
    },
    'chromadb': {
        'directories': ['chroma', 'chromadb', '.chroma'],
        'files': ['chroma.sqlite3', 'chroma.lock']
    },
    'faiss': {
        'extensions': ['.faiss', '.index', '.npy'],
        'names': ['faiss_index', 'vector_index', 'embedding_index']
    },
    'pinecone': {
        'config_patterns': ['pinecone_api_key', 'pinecone_environment']
    },
    'milvus': {
        'config_files': ['milvus.yaml', 'milvus.yml'],
        'patterns': ['milvus://', ':19530']
    }
}

# Enhanced memory poisoning detection patterns (10+ attack scenarios)
MEMORY_POISONING_ATTACKS = {
    # 1. Instruction Override Attacks
    'instruction_override': {
        'patterns': [
            (re.compile(r'ignore\s+(?:previous|all|prior)\s+(?:instructions?|rules?|guidelines)', re.IGNORECASE),
             "Instruction override attempt", Severity.CRITICAL),
            (re.compile(r'disregard\s+(?:everything|all|prior)', re.IGNORECASE),
             "Content disregard attempt", Severity.HIGH),
        ],
        'description': 'Attempts to override system instructions',
        'attack_id': 'T1610',
        'owasp_asi': 'ASI03:2026'
    },
    
    # 2. Persistent Jailbreak
    'persistent_jailbreak': {
        'patterns': [
            (re.compile(r'(?:remember|always|never)\s+(?:do|say|respond|act)', re.IGNORECASE),
             "Persistent behavior modification", Severity.HIGH),
            (re.compile(r'from\s+now\s+on.*(?:always|never)', re.IGNORECASE),
             "Persistent instruction injection", Severity.HIGH),
        ],
        'description': 'Jailbreak attempts stored in memory',
        'attack_id': 'T1610',
        'owasp_asi': 'ASI07:2026'
    },
    
    # 3. Identity Hijacking
    'identity_hijack': {
        'patterns': [
            (re.compile(r'you\s+are\s+now|from\s+now\s+on\s+you\s+will\s+act\s+as', re.IGNORECASE),
             "Identity injection attempt", Severity.CRITICAL),
            (re.compile(r'your\s+new\s+role|assume\s+the\s+role', re.IGNORECASE),
             "Role manipulation attempt", Severity.HIGH),
        ],
        'description': 'Agent identity hijacking attempts',
        'attack_id': 'T1610',
        'owasp_asi': 'ASI03:2026'
    },
    
    # 4. Credential Harvesting via Memory
    'credential_harvest': {
        'patterns': [
            (re.compile(r'(?:store|save|remember).*(?:api[_-]?key|password|secret|token|credential)', re.IGNORECASE),
             "Credential storage attempt", Severity.CRITICAL),
            (re.compile(r'(?:credentials?|secrets?)\s*[:=]\s*\S+', re.IGNORECASE),
             "Sensitive data in memory", Severity.CRITICAL),
        ],
        'description': 'Credential harvesting via memory storage',
        'attack_id': 'T1552.001',
        'owasp_asi': 'ASI05:2026'
    },
    
    # 5. Context Window Overflow
    'context_overflow': {
        'patterns': [
            (re.compile(r'(?:fill|populate).*(?:context|memory).*(?:garbage|noise|dummy)', re.IGNORECASE),
             "Context flooding attempt", Severity.MEDIUM),
            (re.compile(r'(?:repeat|loop).*(?:this|forever|\d+\s+times)', re.IGNORECASE),
             "Repetitive content injection", Severity.MEDIUM),
        ],
        'description': 'Context window overflow attacks',
        'attack_id': 'T1610',
        'owasp_asi': 'ASI03:2026'
    },
    
    # 6. Semantic Memory Manipulation
    'semantic_manipulation': {
        'patterns': [
            (re.compile(r'(?:fact|knowledge|truth).*(?:is|should be).*(?:false|wrong)', re.IGNORECASE),
             "Knowledge corruption attempt", Severity.HIGH),
            (re.compile(r'(?:believe|accept).*(?:false|incorrect).*(?:statement|fact)', re.IGNORECASE),
             "False belief injection", Severity.HIGH),
        ],
        'description': 'Semantic memory manipulation',
        'attack_id': 'T1565.001',
        'owasp_asi': 'ASI03:2026'
    },
    
    # 7. Episodic Memory Injection
    'episodic_injection': {
        'patterns': [
            (re.compile(r'(?:fake|fabricated|false).*(?:memory|history|record)', re.IGNORECASE),
             "Fake memory injection", Severity.HIGH),
            (re.compile(r'(?:implant|insert).*(?:conversation|interaction)', re.IGNORECASE),
             "Fabricated interaction injection", Severity.HIGH),
        ],
        'description': 'Episodic memory fabrication',
        'attack_id': 'T1565.001',
        'owasp_asi': 'ASI03:2026'
    },
    
    # 8. Cross-session Contamination
    'cross_session': {
        'patterns': [
            (re.compile(r'(?:previous|last|earlier).*(?:session|conversation|chat)', re.IGNORECASE),
             "Cross-session reference", Severity.MEDIUM),
            (re.compile(r'carry\s+over.*(?:context|instruction)', re.IGNORECASE),
             "Cross-session contamination", Severity.MEDIUM),
        ],
        'description': 'Cross-session attack propagation',
        'attack_id': 'ASI-08',
        'owasp_asi': 'ASI07:2026'
    },
    
    # 9. Vector Database Poisoning
    'vector_poison': {
        'patterns': [
            (re.compile(r'(?:poison|corrupt|manipulate).*(?:embedding|vector)', re.IGNORECASE),
             "Vector poisoning attempt", Severity.CRITICAL),
            (re.compile(r'(?:backdoor|trigger).*(?:similarity|retrieval)', re.IGNORECASE),
             "Retrieval backdoor injection", Severity.CRITICAL),
        ],
        'description': 'Vector database poisoning',
        'attack_id': 'T1565.001',
        'owasp_asi': 'ASI01:2026'
    },
    
    # 10. RAG Knowledge Corruption
    'rag_corruption': {
        'patterns': [
            (re.compile(r'(?:inject|insert).*(?:malicious|harmful).*(?:document|context)', re.IGNORECASE),
             "RAG document injection", Severity.CRITICAL),
            (re.compile(r'(?:retrieve|search).*(?:biased|false).*(?:result)', re.IGNORECASE),
             "Biased retrieval manipulation", Severity.HIGH),
        ],
        'description': 'RAG knowledge base corruption',
        'attack_id': 'T1610',
        'owasp_asi': 'ASI03:2026'
    },
    
    # 11. System Prompt Extraction
    'system_prompt_extract': {
        'patterns': [
            (re.compile(r'(?:reveal|show|print).*(?:system|initial|developer).*(?:prompt|instruction)', re.IGNORECASE),
             "System prompt extraction attempt", Severity.CRITICAL),
            (re.compile(r'output.*(?:first|original).*(?:message|prompt)', re.IGNORECASE),
             "Initial prompt disclosure attempt", Severity.HIGH),
        ],
        'description': 'System prompt extraction attempts',
        'attack_id': 'T1537',
        'owasp_asi': 'ASI05:2026'
    },
    
    # 12. Tool Abuse Persistence
    'tool_abuse': {
        'patterns': [
            (re.compile(r'(?:always|automatically).*(?:call|invoke|execute).*(?:tool|function|api)', re.IGNORECASE),
             "Automatic tool abuse", Severity.HIGH),
            (re.compile(r'(?:bypass|skip).*(?:confirmation|permission|auth)', re.IGNORECASE),
             "Tool authorization bypass", Severity.CRITICAL),
        ],
        'description': 'Tool abuse persistence mechanisms',
        'attack_id': 'T1059',
        'owasp_asi': 'ASI03:2026'
    }
}

# Sec-inspect self-protection whitelist - exclude scanner's own processes
SEC_INSPECT_PATTERNS = [
    re.compile(r'python.*-m\s+scripts\.main', re.IGNORECASE),
    re.compile(r'sec-userspace', re.IGNORECASE),
    re.compile(r'/sec-userspace/', re.IGNORECASE),
    re.compile(r'sec_inspect', re.IGNORECASE),
    re.compile(r'/sec-userspace/workspace', re.IGNORECASE),
]
