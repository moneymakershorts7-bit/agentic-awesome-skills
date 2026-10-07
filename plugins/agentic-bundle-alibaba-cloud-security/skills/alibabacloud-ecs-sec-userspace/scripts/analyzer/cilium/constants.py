"""Cilium analyzer constants - all class-level constants, patterns, and thresholds."""
import re
from ...reporter.severity import Severity

ATTACK_IDS = {
    'defense_evasion': "T1562.008", 'network_discovery': "T1046", 'app_protocol': "T1071.001",
    'non_standard_port': "T1571", 'lateral_movement': "T1611", 'indicator_removal': "T1070.002",
    'cloud_revert': "T1578.002",
}
ATTACK_ID = "T1562.008"
ATTACK_TACTIC = "Defense Evasion"

VOIDLINK_PATTERNS = [
    (re.compile(r'bpf_map_update_elem.*cilium_ct', re.IGNORECASE), "Direct eBPF map update to Cilium conntrack", Severity.CRITICAL),
    (re.compile(r'bpf_map_delete_elem.*cilium_ct', re.IGNORECASE), "Direct eBPF map delete from Cilium conntrack", Severity.CRITICAL),
    (re.compile(r'conntrack\s+-[FD]', re.IGNORECASE), "Manual conntrack entry deletion", Severity.HIGH),
    (re.compile(r'ip\s+conntrack\s+delete', re.IGNORECASE), "IP conntrack deletion command", Severity.HIGH),
]
CILIUM_AGENT_PATTERNS = [
    (re.compile(r'cilium-agent', re.IGNORECASE), "Cilium agent process"),
    (re.compile(r'cilium-operator', re.IGNORECASE), "Cilium operator process"),
    (re.compile(r'cilium-dbg', re.IGNORECASE), "Cilium debug tool"),
    (re.compile(r'cilium-cli', re.IGNORECASE), "Cilium CLI tool"),
]
SUSPICIOUS_CILIUM_FLAGS = [
    (re.compile(r'--disable-envoy-version-check'), "Envoy version check disabled"),
    (re.compile(r'--disable-endpoint-health-check'), "Endpoint health check disabled"),
    (re.compile(r'--disable-ipv4'), "IPv4 disabled (may hide traffic)"),
    (re.compile(r'--disable-k8s-services'), "K8s services disabled"),
    (re.compile(r'--debug-verbose'), "Debug verbose mode (potential information leak)"),
    (re.compile(r'--enable-policy\s*=\s*never'), "Network policy enforcement disabled"),
    (re.compile(r'--identity-allocation-mode\s*=\s*crd'), "Identity allocation via CRD (slower)"),
]
EXPECTED_EBPF_PROGRAMS = [
    'cil_from_netdev', 'cil_to_netdev', 'cil_from_proxy', 'cil_to_endpoint', 'cil_from_host',
    'cil_to_host', 'cil_xdp_entry', 'cil_sock4_connect', 'cil_sock6_connect', 'cil_handle_policy',
    'cil_lb4_lookup_v2', 'cil_lb6_lookup_v2', 'cil_rev_nat4_lookup', 'cil_rev_nat6_lookup',
    'cil_lb4_service', 'cil_lb6_service', 'cil_nodeport_nat4', 'cil_nodeport_nat6', 'cil_ct_lookup4',
    'cil_ct_lookup6', 'cil_ct_create4', 'cil_ct_create6', 'cil_update_metrics', 'cil_snat_v4_external',
    'cil_snat_v6_external', 'cil_masq4_entry', 'cil_masq6_entry', 'cil_policy_4_ingress',
    'cil_policy_4_egress', 'cil_policy_6_ingress', 'cil_policy_6_egress', 'cil_trace_point',
    'cil_perf_output', 'cil_events_handler', 'cil_vxlan_tunnel', 'cil_geneve_tunnel',
    'cil_encap_v4', 'cil_encap_v6', 'cil_hostfw_4_ingress', 'cil_hostfw_4_egress',
    'cil_hostfw_6_ingress', 'cil_hostfw_6_egress', 'cil_ipsec_decrypt', 'cil_ipsec_encrypt',
    'cil_wireguard_input', 'cil_wireguard_output',
]
CRITICAL_EBPF_MAPS = [
    ('cilium_ct4_global', 'IPv4 connection tracking'), ('cilium_ct6_global', 'IPv6 connection tracking'),
    ('cilium_snat_v4_external', 'External SNAT'), ('cilium_policy_', 'Network policy enforcement'),
    ('cilium_lb', 'Load balancing'), ('cilium_tunnel_map', 'Tunnel endpoint mapping'),
    ('cilium_ep_config', 'Endpoint configuration'), ('cilium_events', 'Event notification'),
    ('cilium_metrics', 'Metrics collection'),
]
HUBBLE_INDICATORS = [
    (re.compile(r'hubble-relay', re.IGNORECASE), "Hubble relay process"),
    (re.compile(r'hubble-ui', re.IGNORECASE), "Hubble UI component"),
    (re.compile(r'hubble-observer', re.IGNORECASE), "Hubble observer pod"),
    (re.compile(r'io\.cilium\.hubble'), "Hubble annotation detected"),
]
SUSPICIOUS_HUBBLE_PATTERNS = [
    (re.compile(r'tls:\s*false|insecure:\s*true', re.IGNORECASE), "Hubble TLS disabled or insecure mode"),
    (re.compile(r'metrics:\s*\[\s*\]', re.IGNORECASE), "Hubble metrics disabled"),
    (re.compile(r'flow:\s*\{\s*enabled:\s*false', re.IGNORECASE), "Hubble flow logging disabled"),
]
CRD_SUSPICIOUS_PATTERNS_NO_SEV = [
    (re.compile(r'kind:\s*CiliumNetworkPolicy', re.IGNORECASE), "CiliumNetworkPolicy CRD detected"),
    (re.compile(r'kind:\s*CiliumClusterwideNetworkPolicy', re.IGNORECASE), "CiliumClusterwideNetworkPolicy CRD detected"),
]
CRD_SUSPICIOUS_PATTERNS_WITH_SEV = [
    (re.compile(r'toPorts:\s*\[\s*\{\s*\}', re.IGNORECASE), "Empty toPorts rule (allows all ports)"),
    (re.compile(r'fromEntities:\s*-?\s*world', re.IGNORECASE), "Allow access from world (external)"),
    (re.compile(r'toCIDR:\s*-?\s*0\.0\.0\.0/0', re.IGNORECASE), "Allow CIDR to any IP (0.0.0.0/0)"),
    (re.compile(r'endpointSelector:\s*\{\s*matchLabels:\s*\{\s*\}', re.IGNORECASE), "Empty endpoint selector"),
    (re.compile(r'ingress:\s*\[\s*\{\s*\}', re.IGNORECASE), "Allow-all ingress rule"),
    (re.compile(r'egress:\s*\[\s*\{\s*\}', re.IGNORECASE), "Allow-all egress rule"),
]
TETRAGON_INDICATORS = [
    (re.compile(r'tetragon', re.IGNORECASE), "Tetragon runtime security"),
    (re.compile(r'/sys/kernel/security/tetragon'), "Tetragon security filesystem"),
    (re.compile(r'tetra\.io'), "Tetragon IO path"),
]
TETRAGON_EVASION_PATTERNS = [
    (re.compile(r'kill\s+.*tetragon|SIGKILL.*tetragon', re.IGNORECASE), "Attempt to kill Tetragon process"),
    (re.compile(r'rm\s+.*tetragon|unlink.*tetragon', re.IGNORECASE), "Attempt to remove Tetragon files"),
    (re.compile(r'CAP_BPF', re.IGNORECASE), "Process with CAP_BPF capability"),
    (re.compile(r'bpf\s+prog\s+unload', re.IGNORECASE), "eBPF program unload command"),
    (re.compile(r'/sys/kernel/debug/tracing', re.IGNORECASE), "Access to tracing filesystem"),
]
CVE_2026_33726_CONFIG = {
    'routing_mode': re.compile(r'routing-mode:\s*["\']?per-endpoint["\']?', re.IGNORECASE),
    'bpf_host_routing': re.compile(r'enable-bpf-host-routing:\s*(false|no|off|0)', re.IGNORECASE),
    'l7_proxy_enabled': re.compile(r'(l7-proxy|enable-l7-proxy):\s*(enabled|true|yes|on|1)', re.IGNORECASE),
}
CILIUM_ENV_PATTERNS = {
    'CILIUM_ROUTING_MODE': re.compile(r'CILIUM_ROUTING_MODE\s*=\s*["\']?per-endpoint["\']?', re.IGNORECASE),
    'CILIUM_ENABLE_BPF_HOST_ROUTING': re.compile(r'CILIUM_ENABLE_BPF_HOST_ROUTING\s*=\s*(false|no|off|0)', re.IGNORECASE),
}
CLUSTER_SIZE_THRESHOLDS = {'small': 3, 'medium': 10, 'large': 50, 'xlarge': 100}
CAPACITY_THRESHOLDS = {'small': 1000, 'medium': 5000, 'large': 20000, 'xlarge': 50000}
NAMESPACE_CATEGORIES = {
    'production': ['production', 'prod', 'live'], 'critical': ['kube-system', 'istio-system', 'monitoring'],
    'staging': ['staging', 'stage', 'pre-prod', 'uat'], 'development': ['development', 'dev', 'test', 'testing', 'qa'],
    'ephemeral': ['preview', 'pr-', 'feature-'],
}
STANDARD_K8S_PORTS = [80, 443, 8080, 8443, 53, 9090, 9091, 6443, 10250, 10251, 10252]
EXPECTED_BINARY_SIZES = {"cilium-agent": (50_000_000, 500_000_000), "cilium-operator": (30_000_000, 300_000_000)}
OFFICIAL_CILIUM_HASHES = {
    "1.15.8": {"cilium-agent": "sha256:placeholder_for_1_15_8", "cilium-operator": "sha256:placeholder_for_1_15_8"},
    "1.16.3": {"cilium-agent": "sha256:placeholder_for_1_16_3", "cilium-operator": "sha256:placeholder_for_1_16_3"},
}
CILIUM_CONFIG_PATHS = ['/etc/cilium/cilium-config.yaml', '/var/lib/cilium/cilium-config.yaml', '/opt/cilium/cilium-config.yaml']
CRD_LOCATIONS = ['/etc/kubernetes/manifests', '/opt/cilium/crds', '/var/lib/cilium/crds']
CILIUM_DIRS = ['/var/run/cilium', '/etc/cilium', '/var/lib/cilium', '/var/run/cilium/cilium-host.mac']
CILIUM_BPF_MARKERS = ['/sys/fs/bpf/tc/globals/cilium_ct4_global', '/sys/fs/bpf/tc/globals/cilium_ct6_global',
    '/sys/fs/bpf/tc/globals/cilium_policy_', '/sys/fs/bpf/tc/globals/cilium_snat_v4_external']
CRITICAL_MAP_PATHS = CILIUM_BPF_MARKERS
BPF_PATHS = ['/sys/fs/bpf/tc/globals', '/sys/fs/bpf']
TETRAGON_PATHS = ['/sys/kernel/security/tetragon', '/var/lib/tetragon']
HUBBLE_DIRS = ['/etc/hubble', '/var/lib/hubble', '/opt/hubble']
CRD_SEARCH_DIRS = ['/etc/cilium', '/opt/cilium', '/tmp/', '/home/']
CONFIGMAP_PATHS = ['/etc/kubernetes/configmaps/cilium-config.yaml', '/var/lib/kubelet/pods/*/volumes/configmap/cilium-config']
CRITICAL_EBPF_HOOKS = ['xdp', 'tc_cls', 'cgroup']
CILIUM_PROCESS_INDICATORS = ['cilium-agent', 'cilium-operator', 'cilium-cni', 'hubble-relay', 'hubble-ui', 'tetragon', 'cilium-nodeinit']
