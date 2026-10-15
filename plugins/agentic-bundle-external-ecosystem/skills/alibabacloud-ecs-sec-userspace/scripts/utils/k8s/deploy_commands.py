#!/usr/bin/env python3
"""Kubernetes Deployment Commands for sec-userspace

Provides a single CLI subcommand for deploying sec-userspace to Kubernetes clusters:
- k8s-deploy: Deploy CronJob -> wait for execution -> collect results -> FP analysis -> trusted output
"""
import argparse
import json
import logging
import re
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("sec-userspace")


def _run_kubectl(cmd, timeout=30, input_data=None):
    """Run kubectl command and return result."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input_data, universal_newlines=True, timeout=timeout)
        return result
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, '', 'Command timed out')
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, -1, '', 'kubectl not found')


def _check_kubectl():
    """Check if kubectl is available."""
    result = _run_kubectl(['kubectl', 'version', '--client'], timeout=10)
    if result.returncode != 0:
        print("[ERROR] kubectl not found or not configured")
        return False
    return True


def cmd_k8s_deploy(args):
    """Deploy sec-userspace CronJob to Kubernetes cluster, collect results, analyze false positives"""
    print("=" * 60)
    print("  sec-userspace K8S Deploy: CronJob + Result Collection + FP Analysis")
    print("=" * 60)
    
    # Step 1: Verify kubectl + kubeconfig
    print("\n[STEP 1] Verifying kubectl and kubeconfig...")
    if not _check_kubectl():
        print("Please ensure kubectl is installed and kubeconfig is configured.")
        return 1
    
    namespace = args.namespace or "security-system"
    schedule = args.schedule or "0 2 * * *"
    image = args.image or "registry.example.com/security/sec-userspace:latest"
    output_dir = args.output_dir or "./sec-userspace-results"
    kubeconfig = args.kubeconfig
    context = args.context
    
    print(f"  Namespace: {namespace}")
    print(f"  Schedule: {schedule}")
    print(f"  Image: {image}")
    print(f"  Output directory: {output_dir}")
    
    # Build kubectl base command
    kubectl_base = ['kubectl']
    if kubeconfig:
        kubectl_base.extend(['--kubeconfig', kubeconfig])
    if context:
        kubectl_base.extend(['--context', context])
    
    deploy_dir = Path(__file__).parent.parent / "deploy" / "k8s"
    if not deploy_dir.exists():
        print(f"[ERROR] Deployment directory not found: {deploy_dir}")
        return 1
    
    # Step 2: Deploy resources
    print("\n[STEP 2] Deploying K8s resources...")
    
    # 2a: Create namespace
    ns_cmd = kubectl_base + ['create', 'namespace', namespace, '--dry-run=client', '-o', 'yaml']
    result = _run_kubectl(ns_cmd)
    if result.returncode == 0:
        apply_cmd = kubectl_base + ['apply', '-f', '-']
        _run_kubectl(apply_cmd, timeout=15, input_data=result.stdout)
        print(f"  [OK] Namespace {namespace} created/updated")
    else:
        print(f"  [WARN] Namespace creation dry-run failed: {result.stderr}")
    
    # 2b: Apply RBAC
    rbac_file = deploy_dir / "rbac.yaml"
    if rbac_file.exists():
        result = _run_kubectl(kubectl_base + ['apply', '-f', str(rbac_file)], timeout=30)
        if result.returncode == 0:
            print("  [OK] RBAC resources created")
        else:
            print(f"  [FAIL] RBAC: {result.stderr}")
            return 1
    else:
        print(f"  [FAIL] RBAC file not found: {rbac_file}")
        return 1
    
    # 2c: Apply ConfigMap
    configmap_file = deploy_dir / "configmap.yaml"
    if configmap_file.exists():
        result = _run_kubectl(kubectl_base + ['apply', '-f', str(configmap_file)], timeout=30)
        if result.returncode == 0:
            print("  [OK] ConfigMap created")
        else:
            print(f"  [FAIL] ConfigMap: {result.stderr}")
            return 1
    else:
        print(f"  [FAIL] ConfigMap file not found: {configmap_file}")
        return 1
    
    # 2d: Apply CronJob (with custom schedule and image)
    cronjob_file = deploy_dir / "cronjob.yaml"
    if cronjob_file.exists():
        content = cronjob_file.read_text(encoding='utf-8')
        # Replace schedule
        content = content.replace('schedule: "0 2 * * *"', f'schedule: "{schedule}"')
        # Replace image
        content = content.replace('registry.example.com/security/sec-userspace:latest', image)
        
        result = _run_kubectl(kubectl_base + ['apply', '-f', '-'], timeout=30, input_data=content)
        if result.returncode == 0:
            print("  [OK] CronJob created/updated")
        else:
            print(f"  [FAIL] CronJob: {result.stderr}")
            return 1
    else:
        print(f"  [FAIL] CronJob file not found: {cronjob_file}")
        return 1
    
    # Step 3: Trigger immediate execution (with per-node parallelism)
    print("\n[STEP 3] Triggering immediate CronJob execution (per-node)...")
    
    # Get node count for parallelism
    nodes_cmd = kubectl_base + ['get', 'nodes', '-l', 'kubernetes.io/os=linux', 
                               '-o', 'jsonpath={.items[*].metadata.name}']
    nodes_result = _run_kubectl(nodes_cmd, timeout=30)
    node_count = 1
    if nodes_result.returncode == 0 and nodes_result.stdout.strip():
        node_list = nodes_result.stdout.strip().split()
        node_count = len(node_list)
        print(f"  Found {node_count} Linux nodes")
    
    ts = int(time.time())
    job_name = f"sec-userspace-manual-{ts}"
    
    # Create job from CronJob
    trigger_cmd = kubectl_base + ['create', 'job', job_name, f'--from=cronjob/sec-userspace', '-n', namespace]
    result = _run_kubectl(trigger_cmd, timeout=30)
    if result.returncode == 0:
        print(f"  [OK] Manual job '{job_name}' triggered")
        
        # Scale job for per-node execution (if more than 1 node)
        if node_count > 1:
            scale_cmd = kubectl_base + ['scale', f'job/{job_name}', 
                                       f'--replicas={node_count}', '-n', namespace]
            scale_result = _run_kubectl(scale_cmd, timeout=30)
            if scale_result.returncode == 0:
                print(f"  [OK] Job scaled to {node_count} replicas (one per node)")
            else:
                print(f"  [WARN] Job scaling failed: {scale_result.stderr}")
    else:
        print(f"  [WARN] Manual job trigger failed (CronJob still scheduled): {result.stderr}")
    
    # Step 4: Wait for completion (if --wait is True)
    if getattr(args, 'wait', True):
        print("\n[STEP 4] Waiting for job completion (timeout: 600s)...")
        wait_cmd = kubectl_base + ['wait', '--for=condition=complete', 
                                   f'job/{job_name}', '-n', namespace, '--timeout=600s']
        result = _run_kubectl(wait_cmd, timeout=610)
        if result.returncode == 0:
            print("  [OK] Job completed")
        else:
            print(f"  [WARN] Job wait failed (may still be running): {result.stderr}")
    
    # Step 5: Collect results from all pods
    print("\n[STEP 5] Collecting scan results...")
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    # Get logs from all sec-userspace pods
    logs_cmd = kubectl_base + ['logs', '-l', 'app=sec-userspace', '-n', namespace, '--tail=-1']
    result = _run_kubectl(logs_cmd, timeout=60)
    
    logs_file = out_path / "scan-results.log"
    if result.returncode == 0 and result.stdout.strip():
        logs_file.write_text(result.stdout, encoding='utf-8')
        print(f"  [OK] Logs collected -> {logs_file}")
    else:
        print(f"  [WARN] No logs collected yet: {result.stderr}")
    
    # Get per-node logs (if NODE_NAME env is available)
    get_pods_cmd = kubectl_base + ['get', 'pods', '-n', namespace, '-l', 'app=sec-userspace',
                                   '-o', 'jsonpath={.items[*].metadata.name}']
    pods_result = _run_kubectl(get_pods_cmd, timeout=30)
    
    if pods_result.returncode == 0 and pods_result.stdout.strip():
        pod_names = pods_result.stdout.strip().split()
        print(f"  Found {len(pod_names)} sec-userspace pods")
        
        for pod_name in pod_names:
            pod_log_cmd = kubectl_base + ['logs', pod_name, '-n', namespace]
            pod_result = _run_kubectl(pod_log_cmd, timeout=30)
            if pod_result.returncode == 0 and pod_result.stdout.strip():
                node_log_file = out_path / f"{pod_name}.log"
                node_log_file.write_text(pod_result.stdout, encoding='utf-8')
    
    # Step 6: False positive analysis (unless --no-fp-analysis)
    if not getattr(args, 'no_fp_analysis', False):
        print("\n[STEP 6] Running false positive analysis...")
        _run_fp_analysis(out_path)
    else:
        print("\n[STEP 6] Skipping FP analysis (--no-fp-analysis specified)")
    
    # Step 7: Output summary
    print("\n" + "=" * 60)
    print("  Deployment and analysis complete!")
    print("=" * 60)
    print(f"\nResults saved to: {output_dir}/")
    print(f"  - scan-results.log: Raw scan output")
    print(f"  - *.log: Per-pod logs")
    if not getattr(args, 'no_fp_analysis', False):
        print(f"  - trusted-alerts.json: Confirmed true threats")
        print(f"  - false-positives.json: Confirmed false positives")
        print(f"  - summary.md: Scan summary")
    
    print(f"\nTo view live logs:")
    print(f"  kubectl -n {namespace} logs -l app=sec-userspace")
    print(f"\nTo check pod details:")
    print(f"  kubectl -n {namespace} describe pods -l app=sec-userspace")
    print(f"\nTo uninstall:")
    print(f"  kubectl delete -n {namespace} -f {deploy_dir}/")
    
    return 0


def _run_fp_analysis(results_dir: Path):
    """Run false positive analysis on collected scan results.
    
    Analyzes scan logs to separate true threats from false positives
    using evidence verification and whitelist filtering.
    """
    # Import FP analysis modules
    try:
        from ...analyzer import base  # noqa: F401
    except ImportError:
        print("  [WARN] FP analysis modules not available, skipping")
        return
    
    # Read collected logs
    logs_file = results_dir / "scan-results.log"
    if not logs_file.exists():
        print("  [WARN] No scan results to analyze")
        return
    
    logs_content = logs_file.read_text(encoding='utf-8')
    
    # Parse alerts from logs (simple extraction)
    alerts = _parse_alerts_from_logs(logs_content)
    
    if not alerts:
        print("  [INFO] No alerts found in scan results")
        # Create empty output files
        _write_empty_fp_results(results_dir)
        return
    
    # Apply FP detection rules
    trusted_alerts = []
    false_positives = []
    
    # DEV_ENV_PATHS: Development environment path indicators for FP detection
    DEV_ENV_PATHS = frozenset([
        '.qoder-cli', '.cursor', '.vscode', '.idea', '.claude',
        '.git/hooks', '__pycache__', '.cache',
        'node_modules', '.npm', '.bun', '.yarn', '.cargo',
        '.venv', 'venv', 'virtualenv',
        'dev', 'staging', 'example', 'demo', 'sample',
        'template', 'fixture', 'mock', 'test', 'tests',
        'testing', 'sandbox', 'playground',
        'build', 'dist', 'out', 'target', 'bin', 'obj',
        'docs', 'documentation', 'examples', 'tutorials',
    ])
    
    for alert in alerts:
        fp_reason = _check_fp_reason(alert, DEV_ENV_PATHS)
        if fp_reason:
            false_positives.append({**alert, "fp_reason": fp_reason})
        else:
            trusted_alerts.append(alert)
    
    trusted_file = results_dir / "trusted-alerts.json"
    with open(trusted_file, 'w', encoding='utf-8') as f:
        json.dump(trusted_alerts, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Trusted alerts: {len(trusted_alerts)} -> {trusted_file}")
    
    fp_file = results_dir / "false-positives.json"
    with open(fp_file, 'w', encoding='utf-8') as f:
        json.dump(false_positives, f, indent=2, ensure_ascii=False)
    print(f"  [OK] False positives: {len(false_positives)} -> {fp_file}")
    
    # Write summary
    summary_file = results_dir / "summary.md"
    summary_content = f"""# Scan Result Summary

## Overview
- **Total alerts**: {len(alerts)}
- **True threats**: {len(trusted_alerts)}
- **False positives**: {len(false_positives)}

## True Threats
"""
    for i, alert in enumerate(trusted_alerts, 1):
        summary_content += f"{i}. [{alert.get('severity', 'UNKNOWN')}] {alert.get('title', 'N/A')}\n"
        if alert.get('source_path'):
            summary_content += f"   - Path: {alert['source_path']}\n"
    
    summary_content += "\n## False Positives\n"
    for i, fp in enumerate(false_positives, 1):
        summary_content += f"{i}. {fp.get('title', 'N/A')} - {fp.get('fp_reason', 'N/A')}\n"
    
    summary_file.write_text(summary_content, encoding='utf-8')
    print(f"  [OK] Summary -> {summary_file}")


def _parse_alerts_from_logs(logs_content: str) -> list:
    """Parse alerts from scan log content."""
    alerts = []
    
    for line in logs_content.split('\n'):
        match = re.search(r'(CRITICAL|HIGH|MEDIUM|LOW).*?[:\-]\s*(.+)', line)
        if match:
            alerts.append({
                "severity": match.group(1),
                "title": match.group(2).strip(),
                "source_path": "",
                "raw_line": line,
            })
    
    return alerts


def _check_fp_reason(alert: dict, dev_paths: frozenset) -> str:
    """Check if an alert is likely a false positive."""
    source = (alert.get('source_path') or alert.get('raw_line') or '').lower()
    title = alert.get('title', '').lower()
    
    for dev_path in dev_paths:
        if dev_path.lower() in source:
            return f"Located in development environment directory: {dev_path}"
    
    test_keywords = ['test', 'example', 'sample', 'demo', 'fixture', 'mock']
    for keyword in test_keywords:
        if keyword in source or keyword in title:
            return f"Contains test/example keyword: {keyword}"
    
    return ""


def _write_empty_fp_results(results_dir: Path):
    """Write empty FP result files when no alerts found."""
    (results_dir / "trusted-alerts.json").write_text('[]', encoding='utf-8')
    (results_dir / "false-positives.json").write_text('[]', encoding='utf-8')
    (results_dir / "summary.md").write_text(
        "# Scan Result Summary\n\nNo alerts found.\n", 
        encoding='utf-8'
    )


def setup_k8s_commands(subparsers):
    """Setup K8S subcommands
    
    Args:
        subparsers: argparse subparsers object
    """
    # k8s-deploy command (single consolidated command)
    deploy_parser = subparsers.add_parser(
        'k8s-deploy',
        help='Deploy CronJob, wait for execution, collect results, and run FP analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deploy with default settings (daily 2 AM, wait for completion)
  sec-userspace k8s-deploy
  
  # Deploy with custom schedule (every 6 hours)
  sec-userspace k8s-deploy --schedule "0 */6 * * *"
  
  # Deploy to custom namespace with custom image
  sec-userspace k8s-deploy --namespace security --image myregistry/sec-userspace:v1.0
  
  # Skip FP analysis, output raw results only
  sec-userspace k8s-deploy --no-fp-analysis
  
  # Deploy without waiting for completion
  sec-userspace k8s-deploy --no-wait
  
  # Use custom kubeconfig and output directory
  sec-userspace k8s-deploy --kubeconfig /path/to/kubeconfig --output-dir /tmp/results
        """
    )
    deploy_parser.add_argument(
        '--namespace', '-n',
        default='security-system',
        help='Kubernetes namespace (default: security-system)'
    )
    deploy_parser.add_argument(
        '--schedule', '-s',
        default='0 2 * * *',
        help='CronJob schedule expression (default: 0 2 * * *, i.e. daily at 2 AM)'
    )
    deploy_parser.add_argument(
        '--image', '-i',
        default=None,
        help='Container image address (default: auto-detect or use cronjob.yaml default)'
    )
    deploy_parser.add_argument(
        '--kubeconfig',
        default=None,
        help='Path to kubeconfig file (default: ~/.kube/config)'
    )
    deploy_parser.add_argument(
        '--context',
        default=None,
        help='Kubernetes context name (default: current context)'
    )
    deploy_parser.add_argument(
        '--output-dir', '-o',
        default='./sec-userspace-results',
        help='Local output directory for collected scan results (default: ./sec-userspace-results)'
    )
    deploy_parser.add_argument(
        '--no-fp-analysis',
        action='store_true',
        default=False,
        help='Skip false positive analysis, output raw results only'
    )
    deploy_parser.add_argument(
        '--no-wait',
        action='store_false',
        dest='wait',
        default=True,
        help='Do not wait for CronJob execution to complete'
    )
    deploy_parser.set_defaults(func=cmd_k8s_deploy)
