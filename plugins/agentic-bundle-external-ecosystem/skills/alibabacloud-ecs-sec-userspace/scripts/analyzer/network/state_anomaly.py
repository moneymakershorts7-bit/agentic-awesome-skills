"""Global TCP connection state anomaly detection mixin for NetworkAnalyzer.

Contains methods for:
- Connection state collection
- Historical baseline management and deviation checking
- Evidence creation helpers for state anomalies
- Global CLOSE_WAIT/TIME_WAIT/FIN_WAIT anomaly detection

Per-IP state anomaly detection is in per_ip_state.py.
"""
from typing import Dict, List, Optional, Tuple

from .helpers import _get_logger, _get_attack_tactic_name, _get_defaultdict, _get_time_module
from .constants import (
    CLOSE_WAIT_THRESHOLD, TIME_WAIT_THRESHOLD, FIN_WAIT_THRESHOLD,
    BASELINE_RATE_THRESHOLD, MIN_BASELINE_SAMPLES,
    _HISTORICAL_BASELINES, _BASELINES_LOCK,
)
from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .per_ip_state import PerIPStateAnomalyMixin


class StateAnomalyMixin(PerIPStateAnomalyMixin):
    """Mixin providing TCP connection state anomaly detection."""

    def _collect_connection_states(self, network_data: Dict) -> Tuple[Dict, Dict]:
        """Collect and organize connection states from network data."""
        all_connections = (
            network_data.get("tcp_connections", []) +
            network_data.get("tcp6_connections", [])
        )

        state_counts = _get_defaultdict()(int)
        state_details = _get_defaultdict()(list)

        for conn in all_connections:
            state = conn.get("state", "")
            if state:
                state_counts[state] += 1

                if len(state_details[state]) < 10:
                    state_details[state].append({
                        "local_ip": conn.get("local_ip", ""),
                        "local_port": conn.get("local_port", 0),
                        "remote_ip": conn.get("remote_ip", ""),
                        "remote_port": conn.get("remote_port", 0),
                        "pid": conn.get("pid", 0),
                        "process_name": conn.get("process_name", ""),
                    })

        return state_counts, state_details

    def _update_historical_baselines(self, state_counts: Dict) -> float:
        """Update historical baselines with current counts."""
        time_module = _get_time_module()
        current_time = time_module.time()
        with _BASELINES_LOCK:
            for state, count in state_counts.items():
                if state not in _HISTORICAL_BASELINES:
                    _HISTORICAL_BASELINES[state] = {"counts": [], "timestamps": []}

                baseline = _HISTORICAL_BASELINES[state]
                baseline["counts"].append(count)
                baseline["timestamps"].append(current_time)

                if len(baseline["counts"]) > 100:
                    baseline["counts"] = baseline["counts"][-100:]
                    baseline["timestamps"] = baseline["timestamps"][-100:]

        return current_time

    def _check_baseline_deviation(self, state: str, current_count: int, current_time: float) -> Tuple[bool, Dict]:
        """Check if current count significantly deviates from historical baseline."""
        with _BASELINES_LOCK:
            baseline = _HISTORICAL_BASELINES.get(state, {})
            counts = list(baseline.get("counts", []))

        if len(counts) < MIN_BASELINE_SAMPLES:
            return False, None

        recent_counts = counts[-20:]
        avg = sum(recent_counts) / len(recent_counts)

        if avg == 0:
            return current_count > 0, {"avg": 0, "std_dev": 0, "deviation_ratio": 99999.0, "sample_count": len(recent_counts)}

        variance = sum((x - avg) ** 2 for x in recent_counts) / len(recent_counts)
        std_dev = variance ** 0.5
        deviation_ratio = current_count / avg if avg > 0 else 99999.0

        is_anomalous = (
            deviation_ratio > BASELINE_RATE_THRESHOLD or
            (std_dev > 0 and (current_count - avg) / std_dev > 3)
        )

        return is_anomalous, {
            "avg": avg,
            "std_dev": std_dev,
            "deviation_ratio": deviation_ratio,
            "sample_count": len(recent_counts),
        }

    def _create_state_anomaly_evidence(
        self,
        state_name: str,
        count: int,
        threshold: int,
        baseline_info: Optional[Dict],
        is_anomalous: bool,
        state_details: List[Dict],
        severity: Severity,
        confidence: float,
        description: str,
        attack_id: str,
        remediation: str,
        remediation_commands: List[str],
        extra_raw_data: Dict = None
    ) -> Evidence:
        """Create evidence for connection state anomaly."""
        adjusted_severity = severity
        adjusted_confidence = confidence

        if is_anomalous and baseline_info:
            deviation_ratio = baseline_info.get("deviation_ratio", 0)
            if deviation_ratio > 5:
                adjusted_severity = Severity.HIGH
            adjusted_confidence = min(0.90, confidence + deviation_ratio * 0.03)

            description += (
                f"\nBaseline deviation detected: current {count} vs "
                f"historical avg {baseline_info['avg']:.0f} "
                f"(deviation: {baseline_info['deviation_ratio']:.1f}x)\n"
            )

        sample_conn = state_details[0] if state_details else {}
        local_addr = f"{sample_conn.get('local_ip', '')}:{sample_conn.get('local_port', '')}"
        remote_addr = f"{sample_conn.get('remote_ip', '')}:{sample_conn.get('remote_port', '')}"

        raw_data = {
            "state": state_name,
            "count": count,
            "threshold": threshold,
            "baseline_avg": baseline_info.get("avg", 0) if baseline_info else 0,
            "deviation_ratio": baseline_info.get("deviation_ratio", 0) if baseline_info else 0,
            "sample_connections": state_details[:5],
        }
        if extra_raw_data:
            raw_data.update(extra_raw_data)

        evidence_detail = EvidenceDetail(
            local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state=state_name,
            pid=sample_conn.get("pid") or None,
        )

        return self._create_evidence(
            title=f"Abnormal {state_name} connections: {count} detected",
            description=description,
            severity=adjusted_severity,
            confidence=adjusted_confidence,
            attack_id=attack_id,
            attack_tactic=_get_attack_tactic_name(attack_id),
            raw_data=raw_data,
            remediation=remediation,
            evidence_details=evidence_detail,
            remediation_commands=remediation_commands,
        )

    def _check_close_wait_anomaly(
        self, count: int, threshold: int, state_details: List[Dict],
        baseline_info: Optional[Dict], is_anomalous: bool
    ) -> Optional[Evidence]:
        """Check and create evidence for CLOSE_WAIT anomaly."""
        if count == 0:
            return None
        if count <= threshold and not is_anomalous:
            return None

        processes_involved = set()
        for detail in state_details:
            if detail.get("process_name"):
                processes_involved.add(detail["process_name"])

        description = (
            f"Detected {count} connections in CLOSE_WAIT state "
            f"(threshold: {threshold}).\n"
            f"This indicates application connection leak - remote side closed connections "
            f"but local application hasn't closed its end.\n"
        )
        description += f"Top processes: {', '.join(list(processes_involved)[:5]) if processes_involved else 'unknown'}"

        remediation_cmds = [
            "ss -tnp state close-wait",
            "netstat -tnp | grep CLOSE_WAIT",
            "cat /proc/sys/net/ipv4/tcp_keepalive_time",
        ]

        return self._create_state_anomaly_evidence(
            state_name="CLOSE_WAIT", count=count, threshold=threshold,
            baseline_info=baseline_info, is_anomalous=is_anomalous,
            state_details=state_details, severity=Severity.MEDIUM, confidence=0.75,
            description=description, attack_id="T1499",
            remediation=(
                "Check application connection pool settings. "
                "Verify proper socket cleanup in application code. "
                "Review processes with most CLOSE_WAIT connections."
            ),
            remediation_commands=remediation_cmds,
            extra_raw_data={"processes": list(processes_involved)[:10]},
        )

    def _check_time_wait_anomaly(
        self, count: int, threshold: int, state_details: List[Dict],
        baseline_info: Optional[Dict], is_anomalous: bool
    ) -> Optional[Evidence]:
        """Check and create evidence for TIME_WAIT anomaly."""
        if count == 0:
            return None
        if count <= threshold and not is_anomalous:
            return None

        description = (
            f"Detected {count} connections in TIME_WAIT state "
            f"(threshold: {threshold}).\n"
            f"This may indicate connection storm or rapid connection churn.\n"
            f"Can exhaust local ports and cause connection failures."
        )

        remediation_cmds = [
            "ss -tnp state time-wait",
            "sysctl net.ipv4.tcp_tw_reuse",
            "sysctl net.ipv4.tcp_max_tw_buckets",
        ]

        return self._create_state_anomaly_evidence(
            state_name="TIME_WAIT", count=count, threshold=threshold,
            baseline_info=baseline_info, is_anomalous=is_anomalous,
            state_details=state_details, severity=Severity.MEDIUM, confidence=0.70,
            description=description, attack_id="T1498",
            remediation=(
                "Consider enabling tcp_tw_reuse kernel parameter. "
                "Review connection pool reuse. "
                "Check for connection flood or DoS attack."
            ),
            remediation_commands=remediation_cmds,
        )

    def _check_fin_wait_anomaly(
        self, fin_wait1_count: int, fin_wait2_count: int, threshold: int,
        baseline_info: Optional[Dict], is_anomalous: bool
    ) -> Optional[Evidence]:
        """Check and create evidence for FIN_WAIT anomaly."""
        total_fin_wait = fin_wait1_count + fin_wait2_count

        if total_fin_wait == 0:
            return None
        if total_fin_wait <= threshold and not is_anomalous:
            return None

        description = (
            f"Detected {total_fin_wait} connections in FIN_WAIT states "
            f"(FIN_WAIT1: {fin_wait1_count}, FIN_WAIT2: {fin_wait2_count}, "
            f"threshold: {threshold}).\n"
            f"High FIN_WAIT count may indicate slow connection teardown or network issues."
        )

        remediation_cmds = [
            "ss -tnp state fin-wait-1 state fin-wait-2",
            "sysctl net.ipv4.tcp_fin_timeout",
            "cat /proc/sys/net/ipv4/tcp_fin_timeout",
        ]

        return self._create_state_anomaly_evidence(
            state_name="FIN_WAIT", count=total_fin_wait, threshold=threshold,
            baseline_info=baseline_info, is_anomalous=is_anomalous,
            state_details=[], severity=Severity.MEDIUM, confidence=0.65,
            description=description, attack_id="T1499",
            remediation=(
                "Check network latency and packet loss. "
                "Review application connection termination logic. "
                "Consider tuning TCP timeout parameters."
            ),
            remediation_commands=remediation_cmds,
            extra_raw_data={"fin_wait1_count": fin_wait1_count, "fin_wait2_count": fin_wait2_count, "total": total_fin_wait},
        )

    def _detect_connection_state_anomalies(self, network_data: Dict) -> List[Evidence]:
        """Detect TCP connection state anomalies.

        Detects:
        - CLOSE_WAIT connection leak (> 100 connections)
        - TIME_WAIT connection storm (> 1000 connections)
        - FIN_WAIT accumulation (> 500 connections)
        - Baseline deviation (current count > 3x historical baseline)

        ATT&CK:
        - T1498 - Network Denial of Service (connection exhaustion)
        - T1499 - Endpoint Denial of Service (resource exhaustion)
        """
        evidences = []

        if not network_data:
            return evidences

        try:
            state_counts, state_details = self._collect_connection_states(network_data)

            if not state_counts:
                return evidences

            current_time = self._update_historical_baselines(state_counts)

            close_wait_count = state_counts.get("CLOSE_WAIT", 0)
            if close_wait_count > 0:
                is_anomalous, baseline_info = self._check_baseline_deviation(
                    "CLOSE_WAIT", close_wait_count, current_time
                )
                evidence = self._check_close_wait_anomaly(
                    count=close_wait_count, threshold=CLOSE_WAIT_THRESHOLD,
                    state_details=state_details.get("CLOSE_WAIT", []),
                    baseline_info=baseline_info, is_anomalous=is_anomalous,
                )
                if evidence:
                    evidences.append(evidence)

            time_wait_count = state_counts.get("TIME_WAIT", 0)
            if time_wait_count > 0:
                is_anomalous, baseline_info = self._check_baseline_deviation(
                    "TIME_WAIT", time_wait_count, current_time
                )
                evidence = self._check_time_wait_anomaly(
                    count=time_wait_count, threshold=TIME_WAIT_THRESHOLD,
                    state_details=state_details.get("TIME_WAIT", []),
                    baseline_info=baseline_info, is_anomalous=is_anomalous,
                )
                if evidence:
                    evidences.append(evidence)

            fin_wait1_count = state_counts.get("FIN_WAIT1", 0)
            fin_wait2_count = state_counts.get("FIN_WAIT2", 0)
            if (fin_wait1_count + fin_wait2_count) > 0:
                is_anomalous, baseline_info = self._check_baseline_deviation(
                    "FIN_WAIT", fin_wait1_count + fin_wait2_count, current_time
                )
                evidence = self._check_fin_wait_anomaly(
                    fin_wait1_count=fin_wait1_count, fin_wait2_count=fin_wait2_count,
                    threshold=FIN_WAIT_THRESHOLD, baseline_info=baseline_info,
                    is_anomalous=is_anomalous,
                )
                if evidence:
                    evidences.append(evidence)

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Connection state anomaly detection failed: {e}")

        return evidences
