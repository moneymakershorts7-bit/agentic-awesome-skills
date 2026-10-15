"""Network Connection Collector"""
import gc
import logging
import threading
import time
from .base import BaseCollector, safe_run_command
from ..utils import proc

logger = logging.getLogger("sec-userspace")


class NetworkCollector(BaseCollector):
    """Network Connection Collector"""
    name = "network"

    def __init__(self):
        super().__init__()
        self._lock = threading.RLock()  # Use RLock to allow recursive locking
        self._scan_start_time = None
        self._tcp_connections = []
        self._tcp6_connections = []
        self._udp_connections = []
        self._udp6_connections = []
        self._listening_ports = []
        self._ssl_connections = []
        self._process_connections = {}
        self._inode_pid_map = {}

        self.timeout = self._get_config("timeout", 180)
        
        self._tcp_parse_timeout = self._get_config("tcp_timeout", 10.0)
        self._udp_parse_timeout = self._get_config("udp_timeout", 15.0)
        
        self._paths = self._get_config("paths", {})

    def _parse_tcp_with_timeout(self, path: str, timeout: float = 10.0) -> list:
        """Parse TCP connections with timeout protection

        In large environments, /proc/net/tcp can have hundreds of thousands
        of connections. This wraps parsing in a thread with timeout to prevent
        blocking the entire scan.
        
        Uses streaming parser that returns partial results on timeout instead
        of empty list, improving detection reliability under high load.

        Args:
            path: Path to TCP file (/proc/net/tcp or /proc/net/tcp6)
            timeout: Maximum seconds to wait for parsing

        Returns:
            List of connection dicts (may be partial on timeout), or empty list
            only on parsing failure
        """
        result = []
        parse_exception = None
        timed_out = False

        def _parse_streaming():
            nonlocal result, parse_exception, timed_out
            try:
                # Use streaming parser that supports partial results
                result, timed_out = proc.parse_proc_net_tcp_streaming(path, timeout=timeout)
            except (OSError, ValueError, IndexError, KeyError) as e:
                parse_exception = e
                timed_out = False

        thread = threading.Thread(target=_parse_streaming, daemon=True)
        thread.start()
        # Add 0.5s buffer for thread overhead
        thread.join(timeout=timeout + 0.5)

        if thread.is_alive():
            logger.warning(
                f"Network collector: TCP parsing thread timed out after {timeout + 0.5:.1f}s ({path})"
            )
            # Return any partial results that streaming may have produced
            return result

        if parse_exception:
            logger.warning(f"Network collector: TCP parsing failed: {parse_exception}")
            return []

        if timed_out:
            logger.warning(
                f"Network collector: TCP streaming parse timed out after {timeout:.1f}s, "
                f"returning {len(result)} partial connections ({path})"
            )

        return result
    
    def _parse_udp_with_timeout(self, path: str, timeout: float = 15.0) -> list:
        """Parse UDP connections with timeout protection
        
        Similar to _parse_tcp_with_timeout but for UDP protocol.
        Uses streaming parser that returns partial results on timeout.

        Args:
            path: Path to UDP file (/proc/net/udp or /proc/net/udp6)
            timeout: Maximum seconds to wait for parsing
            
        Returns:
            List of connection dicts (may be partial on timeout), or empty list
            only on parsing failure
        """
        result = []
        parse_exception = None
        timed_out = False
        
        def _parse_streaming():
            nonlocal result, parse_exception, timed_out
            try:
                result, timed_out = proc.parse_proc_net_udp_streaming(path, timeout=timeout)
            except (OSError, ValueError, IndexError, KeyError) as e:
                parse_exception = e
                timed_out = False
        
        thread = threading.Thread(target=_parse_streaming, daemon=True)
        thread.start()
        # Add 0.5s buffer for thread overhead
        thread.join(timeout=timeout + 0.5)
        
        if thread.is_alive():
            logger.warning(
                f"Network collector: UDP parsing thread timed out after {timeout + 0.5:.1f}s ({path})"
            )
            return result
        
        if parse_exception:
            logger.warning(f"Network collector: UDP parsing failed: {parse_exception}")
            return []
        
        if timed_out:
            logger.warning(
                f"Network collector: UDP streaming parse timed out after {timeout:.1f}s, "
                f"returning {len(result)} partial connections ({path})"
            )
        
        return result

    def _calculate_completeness(self) -> dict:
        """Calculate data completeness score for partial results
        
        Returns a completeness assessment based on which collection phases
        completed and how much data was collected.
        
        Returns:
            dict with completeness metrics:
                - score: 0.0 to 1.0 overall completeness
                - phases_completed: dict of phase completion status
                - data_sufficient: bool indicating if data is sufficient for analysis
                - warnings: list of degradation warnings
        """
        with self._lock:
            tcp_count = len(self._tcp_connections)
            tcp6_count = len(self._tcp6_connections)
            udp_count = len(self._udp_connections)
            udp6_count = len(self._udp6_connections)
            listening_count = len(self._listening_ports)
            has_ssl = len(self._ssl_connections) > 0
            has_process_map = len(self._process_connections) > 0
            
            total_connections = tcp_count + tcp6_count + udp_count + udp6_count
            
            # Phase completion tracking
            phases = {
                "tcp_parsed": tcp_count > 0,
                "tcp6_parsed": tcp6_count > 0,
                "udp_parsed": udp_count > 0,
                "udp6_parsed": udp6_count > 0,
                "listening_extracted": listening_count > 0,
                "ssl_collected": has_ssl,
                "process_mapped": has_process_map,
            }
            
            # Weight-based scoring (TCP is most important for detection)
            phase_weights = {
                "tcp_parsed": 0.25,
                "tcp6_parsed": 0.15,
                "udp_parsed": 0.10,
                "udp6_parsed": 0.05,
                "listening_extracted": 0.20,
                "ssl_collected": 0.10,
                "process_mapped": 0.15,
            }
            
            score = sum(weight for phase, weight in phase_weights.items()
                       if phases.get(phase, False))
            
            # Determine if data is sufficient for core detections
            # C2 detection needs: TCP connections + listening ports
            # DGA detection needs: TCP connections with domain names
            # Threat intel needs: All connection types
            has_tcp_data = tcp_count > 0 or tcp6_count > 0
            has_listening_data = listening_count > 0
            data_sufficient = has_tcp_data and has_listening_data
            
            # Generate warnings
            warnings = []
            if not phases.get("tcp_parsed"):
                warnings.append("TCP connections not collected - C2 detection unavailable")
            if not phases.get("listening_extracted"):
                warnings.append("Listening ports not extracted - backdoor detection unavailable")
            if not phases.get("process_mapped"):
                warnings.append("Process mapping incomplete - cannot associate connections to processes")
            if not phases.get("ssl_collected"):
                warnings.append("SSL connections not collected - HTTPS/LLM API detection unavailable")
            if not phases.get("udp_parsed") and not phases.get("udp6_parsed"):
                warnings.append("UDP connections not collected - DNS tunneling detection unavailable")
            
            return {
                "score": round(score, 2),
                "phases_completed": phases,
                "data_sufficient": data_sufficient,
                "total_connections": total_connections,
                "warnings": warnings,
            }

    def _update_partial_result(self, **kwargs):
        """Update partial result data for timeout recovery"""
        with self._lock:
            if "tcp_conn" in kwargs:
                self._tcp_connections = kwargs["tcp_conn"]
            if "tcp6_conn" in kwargs:
                self._tcp6_connections = kwargs["tcp6_conn"]
            if "udp_conn" in kwargs:
                self._udp_connections = kwargs["udp_conn"]
            if "udp6_conn" in kwargs:
                self._udp6_connections = kwargs["udp6_conn"]
            if "listening" in kwargs:
                self._listening_ports = kwargs["listening"]
            if "ssl" in kwargs:
                self._ssl_connections = kwargs["ssl"]
            if "process_conn" in kwargs:
                self._process_connections = kwargs["process_conn"]

            total = (len(self._tcp_connections) + len(self._tcp6_connections) +
                     len(self._udp_connections) + len(self._udp6_connections))

            # Calculate completeness score
            completeness = self._calculate_completeness()

            self._partial_data = {
                "tcp_connections": self._tcp_connections,
                "tcp6_connections": self._tcp6_connections,
                "udp_connections": self._udp_connections,
                "udp6_connections": self._udp6_connections,
                "listening_ports": self._listening_ports,
                "ssl_connections": self._ssl_connections,
                "process_connections": self._process_connections,
                "total_connections": total,
                "listening_count": len(self._listening_ports),
                "_partial": True,
                "_completeness": completeness,
            }

    def get_partial_result(self) -> dict:
        """Get partial result data if available"""
        with self._lock:
            return dict(self._partial_data) if self._partial_data else {}
    def _build_inode_pid_map_with_progress(self) -> dict:
        """Build inode-to-PID mapping with progress tracking for timeout recovery
        
        This method periodically updates partial data during the expensive
        inode-pid map building process (~15-20s) to ensure we have some
        data if timeout occurs.
        
        In large environments (1000+ PIDs with many FDs), this can take 60-120s.
        We add per-PID timeout checks and skip timeout-exceeded PIDs gracefully.
        """
        inode_pid_map = {}
        pids = list(proc.list_pids())
        total_pids = len(pids)
        last_progress_update = time.time()
        progress_interval = 3.0  # Update partial data every 3 seconds (more frequent)
        pid_timeout = 2.0  # Max time per PID to prevent single PID from blocking
        
        for idx, pid in enumerate(pids):
            pid_start = time.time()
            
            # Check soft timeout BEFORE processing each PID (more frequent checks)
            if self._should_skip_due_to_timeout():
                elapsed = time.time() - self._scan_start_time
                logger.warning(
                    f"Network collector: soft timeout during inode-pid map building "
                    f"({idx+1}/{total_pids} PIDs, {elapsed:.1f}s, map_size={len(inode_pid_map)})"
                )
                # Update partial data and return what we have so far
                self._update_partial_result(process_conn={})
                with self._lock:
                    self._partial_data["_partial"] = True
                    self._partial_data["_soft_timeout_phase"] = "inode_map_building"
                return inode_pid_map
            
            try:
                # Add per-PID timeout protection using thread
                fd_list = []
                comm = ""
                pid_exception = None
                
                def _get_pid_data():
                    nonlocal fd_list, comm, pid_exception
                    try:
                        fd_list = proc.get_proc_fd_list(pid)
                        comm = proc.get_proc_stat(pid).get("comm", "")
                    except (OSError, ValueError, KeyError) as e:
                        pid_exception = e
                
                pid_thread = threading.Thread(target=_get_pid_data, daemon=True)
                pid_thread.start()
                pid_thread.join(timeout=pid_timeout)
                
                if pid_thread.is_alive():
                    logger.debug(f"Network collector: PID {pid} FD scan timed out after {pid_timeout}s, skipping")
                    continue
                
                if pid_exception:
                    continue
                    
                for fd_info in fd_list:
                    if fd_info["type"] == "socket":
                        try:
                            target = fd_info["target"]
                            if "[" in target and "]" in target:
                                inode = int(target.split("[")[1].rstrip("]"))
                                inode_pid_map[inode] = (pid, comm)
                        except (ValueError, IndexError):
                            pass
            except (PermissionError, FileNotFoundError):
                pass
            
            # Check if we should update partial data
            current_time = time.time()
            if current_time - last_progress_update > progress_interval:
                last_progress_update = current_time
                elapsed = current_time - self._scan_start_time
                logger.debug(
                    f"Network collector: building inode-pid map "
                    f"({idx+1}/{total_pids} PIDs, {elapsed:.1f}s elapsed, map_size={len(inode_pid_map)})"
                )
                # Update partial data with current progress
                with self._lock:
                    self._partial_data["_inode_map_progress"] = {
                        "pids_processed": idx + 1,
                        "total_pids": total_pids,
                        "map_size": len(inode_pid_map),
                        "elapsed": elapsed
                    }
        
        return inode_pid_map
    
    def _log_progress(self, stage: str, elapsed: float):
        """Log collection progress with timing information"""
        logger.debug(f"Network collector: {stage} ({elapsed:.1f}s)")
    
    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout"""
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time
        # Use 85% as soft limit for quick mode (more lenient since quick mode is optimized), 88% for standard
        # Standard mode has more phases, so we need more headroom
        soft_timeout_ratio = 0.88
        soft_timeout = self.timeout * soft_timeout_ratio
        return elapsed > soft_timeout
    def _enrich_connections(self, connections: list, inode_pid_map: dict) -> list:
        """Enrich connections with PID and process name"""
        enriched = []
        for conn in connections:
            inode = conn.get("inode", 0)
            pid_info = inode_pid_map.get(inode, (0, ""))
            enriched.append({
                "local_ip": conn["local_ip"],
                "local_port": conn["local_port"],
                "remote_ip": conn["remote_ip"],
                "remote_port": conn["remote_port"],
                "state": conn["state"],
                "inode": inode,
                "pid": pid_info[0],
                "process_name": pid_info[1],
            })
        return enriched
    
    def _extract_listening_ports(self, tcp_conns: list, tcp6_conns: list, udp_conns: list, udp6_conns: list) -> list:
        """Extract all listening ports"""
        listening = []
        
        # TCP LISTEN
        for conn in tcp_conns + tcp6_conns:
            if conn["state"] == "LISTEN":
                listening.append({
                    "port": conn["local_port"],
                    "protocol": "tcp",
                    "ip": conn["local_ip"],
                    "pid": conn["pid"],
                    "process": conn["process_name"],
                })
        
        # UDP listening (remote_port == 0)
        for conn in udp_conns + udp6_conns:
            if conn["remote_port"] == 0:
                listening.append({
                    "port": conn["local_port"],
                    "protocol": "udp",
                    "ip": conn["local_ip"],
                    "pid": conn.get("pid", 0),
                    "process": conn.get("process_name", ""),
                })
        
        # Deduplicate and sort
        seen = set()
        unique = []
        for item in listening:
            key = (item["port"], item["protocol"], item["ip"])
            if key not in seen:
                seen.add(key)
                unique.append(item)
        
        return sorted(unique, key=lambda x: (x["port"], x["protocol"]))
    
    def collect(self) -> dict:
        """Collect network connection information with progressive results"""
        self._scan_start_time = time.time()
        
        # Initialize partial data immediately for early timeout recovery
        # This ensures we return structured data even if timeout occurs during 
        # expensive operations like _build_inode_pid_map() or TCP parsing
        self._update_partial_result(
            tcp_conn=[],
            tcp6_conn=[],
            udp_conn=[],
            udp6_conn=[],
            listening=[],
            ssl=[],
            process_conn=[]
        )
        logger.debug("Network collector: initialized empty partial data for timeout recovery")

        # Standard mode: full collection with timeout protection
        # Build inode-to-PID mapping (expensive operation ~15-20s)
        # Check timeout before starting expensive operation
        if self._should_skip_due_to_timeout():
            logger.warning("Network collector: soft timeout before inode-pid map building")
            return self._build_empty_network_result(partial=True, partial_note="Timeout before inode-pid map")
        
        inode_pid_map = self._build_inode_pid_map_with_progress()

        # Check timeout after inode-pid map
        if self._should_skip_due_to_timeout():
            logger.warning("Network collector: soft timeout after inode-pid map building")
            return self._build_empty_network_result(partial=True, partial_note="Timeout after inode-pid map")

        # Parse TCP connections with timeout protection (expensive operation: 10-20s)
        tcp_path = self._paths.get("tcp", "/proc/net/tcp")
        try:
            tcp_connections = self._enrich_connections(
                self._parse_tcp_with_timeout(tcp_path, timeout=self._tcp_parse_timeout),
                inode_pid_map
            )
            self._update_partial_result(tcp_conn=tcp_connections)

        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.warning(f"Network collector: failed to parse TCP: {e}")
            tcp_connections = []
            if self._should_skip_due_to_timeout():
                logger.warning("Network collector: timeout during TCP parsing, returning partial data")
                with self._lock:
                    self._partial_data["_partial"] = True
                return self.get_partial_result()
        elapsed = time.time() - self._scan_start_time
        self._log_progress("tcp_parsed", elapsed)

        # Check timeout before continuing
        if self._should_skip_due_to_timeout():
            logger.warning("Network collector: soft timeout reached, returning partial TCP data")
            with self._lock:
                self._partial_data["_partial"] = True
            return self.get_partial_result()

        # Parse TCP6 connections with timeout protection
        tcp6_path = self._paths.get("tcp6", "/proc/net/tcp6")
        tcp6_connections = self._enrich_connections(
            self._parse_tcp_with_timeout(tcp6_path, timeout=self._tcp_parse_timeout),
            inode_pid_map
        )
        self._update_partial_result(tcp6_conn=tcp6_connections)
        elapsed = time.time() - self._scan_start_time
        self._log_progress("tcp6_parsed", elapsed)

        if self._should_skip_due_to_timeout():
            logger.warning("Network collector: soft timeout reached, returning partial TCP+TCP6 data")
            with self._lock:
                self._partial_data["_partial"] = True
            return self.get_partial_result()

        # Parse UDP connections with timeout protection
        udp_path = self._paths.get("udp", "/proc/net/udp")
        udp_connections = self._enrich_connections(
            self._parse_udp_with_timeout(udp_path, timeout=self._udp_parse_timeout),
            inode_pid_map
        )
        self._update_partial_result(udp_conn=udp_connections)
        elapsed = time.time() - self._scan_start_time
        self._log_progress("udp_parsed", elapsed)

        if self._should_skip_due_to_timeout():
            logger.warning("Network collector: soft timeout reached, returning partial TCP+TCP6+UDP data")
            with self._lock:
                self._partial_data["_partial"] = True
            return self.get_partial_result()

        # Parse UDP6 connections with timeout protection
        udp6_path = self._paths.get("udp6", "/proc/net/udp6")
        udp6_connections = self._enrich_connections(
            self._parse_udp_with_timeout(udp6_path, timeout=self._udp_parse_timeout),
            inode_pid_map
        )
        self._update_partial_result(udp6_conn=udp6_connections)
        elapsed = time.time() - self._scan_start_time
        self._log_progress("udp6_parsed", elapsed)

        # Extract listening ports
        listening_ports = self._extract_listening_ports(
            tcp_connections, tcp6_connections,
            udp_connections, udp6_connections
        )
        self._update_partial_result(listening=listening_ports)
        elapsed = time.time() - self._scan_start_time
        self._log_progress("listening_ports_extracted", elapsed)

        if self._should_skip_due_to_timeout():
            logger.warning("Network collector: soft timeout reached, returning partial data without SSL/process mapping")
            with self._lock:
                self._partial_data["_partial"] = True
            return self.get_partial_result()

        # Collect SSL/TLS connections (port 443, 8443)
        ssl_connections = self._collect_ssl_connections()
        self._update_partial_result(ssl=ssl_connections)

        # Map processes to connections
        process_connections = self._map_process_connections(
            tcp_connections + tcp6_connections
        )
        self._update_partial_result(process_conn=process_connections)

        # Statistics
        total = len(tcp_connections) + len(tcp6_connections) + len(udp_connections) + len(udp6_connections)

        elapsed = time.time() - self._scan_start_time
        logger.debug(
            f"Network collector: returning {total} connections "
            f"(TCP: {len(tcp_connections)}, TCP6: {len(tcp6_connections)}, "
            f"UDP: {len(udp_connections)}, UDP6: {len(udp6_connections)}, "
            f"Listening: {len(listening_ports)}, SSL: {len(ssl_connections)})"
        )

        result = {
            "tcp_connections": tcp_connections,
            "tcp6_connections": tcp6_connections,
            "udp_connections": udp_connections,
            "udp6_connections": udp6_connections,
            "listening_ports": listening_ports,
            "ssl_connections": ssl_connections,
            "process_connections": process_connections,
            "total_connections": total,
            "listening_count": len(listening_ports),
        }

        del tcp_connections, tcp6_connections, udp_connections, udp6_connections
        del listening_ports, ssl_connections, process_connections, inode_pid_map
        
        gc.collect()

        return result
    
    def _build_empty_network_result(self, partial: bool = False, partial_note: str = "") -> dict:
        """Build empty network result for timeout recovery
        
        Args:
            partial: Whether this is a partial result
            partial_note: Note explaining why data is empty/partial
            
        Returns:
            Empty network result dict
        """
        result = {
            "tcp_connections": [],
            "tcp6_connections": [],
            "udp_connections": [],
            "udp6_connections": [],
            "listening_ports": [],
            "ssl_connections": [],
            "process_connections": {},
            "total_connections": 0,
            "listening_count": 0,
        }
        
        if partial:
            result["_partial"] = True
            if partial_note:
                result["_partial_note"] = partial_note
        
        return result
    
    def _collect_ssl_connections(self) -> list:
        """Collect SSL/TLS connection information (HTTPS to LLM APIs)"""
        ssl_conns = []
        
        try:
            # Use ss command to get TLS connections
            result = safe_run_command(
                ["ss", "-tnpa", "( dport = 443 or dport = 8443 )"],
                timeout=10
            )
            
            if not result:
                return ssl_conns
            
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    # Parse: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                    conn_info = {
                        "state": parts[0],
                        "local": parts[4] if len(parts) > 4 else "",
                        "remote": parts[5] if len(parts) > 5 else "",
                        "protocol": "TLS",
                    }
                    
                    # Extract process info if available
                    if len(parts) > 6 and "users:" in parts[6]:
                        proc_info = parts[6]
                        if "(" in proc_info and ")" in proc_info:
                            pid_str = proc_info.split("(")[1].split(")")[0]
                            try:
                                conn_info["pid"] = int(pid_str)
                            except ValueError:
                                pass
                    
                    ssl_conns.append(conn_info)
                    
        except FileNotFoundError:
            logger.debug("SSL collection skipped: 'ss' command not found")
        except OSError as e:
            logger.warning("SSL collection failed due to IO error: %s", e)
        except ValueError as e:
            logger.debug("SSL connection parsing error: %s", e)
        
        return ssl_conns
    
    def _map_process_connections(self, connections: list) -> dict:
        """Map processes to their network connections
        
        Returns:
            dict: {pid: {"process_name": str, "connections": [conn_info]}}
        """
        process_map = {}
        
        for conn in connections:
            pid = conn.get("pid", 0)
            if pid <= 0:
                continue
            
            if pid not in process_map:
                try:
                    comm = proc.get_proc_stat(pid).get("comm", "")
                    cmdline = proc.get_proc_cmdline(pid)
                    process_map[pid] = {
                        "process_name": comm,
                        "cmdline": cmdline,
                        "connections": []
                    }
                except (PermissionError, FileNotFoundError):
                    continue
            
            if pid in process_map:
                process_map[pid]["connections"].append({
                    "remote_ip": conn.get("remote_ip", ""),
                    "remote_port": conn.get("remote_port", 0),
                    "state": conn.get("state", ""),
                })
        
        return process_map
