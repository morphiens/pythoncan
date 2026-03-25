"""
Interface to morphle socket eth2can
Authors: Ashish Manmode
https://www.uotek.com/pro_view-236.html__name__
https://www.uotek.com/Uploads/file/20230210/20230210143551_12219.pdf
"""
import datetime
import errno
import logging
import os
import select
import socket
import struct
import time
import traceback
import threading
from collections import deque
from typing import Set

import can

try:
    from src.can_service import protocol as can_daemon_protocol
except ImportError:
    can_daemon_protocol = None

# Optional diagnostic import - gracefully degrade if not available
try:
    from src.robotome_commons.diagnostics import log_diagnostic_report
    DIAGNOSTICS_AVAILABLE = True
except ImportError:
    DIAGNOSTICS_AVAILABLE = False
    log_diagnostic_report = None

log = logging.getLogger("can_comm_logger")

# TCP Keepalive configuration
TCP_KEEPALIVE_IDLE = 30      # Start keepalive probes after 30s idle
TCP_KEEPALIVE_INTERVAL = 10  # Send keepalive probes every 10s
TCP_KEEPALIVE_COUNT = 3      # Consider connection dead after 3 failed probes


def configure_tcp_keepalive(sock):
    """Configure TCP keepalive to detect dead connections proactively."""
    try:
        # Enable TCP keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Platform-specific keepalive settings (Linux)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, TCP_KEEPALIVE_IDLE)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, TCP_KEEPALIVE_INTERVAL)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, TCP_KEEPALIVE_COUNT)
        
        log.info(f"[eth2can] TCP keepalive enabled: idle={TCP_KEEPALIVE_IDLE}s, interval={TCP_KEEPALIVE_INTERVAL}s, count={TCP_KEEPALIVE_COUNT}")
    except Exception as e:
        log.warning(f"[eth2can] Failed to configure TCP keepalive: {e}")


def connect_to_server(s, host, port):
    timeout_ms = 10000
    now = time.time() * 1000
    end_time = now + timeout_ms
    while now < end_time:
        try:
            s.connect((host, port))
            configure_tcp_keepalive(s)
            return
        except Exception as e:
            log.warning(f"Failed to bind to server: {type(e)} Message: {e}")
            now = time.time() * 1000
    raise TimeoutError(
        f"connect_to_server: Failed to connect server for {timeout_ms} ms"
    )


def connect_unix_with_retry(path: str) -> socket.socket:
    """Connect to a Unix domain socket with the same retry window as TCP eth2can."""
    timeout_ms = 10000
    now = time.time() * 1000
    end_time = now + timeout_ms
    last_exc = None
    while now < end_time:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
            return s
        except OSError as e:
            last_exc = e
            try:
                s.close()
            except Exception:
                pass
            log.warning(f"Failed to connect Unix CAN daemon socket {path}: {e}")
            time.sleep(0.2)
            now = time.time() * 1000
    raise TimeoutError(
        f"connect_unix_with_retry: Failed to connect {path} for {timeout_ms} ms: {last_exc}"
    )


def _use_separate_can_from_env() -> bool:
    """True when morphle.profile (or env) sets USE_SEPARATE_CAN_SERVICE."""
    v = os.environ.get("USE_SEPARATE_CAN_SERVICE", "").strip().lower()
    return v in ("1", "true", "yes", "on")


DEFAULT_CAN_SERVICE_SOCKET = "/run/robotome-can/can.sock"


class MorphleCanBus(can.BusABC):
    # Maximum reconnection attempts before giving up
    MAX_RECONNECT_ATTEMPTS = 5
    RECONNECT_DELAY_BASE = 1.0  # Base delay between reconnection attempts (exponential backoff)
    
    def __init__(self, channel, host, port, can_filters=None, **kwargs):
        """Connects to a CAN bus served by socketcand.

        1. Make UOTEK can port as server
        2. Connect from MorphleCanBus
        3. Create multiple can handlers for connecting to different can bus

        It will attempt to connect to the server for up to 10s, after which a
        TimeoutError exception will be thrown.

        If the handshake with the socketcand server fails, a CanError exception
        is thrown.
        
        :param host:
            The host address of the socketcand server.
        :param port:
            The port of the socketcand server.
        :param can_filters:
            See :meth:`can.BusABC.set_filters`.
        """

        # Below parameters are taken from UOTek documentation
        # refer to https://www.uotek.com/Uploads/file/20230210/20230210143551_12219.pdf
        self.__COMMAND_STRUCT_HEADER = ">BI"
        self.__ethcan_message_fixed_len = 13
        self.__ethcan_message_head = 0x08

        use_separate = kwargs.pop("use_separate_can_service", None)
        if use_separate is None:
            use_separate = _use_separate_can_from_env()
        else:
            use_separate = bool(use_separate)

        self._proxy_bus_id = int(kwargs.pop("proxy_bus_id", 1))
        socket_path_kw = kwargs.pop("can_service_socket", None)
        self._socket_path = socket_path_kw or os.environ.get(
            "CAN_SERVICE_SOCKET", DEFAULT_CAN_SERVICE_SOCKET
        )
        self._on_transport_reconnect = kwargs.pop("on_transport_reconnect", None)

        self.__reconnect_lock = threading.Lock()
        self.__is_reconnecting = False
        self.__connection_healthy = True
        self.__last_failure_type = "unknown"  # set before each _reconnect() call (TCP path)
        self.__fault_detected_at: float = 0.0  # monotonic timestamp of first fault detection

        self.__message_buffer = deque()
        self.__receive_buffer = []

        if use_separate:
            if can_daemon_protocol is None:
                raise ImportError(
                    "use_separate_can_service requires src.can_service.protocol (repo root on PYTHONPATH)."
                )
            self._proxy_mode = True
            self._proxy_protocol = can_daemon_protocol
            self._proxy_subscribed_ids: Set[int] = set()
            self.__host = host
            self.__port = int(port)
            self.__socket = connect_unix_with_retry(self._socket_path)
            self.channel_info = (
                f"morphle_eth2can via robotome-can daemon unix:{self._socket_path} bus={self._proxy_bus_id}"
            )
            log.info(
                "morphle_eth2can: connected to CAN daemon at %s (bus_id=%d)",
                self._socket_path,
                self._proxy_bus_id,
            )
        else:
            self._proxy_mode = False
            self.__host = host
            self.__port = int(port)
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.channel_info = f"morphle_eth2can connecting on {host}:{port}"
            connect_to_server(self.__socket, self.__host, self.__port)
            log.info(
                f"morphle_eth2can: started socket server at address {self.__socket.getsockname()}"
            )

        super().__init__(channel=None, can_filters=can_filters, **kwargs)

    def _invoke_transport_reconnect_hook(self) -> None:
        hook = getattr(self, "_on_transport_reconnect", None)
        if callable(hook):
            try:
                hook()
            except Exception as exc:
                log.warning("[eth2can] on_transport_reconnect hook failed: %s", exc)

    def _mark_fault_detected(self):
        """Stamp the monotonic time of the first fault detection (idempotent)."""
        if self.__fault_detected_at == 0.0:
            self.__fault_detected_at = time.monotonic()

    def notify_subscription(self, can_id: int, add: bool) -> None:
        """When using robotome-can daemon, forward SUBSCRIBE/UNSUBSCRIBE (see CANHandler.subscribe)."""
        if not self._proxy_mode:
            return
        if add:
            self._proxy_subscribed_ids.add(can_id)
            self._socket_send(
                self._proxy_protocol.encode_subscribe(self._proxy_bus_id, can_id),
                retry_on_error=True,
            )
        else:
            self._proxy_subscribed_ids.discard(can_id)
            self._socket_send(
                self._proxy_protocol.encode_unsubscribe(self._proxy_bus_id, can_id),
                retry_on_error=True,
            )

    def get_bus_state(self):
        """Subset used by CANHandler.get_bus_state / BaseController diagnostics."""
        return {
            "channel_info": self.channel_info,
            "bus_ready": self.__connection_healthy,
            "bus_alive": self.__connection_healthy,
            "msg_tx_count": None,
            "msg_rx_count": None,
        }

    def _reconnect(self):
        """Reconnect TCP to eth2can hardware, or Unix socket to robotome-can daemon."""
        with self.__reconnect_lock:
            if self.__is_reconnecting:
                log.debug("[eth2can] Reconnection already in progress, waiting...")
                return self.__connection_healthy
            self.__is_reconnecting = True

        reconnect_start = time.monotonic()
        try:
            if self._proxy_mode:
                log.warning(
                    "[eth2can] 🔄 Attempting to reconnect CAN daemon socket %s...",
                    self._socket_path,
                )
                for attempt in range(1, self.MAX_RECONNECT_ATTEMPTS + 1):
                    delay = min(self.RECONNECT_DELAY_BASE * (2 ** (attempt - 1)), 10.0)
                    try:
                        try:
                            self.__socket.close()
                        except Exception:
                            pass
                        self.__socket = connect_unix_with_retry(self._socket_path)
                        self.__receive_buffer = []
                        self.__message_buffer.clear()
                        for cid in sorted(self._proxy_subscribed_ids):
                            try:
                                self.__socket.sendall(
                                    self._proxy_protocol.encode_subscribe(self._proxy_bus_id, cid)
                                )
                            except Exception as exc:
                                log.warning("[eth2can] resubscribe can_id=0x%X failed: %s", cid, exc)
                        log.info(
                            "[eth2can] ✅ Reconnected to CAN daemon %s (attempt %d/%d)",
                            self._socket_path,
                            attempt,
                            self.MAX_RECONNECT_ATTEMPTS,
                        )
                        self.__connection_healthy = True
                        self._invoke_transport_reconnect_hook()
                        return True
                    except (socket.error, OSError, TimeoutError) as e:
                        log.warning(
                            "[eth2can] Daemon reconnection attempt %d/%d failed: %s",
                            attempt,
                            self.MAX_RECONNECT_ATTEMPTS,
                            e,
                        )
                        if attempt < self.MAX_RECONNECT_ATTEMPTS:
                            time.sleep(delay)
                log.error("[eth2can] ❌ Failed to reconnect CAN daemon socket.")
                self.__connection_healthy = False
                return False

            log.warning(f"[eth2can] 🔄 Attempting to reconnect to {self.__host}:{self.__port}...")

            for attempt in range(1, self.MAX_RECONNECT_ATTEMPTS + 1):
                delay = min(self.RECONNECT_DELAY_BASE * (2 ** (attempt - 1)), 10.0)  # Max 10s delay

                try:
                    # Close old socket
                    try:
                        self.__socket.close()
                    except Exception:
                        pass

                    # Create new socket
                    self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.__socket.settimeout(5.0)  # 5 second timeout for connect

                    # Attempt connection
                    self.__socket.connect((self.__host, self.__port))
                    self.__socket.settimeout(None)  # Reset to blocking mode

                    # Configure keepalive on new socket
                    configure_tcp_keepalive(self.__socket)

                    # Clear ALL buffers to avoid stale message issues
                    self.__receive_buffer = []
                    self.__message_buffer.clear()

                    reconnect_sec = time.monotonic() - reconnect_start
                    downtime_sec = (
                        (time.monotonic() - self.__fault_detected_at)
                        if self.__fault_detected_at > 0 else reconnect_sec
                    )
                    log.info(
                        f"[eth2can] ✅ Reconnected to {self.__host}:{self.__port} "
                        f"on attempt {attempt}/{self.MAX_RECONNECT_ATTEMPTS} "
                        f"| reconnect took {reconnect_sec:.1f}s "
                        f"| back in {downtime_sec:.1f}s since fault detected"
                    )
                    self.__connection_healthy = True
                    self._log_uotek_device_failure(
                        error_type=self.__last_failure_type,
                        detail=f"reconnected on attempt {attempt}/{self.MAX_RECONNECT_ATTEMPTS}",
                        recovered=True,
                        downtime_sec=downtime_sec,
                    )
                    self.__fault_detected_at = 0.0
                    self._invoke_transport_reconnect_hook()
                    return True

                except (socket.error, OSError, ConnectionRefusedError, ConnectionResetError) as e:
                    log.warning(f"[eth2can] Reconnection attempt {attempt}/{self.MAX_RECONNECT_ATTEMPTS} failed: {e}")
                    if attempt < self.MAX_RECONNECT_ATTEMPTS:
                        log.info(f"[eth2can] Retrying in {delay:.1f}s...")
                        time.sleep(delay)

            reconnect_sec = time.monotonic() - reconnect_start
            downtime_sec = (
                (time.monotonic() - self.__fault_detected_at)
                if self.__fault_detected_at > 0 else reconnect_sec
            )
            log.error(
                f"[eth2can] ❌ Failed to reconnect after {self.MAX_RECONNECT_ATTEMPTS} attempts "
                f"| {reconnect_sec:.1f}s spent trying | down for {downtime_sec:.1f}s. Connection is dead."
            )
            self.__connection_healthy = False
            if not self._proxy_mode:
                self._log_uotek_device_failure(
                    error_type=self.__last_failure_type,
                    detail=f"reconnect exhausted all {self.MAX_RECONNECT_ATTEMPTS} attempts — connection dead",
                    recovered=False,
                    downtime_sec=downtime_sec,
                )
            return False

        finally:
            with self.__reconnect_lock:
                self.__is_reconnecting = False
    
    def _probe_device(self) -> tuple:
        """Quick non-blocking probe to determine whether the UOTEK device itself
        is reachable and whether its TCP server port is up.

        Runs two checks in parallel (via threads) so total latency is bounded by
        the slower of the two, not their sum.

        Returns:
            (ping_ok: bool, port_open: bool)
            ping_ok   — True if ICMP echo reply received within 1 s
            port_open — True if TCP connect to self.__host:self.__port succeeds
                        within 1 s (i.e. the CAN server is already back up)
        """
        import subprocess
        ping_ok = False
        port_open = False

        def _ping():
            nonlocal ping_ok
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', self.__host],
                    capture_output=True, timeout=2
                )
                ping_ok = (result.returncode == 0)
            except Exception:
                ping_ok = False

        def _port():
            nonlocal port_open
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((self.__host, self.__port))
                s.close()
                port_open = True
            except Exception:
                port_open = False

        t1 = threading.Thread(target=_ping, daemon=True)
        t2 = threading.Thread(target=_port, daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=2.5)
        t2.join(timeout=2.5)
        return ping_ok, port_open

    def _log_uotek_device_failure(
        self, error_type: str, detail: str, recovered: bool = False,
        downtime_sec: float = -1.0,
    ):
        """Probe the UOTEK device and emit a structured WARNING classifying the fault.

        Distinguishes three root causes so the log is actionable:
          - UOTEK_DEVICE_FAULT  : device is pingable but its TCP server port is down
                                  → UOTEK firmware reset / watchdog cycle
          - NETWORK_FAULT       : device is not pingable at all
                                  → switch, cable, or PoE issue
          - UNKNOWN_FAULT       : probe inconclusive (device mid-reset, probe timed out)

        The tag [UOTEK_FAULT] is always present so a single grep finds all events
        regardless of classification.

        Args:
            error_type: Short error category, e.g. 'ConnectionResetError', 'BrokenPipe',
                        'recv_empty', 'select_error', 'socket_unhealthy'.
            detail:     Human-readable context (what operation was in progress).
            recovered:  True if the subsequent _reconnect() call succeeded.
            downtime_sec: Total downtime in seconds (-1 if unknown).
        """
        # Only probe on the initial failure, not on the recovery log call
        # (by then the socket is already reconnected, probe would show port_open=True)
        if not recovered:
            try:
                ping_ok, port_open = self._probe_device()
            except Exception:
                ping_ok, port_open = False, False

            if ping_ok and not port_open:
                fault_class = "UOTEK_DEVICE_FAULT"
                fault_desc = (
                    f"device is pingable but TCP port {self.__port} is DOWN "
                    f"→ UOTEK firmware reset / watchdog cycle"
                )
            elif not ping_ok:
                fault_class = "NETWORK_FAULT"
                fault_desc = (
                    f"device {self.__host} is NOT pingable "
                    f"→ network switch / cable / PoE issue"
                )
            else:
                # ping_ok=True AND port_open=True: device recovered before we even probed
                fault_class = "UNKNOWN_FAULT"
                fault_desc = (
                    f"device is pingable and port {self.__port} is already open "
                    f"(recovered before probe, or transient glitch)"
                )
        else:
            fault_class = "RECOVERED"
            fault_desc = detail
            ping_ok = port_open = None  # not probed on recovery path

        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "RECOVERED" if recovered else "PENDING_RECONNECT"
        downtime_str = f"{downtime_sec:.1f}s" if downtime_sec >= 0 else "unknown"

        log.warning(
            f"[UOTEK_FAULT] ⚠️  CAN bus TCP drop  "
            f"| device={self.__host}:{self.__port}  "
            f"| error={error_type}  "
            f"| fault_class={fault_class}  "
            f"| {fault_desc}  "
            f"| context={detail}  "
            f"| status={status}  "
            f"| downtime={downtime_str}  "
            f"| ts={ts}"
        )

    def _generate_failure_diagnostic(self, reason: str):
        """Generate a network diagnostic report when connection fails."""
        if DIAGNOSTICS_AVAILABLE and log_diagnostic_report:
            try:
                if self._proxy_mode:
                    log_diagnostic_report(
                        trigger_reason=f"eth2can daemon: {reason}",
                        trigger_device=f"unix:{self._socket_path}",
                        check_ports=False,
                        device_ports={},
                        logger=log,
                    )
                else:
                    log_diagnostic_report(
                        trigger_reason=f"eth2can: {reason}",
                        trigger_device=f"eth2can @ {self.__host}:{self.__port}",
                        check_ports=True,
                        device_ports={self.__host: self.__port},
                        logger=log,
                    )
            except Exception as e:
                log.warning(f"[eth2can] Failed to generate diagnostic report: {e}")
        else:
            log.error(f"[eth2can] 📊 Basic connection diagnostic:")
            if self._proxy_mode:
                log.error(f"   Target: unix:{self._socket_path}")
            else:
                log.error(f"   Target: {self.__host}:{self.__port}")
            log.error(f"   Connection healthy: {self.__connection_healthy}")
            log.error(f"   Reconnecting: {self.__is_reconnecting}")
            if not self._proxy_mode:
                try:
                    import subprocess
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '2', self.__host],
                        capture_output=True, text=True, timeout=3
                    )
                    ping_ok = result.returncode == 0
                    log.error(f"   Ping to {self.__host}: {'✓ OK' if ping_ok else '✗ FAILED'}")
                except Exception as e:
                    log.error(f"   Ping check failed: {e}")

    def _recv_internal_proxy(self, timeout):
        """Receive one FRAME from robotome-can daemon (Unix socket protocol)."""
        try:
            ready_receive_sockets, _, _ = select.select(
                [self.__socket], [], [], timeout
            )
        except OSError as exc:
            log.error(f"[eth2can] select() failed (daemon): {exc}")
            self._generate_failure_diagnostic(f"select() failed: {type(exc).__name__}: {exc}")
            if self._reconnect():
                log.info("[eth2can] Reconnected after select() error (daemon)")
                return None, False
            raise can.CanError(f"Failed to receive: {exc}")

        if not ready_receive_sockets:
            return None, False

        try:
            msg = self._proxy_protocol.read_message(self.__socket)
        except ValueError as exc:
            log.error(f"[eth2can] Invalid daemon frame: {exc}")
            return None, False
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError) as exc:
            log.error(f"[eth2can] Connection error in recv (daemon): {exc}")
            self._generate_failure_diagnostic(f"Connection error: {type(exc).__name__}")
            if self._reconnect():
                log.info("[eth2can] Reconnected successfully after connection error in recv (daemon)")
                return None, False
            raise can.CanError(f"Failed to receive and reconnection failed: {exc}")

        if msg[0] != self._proxy_protocol.FRAME:
            log.debug("[eth2can] daemon message type %s (not FRAME), ignoring", msg[0])
            return None, False

        _, bus_id, can_id, ts, data = msg
        if bus_id != self._proxy_bus_id:
            return None, False
        return (
            can.Message(
                arbitration_id=can_id,
                data=data,
                is_extended_id=False,
                timestamp=ts,
            ),
            False,
        )

    def _recv_internal(self, timeout):
        if len(self.__message_buffer) != 0:
            can_message = self.__message_buffer.popleft()
            return can_message, False

        if self._proxy_mode:
            return self._recv_internal_proxy(timeout)

        try:
            # get all sockets that are ready (can be a list with a single value
            # being self.socket or an empty list if self.socket is not ready)
            ready_receive_sockets, _, _ = select.select(
                [self.__socket], [], [], timeout
            )
        except OSError as exc:
            # something bad happened (e.g. the interface went down)
            log.error(f"[eth2can] select() failed: {exc}")
            self._mark_fault_detected()
            self._log_uotek_device_failure("select_error", f"select() failed: {exc}")
            # Generate diagnostic BEFORE attempting reconnection
            self._generate_failure_diagnostic(f"select() failed: {type(exc).__name__}: {exc}")
            self.__last_failure_type = "select_error"
            # Attempt reconnection
            if self._reconnect():
                log.info("[eth2can] Reconnected successfully after select() error, returning None for this recv cycle")
                return None, False
            raise can.CanError(f"Failed to receive: {exc}")

        try:
            if not ready_receive_sockets:
                # socket wasn't readable or timeout occurred
                # log.debug("Socket not ready")
                return None, False

            msg = self.__socket.recv(1024)  # may contain multiple messages
            
            # Check for connection closed (recv returns empty bytes)
            if not msg:
                log.error("[eth2can] Connection closed by remote host (recv returned empty)")
                self._mark_fault_detected()
                self._log_uotek_device_failure("recv_empty", "UOTEK closed TCP connection (FIN received)")
                # Generate diagnostic BEFORE attempting reconnection
                self._generate_failure_diagnostic("Connection closed by remote host (recv returned empty)")
                self.__last_failure_type = "recv_empty"
                if self._reconnect():
                    log.info("[eth2can] Reconnected successfully after connection closed")
                    return None, False
                raise can.CanError("Connection closed by remote host and reconnection failed")
            
            log.debug("received raw can message (over ethernet, may contain multiple can messages). len={}, message={}".format(len(msg), msg))
            self.__receive_buffer += msg

            num_messages = int(len(self.__receive_buffer) / self.__ethcan_message_fixed_len)
            for i in range(num_messages):
                can_frame = self.__receive_buffer[
                            i * self.__ethcan_message_fixed_len:(i + 1) * self.__ethcan_message_fixed_len]
                if self.__receive_buffer[i * self.__ethcan_message_fixed_len] <= self.__ethcan_message_head:
                    log.debug("[{}/{}] received full eth2can message: {}".format(i, num_messages, can_frame))
                    self.__message_buffer.append(can.Message(
                        arbitration_id=struct.unpack(self.__COMMAND_STRUCT_HEADER, bytes(can_frame[:5]))[1],
                        data=can_frame[5:],
                        is_extended_id=False,
                        timestamp=time.time(),
                    ))
                else:
                    log.error("[{}/{}] invalid eth2can message, Please check the eth2can configuration. "
                          " Contact the Author more details: {}".format(i, num_messages, can_frame))

            self.__receive_buffer = self.__receive_buffer[
                                    num_messages *
                                    self.__ethcan_message_fixed_len:]

            can_message = (
                None
                if len(self.__message_buffer) == 0
                else self.__message_buffer.popleft()
            )
            log.debug("returning can message: " + str(can_message))
            return can_message, False

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as exc:
            # Connection-specific errors - attempt reconnection
            log.error(f"[eth2can] Connection error in recv: {exc}")
            self._mark_fault_detected()
            error_type = type(exc).__name__
            self._log_uotek_device_failure(error_type, f"TCP RST/drop detected in recv: {exc}")
            # Generate diagnostic at time of error (before reconnect attempt)
            self._generate_failure_diagnostic(f"Connection error: {error_type}")
            self.__last_failure_type = error_type
            if self._reconnect():
                log.info("[eth2can] Reconnected successfully after connection error in recv")
                return None, False
            raise can.CanError(f"Failed to receive and reconnection failed: {exc}  {traceback.format_exc()}")

        except Exception as exc:
            log.error(f"Failed to receive: {exc}  {traceback.format_exc()}")
            raise can.CanError(f"Failed to receive: {exc}  {traceback.format_exc()}")

    def _check_socket_health(self) -> bool:
        """Proactively check if the TCP socket is still alive before sending.

        Uses a zero-timeout select() on the exceptional-condition set.  On Linux,
        a RST from the remote end sets the socket error flag which shows up as an
        exceptional condition.  We also do a non-blocking peek recv: if the remote
        closed the connection cleanly (FIN) the socket becomes readable and recv
        returns b'', which we detect here rather than waiting for the 2 s read_ack
        timeout to fire.

        Returns True if the socket appears healthy, False if it is dead.
        """
        try:
            # Check for exceptional conditions (RST / socket error)
            _, _, exceptional = select.select([], [], [self.__socket], 0)
            if exceptional:
                log.warning("[eth2can] _check_socket_health: socket has exceptional condition (RST?)")
                return False
            # Check if socket is readable with zero timeout — if so, peek at data
            readable, _, _ = select.select([self.__socket], [], [], 0)
            if readable:
                # Peek without consuming — if it returns empty the connection is closed
                peek = self.__socket.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                if not peek:
                    log.warning("[eth2can] _check_socket_health: recv peek returned empty (connection closed)")
                    return False
        except (OSError, socket.error) as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                # EAGAIN/EWOULDBLOCK from MSG_DONTWAIT recv means no data available right now —
                # not a dead socket. The select() indicated readable but the data was already
                # consumed (e.g. by the notifier thread) between select and recv. Socket is healthy.
                return True
            log.warning(f"[eth2can] _check_socket_health: socket error during health check: {e}")
            return False
        return True

    def _socket_send(self, msg, retry_on_error=True):
        """Send raw bytes (TCP eth2can or daemon IPC). TCP path uses proactive health check."""
        log.debug("Sending socket message (len=%d)", len(msg))

        if not self._proxy_mode:
            if not self._check_socket_health():
                log.warning("[eth2can] _socket_send: socket unhealthy before send, triggering reconnect")
                self._mark_fault_detected()
                self._log_uotek_device_failure(
                    "socket_unhealthy",
                    "dead socket detected by proactive health check before send",
                )
                self._generate_failure_diagnostic("Socket unhealthy before send")
                self.__last_failure_type = "socket_unhealthy"
                if self._reconnect():
                    log.warning(
                        "[eth2can] Reconnected successfully (proactive). Retrying send on fresh socket."
                    )
                    self.__socket.sendall(msg)
                    return
                raise ConnectionResetError("[eth2can] Socket dead and reconnection failed before send")

        try:
            self.__socket.sendall(msg)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
            log.error(f"[eth2can] Send failed with connection error: {e}")
            error_type = type(e).__name__
            if self._proxy_mode:
                if retry_on_error:
                    self._generate_failure_diagnostic(f"Send failed: {error_type}")
                    if self._reconnect():
                        log.warning(
                            "[eth2can] Reconnected successfully after send error. "
                            "NOT retrying send to avoid duplicate messages - let higher layer retry."
                        )
                raise
            self._mark_fault_detected()
            self._log_uotek_device_failure(error_type, f"TCP error on send: {e}")
            if retry_on_error:
                self._generate_failure_diagnostic(f"Send failed: {error_type}")
                self.__last_failure_type = error_type
                if self._reconnect():
                    log.warning(
                        "[eth2can] Reconnected successfully after send error. "
                        "NOT retrying send to avoid duplicate messages - let higher layer retry."
                    )
            raise

    def send(self, msg, timeout=None):
        """Transmit a message to the CAN bus.

        :param msg: A message object.
        :param timeout: Ignored
        """
        log.debug("canMessage arbitration_id={} data={} dlc={} timestamp={}".format(msg.arbitration_id,
                                                                                   msg.data, msg.dlc, msg.timestamp))
        if self._proxy_mode:
            payload = self._proxy_protocol.encode_send(
                self._proxy_bus_id,
                msg.arbitration_id,
                bytes(msg.data)[:8],
            )
            self._socket_send(payload)
            return

        header_payload = struct.pack(self.__COMMAND_STRUCT_HEADER, self.__ethcan_message_head, msg.arbitration_id)
        homing_payload = header_payload + msg.data

        log.debug("payload to be sent=" + str([hex(a) for a in homing_payload]))
        self._socket_send(homing_payload)

    def shutdown(self):
        """Stops all active periodic tasks and closes the socket."""
        super().shutdown()
        self.__socket.close()
