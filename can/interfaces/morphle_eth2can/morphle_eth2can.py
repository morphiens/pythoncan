"""
Interface to morphle socket eth2can
Authors: Ashish Manmode
https://www.uotek.com/pro_view-236.html__name__
https://www.uotek.com/Uploads/file/20230210/20230210143551_12219.pdf
"""
import logging
import select
import socket
import struct
import time
import traceback
import threading
from collections import deque

import can

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

        self.__host = host
        self.__port = port
        
        # Reconnection state
        self.__reconnect_lock = threading.Lock()
        self.__is_reconnecting = False
        self.__connection_healthy = True

        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__message_buffer = deque()
        self.__receive_buffer = []
        self.channel_info = f"morphle_eth2can connecting on {host}:{port}"
        connect_to_server(self.__socket, self.__host, self.__port)

        log.error(
            f"morphle_eth2can: started socket server at address {self.__socket.getsockname()}"
        )

        super().__init__(channel=None, can_filters=can_filters, **kwargs)
    
    def _reconnect(self):
        """Attempt to reconnect the TCP socket with exponential backoff.
        
        Returns True if reconnection was successful, False otherwise.
        Thread-safe: only one reconnection attempt at a time.
        """
        with self.__reconnect_lock:
            if self.__is_reconnecting:
                log.debug("[eth2can] Reconnection already in progress, waiting...")
                return self.__connection_healthy
            self.__is_reconnecting = True
        
        try:
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
                    
                    # Clear buffers
                    self.__receive_buffer = []
                    
                    log.info(f"[eth2can] ✅ Successfully reconnected to {self.__host}:{self.__port} on attempt {attempt}/{self.MAX_RECONNECT_ATTEMPTS}")
                    self.__connection_healthy = True
                    return True
                    
                except (socket.error, OSError, ConnectionRefusedError, ConnectionResetError) as e:
                    log.warning(f"[eth2can] Reconnection attempt {attempt}/{self.MAX_RECONNECT_ATTEMPTS} failed: {e}")
                    if attempt < self.MAX_RECONNECT_ATTEMPTS:
                        log.info(f"[eth2can] Retrying in {delay:.1f}s...")
                        time.sleep(delay)
            
            log.error(f"[eth2can] ❌ Failed to reconnect after {self.MAX_RECONNECT_ATTEMPTS} attempts. Connection is dead.")
            self.__connection_healthy = False
            # Note: Diagnostic report is generated by caller BEFORE calling _reconnect()
            return False
            
        finally:
            with self.__reconnect_lock:
                self.__is_reconnecting = False
    
    def _generate_failure_diagnostic(self, reason: str):
        """Generate a network diagnostic report when connection fails."""
        if DIAGNOSTICS_AVAILABLE and log_diagnostic_report:
            try:
                log_diagnostic_report(
                    trigger_reason=f"eth2can: {reason}",
                    trigger_device=f"eth2can @ {self.__host}:{self.__port}",
                    check_ports=True,
                    device_ports={self.__host: self.__port},
                    logger=log
                )
            except Exception as e:
                log.warning(f"[eth2can] Failed to generate diagnostic report: {e}")
        else:
            # Basic diagnostic without the full module
            log.error(f"[eth2can] 📊 Basic connection diagnostic:")
            log.error(f"   Target: {self.__host}:{self.__port}")
            log.error(f"   Connection healthy: {self.__connection_healthy}")
            log.error(f"   Reconnecting: {self.__is_reconnecting}")
            # Try a simple ping
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

    def _recv_internal(self, timeout):
        if len(self.__message_buffer) != 0:
            can_message = self.__message_buffer.popleft()
            return can_message, False

        try:
            # get all sockets that are ready (can be a list with a single value
            # being self.socket or an empty list if self.socket is not ready)
            ready_receive_sockets, _, _ = select.select(
                [self.__socket], [], [], timeout
            )
        except OSError as exc:
            # something bad happened (e.g. the interface went down)
            log.error(f"[eth2can] select() failed: {exc}")
            # Generate diagnostic BEFORE attempting reconnection
            self._generate_failure_diagnostic(f"select() failed: {type(exc).__name__}: {exc}")
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
                # Generate diagnostic BEFORE attempting reconnection
                self._generate_failure_diagnostic("Connection closed by remote host (recv returned empty)")
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
                        timestamp=0.0,
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
            # Generate diagnostic at time of error (before reconnect attempt)
            self._generate_failure_diagnostic(f"Connection error: {type(exc).__name__}")
            if self._reconnect():
                log.info("[eth2can] Reconnected successfully after connection error in recv")
                return None, False
            raise can.CanError(f"Failed to receive and reconnection failed: {exc}  {traceback.format_exc()}")

        except Exception as exc:
            log.error(f"Failed to receive: {exc}  {traceback.format_exc()}")
            raise can.CanError(f"Failed to receive: {exc}  {traceback.format_exc()}")

    def _tcp_send(self, msg, retry_on_error=True):
        """Send a TCP message with automatic reconnection on failure.
        
        :param msg: The message bytes to send.
        :param retry_on_error: If True, attempt reconnection and retry on connection errors.
        """
        log.debug(f"Sending TCP Message: '{msg}'")
        try:
            self.__socket.sendall(msg)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
            log.error(f"[eth2can] Send failed with connection error: {e}")
            if retry_on_error:
                # Generate diagnostic at time of error (before reconnect attempt)
                self._generate_failure_diagnostic(f"Send failed: {type(e).__name__}")
                if self._reconnect():
                    log.info("[eth2can] Reconnected successfully, retrying send...")
                    # Retry send after reconnection (without retry to avoid infinite loop)
                    self._tcp_send(msg, retry_on_error=False)
                    return
            raise

    def send(self, msg, timeout=None):
        """Transmit a message to the CAN bus.

        :param msg: A message object.
        :param timeout: Ignored
        """
        log.debug("canMessage arbitration_id={} data={} dlc={} timestamp={}".format(msg.arbitration_id,
                                                                                   msg.data, msg.dlc, msg.timestamp))
        header_payload = struct.pack(self.__COMMAND_STRUCT_HEADER, self.__ethcan_message_head, msg.arbitration_id)
        homing_payload = header_payload + msg.data

        log.debug("payload to be sent=" + str([hex(a) for a in homing_payload]))
        self._tcp_send(homing_payload)

    def shutdown(self):
        """Stops all active periodic tasks and closes the socket."""
        super().shutdown()
        self.__socket.close()
