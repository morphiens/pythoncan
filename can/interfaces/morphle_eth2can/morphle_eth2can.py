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
from collections import deque

import can

log = logging.getLogger("can_comm_logger")


def connect_to_server(s, host, port):
    timeout_ms = 10000
    now = time.time() * 1000
    end_time = now + timeout_ms
    while now < end_time:
        try:
            s.connect((host, port))
            return
        except Exception as e:
            log.warning(f"Failed to bind to server: {type(e)} Message: {e}")
            now = time.time() * 1000
    raise TimeoutError(
        f"connect_to_server: Failed to connect server for {timeout_ms} ms"
    )


class MorphleCanBus(can.BusABC):
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

        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__message_buffer = deque()
        self.__receive_buffer = []
        self.channel_info = f"morphle_eth2can connecting on {host}:{port}"
        connect_to_server(self.__socket, self.__host, self.__port)

        log.error(
            f"morphle_eth2can: started socket server at address {self.__socket.getsockname()}"
        )

        super().__init__(channel=None, can_filters=can_filters, **kwargs)

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
            log.error(f"Failed to receive: {exc}")
            raise can.CanError(f"Failed to receive: {exc}")

        try:
            if not ready_receive_sockets:
                # socket wasn't readable or timeout occurred
                # log.debug("Socket not ready")
                return None, False

            msg = self.__socket.recv(1024)  # may contain multiple messages
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

        except Exception as exc:
            log.error(f"Failed to receive: {exc}  {traceback.format_exc()}")
            raise can.CanError(f"Failed to receive: {exc}  {traceback.format_exc()}")

    def _tcp_send(self, msg):
        log.debug(f"Sending TCP Message: '{msg}'")
        self.__socket.sendall(msg)

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
