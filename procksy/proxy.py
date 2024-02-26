"""Proxy module
"""
from time import sleep
from threading import Event, Thread, active_count
from dataclasses import dataclass
from .socket import (
    recv,
    proxy,
    connect,
    sendall,
    encode_addr,
    decode_addr,
    create_socket,
    bind_and_listen,
)
from .config import ProcksyConfig
from .logging import LOGGER
from .protocol import (
    build,
    parse,
    ADDR_TYPE_IPV4,
    ADDR_TYPE_DOMAINNAME,
    COMMAND_CONNECT,
    METHOD_NA,
    METHOD_NO_AUTH,
    METHOD_UP_AUTH,
    RESPONSE_SUCCEEDED,
    RESPONSE_SERVER_FAILURE,
    RESPONSE_COMMAND_NOT_SUPPORTED,
    RESPONSE_ADDR_TYPE_NOT_SUPPORTED,
    STATUS_SUCCESS,
    STATUS_FAILURE,
    ServerReplyMessage,
    ClientRequestMessage,
    ServerMethodSelectionMessage,
    ClientMethodSelectionMessage,
    ClientBasicAuthMessage,
    ServerBasicAuthStatusMessage,
)


DECODE_ADDR_MAP = {
    ADDR_TYPE_IPV4: lambda cr_msg: decode_addr(cr_msg.addr),
    ADDR_TYPE_DOMAINNAME: lambda cr_msg: cr_msg.addr.value.decode('utf-8'),
}


@dataclass
class Procksy:
    """Partial SOCKS5 proxy implementation"""

    config: ProcksyConfig
    term_evt: Event

    def _proxy(self, client_sock, dest_addr: bytes, dest_port: int):
        payload = {
            'response': RESPONSE_SERVER_FAILURE,
            'addr_type': ADDR_TYPE_IPV4,
            'addr': bytes([0, 0, 0, 0]),
            'port': 0,
        }
        target = (dest_addr, dest_port)
        LOGGER.info("action=connecting target=%s", target)
        dest_sock = create_socket(self.config.sock_timeout)
        if not dest_sock:
            LOGGER.error("failed to create socket for target %s", target)
            sendall(client_sock, build(ServerReplyMessage, payload))
            return
        connected = connect(dest_sock, target)
        if not connected:
            LOGGER.error("failed to connect to target %s", target)
            sendall(client_sock, build(ServerReplyMessage, payload))
            return
        bound_addr, bound_port = dest_sock.getsockname()
        payload['response'] = RESPONSE_SUCCEEDED
        payload['addr'] = encode_addr(bound_addr)
        payload['port'] = bound_port
        if not sendall(client_sock, build(ServerReplyMessage, payload)):
            LOGGER.error("failed to send RESPONSE_SUCCEEDED to client")
            return
        LOGGER.info(
            "action=proxying client=%s target=%s",
            client_sock.getpeername(),
            target,
        )
        while not self.term_evt.is_set():
            status = proxy(client_sock, dest_sock, self.config.buffer_size)
            if not status:
                break
        if client_sock != 0:
            client_sock.close()
        if dest_sock != 0:
            dest_sock.close()

    def _handle_request(self, client_sock):
        """Handle client request"""
        payload = {
            'response': RESPONSE_COMMAND_NOT_SUPPORTED,
            'addr_type': ADDR_TYPE_IPV4,
            'addr': bytes([0, 0, 0, 0]),
            'port': 0,
        }
        cr_data = recv(client_sock, self.config.buffer_size)
        if not cr_data:
            LOGGER.error("client connection closed")
            return
        cr_msg = parse(ClientRequestMessage, cr_data)
        if not cr_msg:
            LOGGER.error("failed to parse ClientRequestMessage")
            sendall(client_sock, build(ServerReplyMessage, payload))
            return
        if cr_msg.command != COMMAND_CONNECT:
            LOGGER.error("ClientRequestMessage command is not COMMAND_CONNECT")
            sendall(client_sock, build(ServerReplyMessage, payload))
            return
        if cr_msg.addr_type in (ADDR_TYPE_DOMAINNAME, ADDR_TYPE_IPV4):
            dest_port = cr_msg.port
            dest_addr = DECODE_ADDR_MAP[cr_msg.addr_type](cr_msg)
            if not dest_addr:
                LOGGER.error(
                    "action=denied client=%s target=%s error=decode_addr_failed",
                    client_sock.getpeername(),
                    (dest_addr, dest_port),
                )
                sendall(client_sock, build(ServerReplyMessage, payload))
                return
            if not self.config.target_filter.is_allowed(dest_addr, dest_port):
                LOGGER.warning(
                    "action=denied client=%s target=%s",
                    client_sock.getpeername(),
                    (dest_addr, dest_port),
                )
                sendall(client_sock, build(ServerReplyMessage, payload))
                return
            LOGGER.info(
                "action=allowed client=%s target=%s",
                client_sock.getpeername(),
                (dest_addr, dest_port),
            )
            self._proxy(client_sock, dest_addr, dest_port)
            return
        payload['response'] = RESPONSE_ADDR_TYPE_NOT_SUPPORTED
        LOGGER.error("ClientRequestMessage address type not supported")
        sendall(client_sock, build(ServerReplyMessage, payload))

    def _handle_authentication(self, client_sock) -> bool:
        payload = {'status': STATUS_FAILURE}
        cba_msg_data = recv(client_sock, self.config.buffer_size)
        if not cba_msg_data:
            LOGGER.error("client connection closed")
            return False
        cba_msg = parse(ClientBasicAuthMessage, cba_msg_data)
        if not cba_msg:
            LOGGER.error("failed to parse ClientBasicAuthMessage")
            sendall(client_sock, build(ServerBasicAuthStatusMessage, payload))
            return False
        if not self.config.authenticator.is_allowed(
            cba_msg.username.value, cba_msg.password.value
        ):
            sendall(client_sock, build(ServerBasicAuthStatusMessage, payload))
            return False
        payload['status'] = STATUS_SUCCESS
        sendall(client_sock, build(ServerBasicAuthStatusMessage, payload))
        return True

    def _handle_method_selection(self, client_sock):
        """Handle protocol version and authentication method negociation"""
        payload = {
            'method': METHOD_NA,
        }
        peer_addr, _ = client_sock.getpeername()
        if not self.config.client_filter.is_allowed(peer_addr):
            LOGGER.warning(
                "action=denied client=%s", client_sock.getpeername()
            )
            sendall(client_sock, build(ServerMethodSelectionMessage, payload))
            return METHOD_NA
        cms_msg_data = recv(client_sock, self.config.buffer_size)
        if not cms_msg_data:
            LOGGER.error("client connection closed")
            return METHOD_NA
        cms_msg = parse(ClientMethodSelectionMessage, cms_msg_data)
        if not cms_msg:
            LOGGER.error("failed to parse ClientMethodSelectionMessage")
            sendall(client_sock, build(ServerMethodSelectionMessage, payload))
            return METHOD_NA
        if self.config.authenticator.enabled:
            if METHOD_UP_AUTH not in cms_msg.methods:
                LOGGER.error(
                    "ClientMethodSelectionMessage is missing METHOD_UP_AUTH"
                )
                sendall(
                    client_sock, build(ServerMethodSelectionMessage, payload)
                )
                return METHOD_NA
            payload['method'] = METHOD_UP_AUTH
            LOGGER.info(
                "client=%s method=METHOD_UP_AUTH", client_sock.getpeername()
            )
            sendall(client_sock, build(ServerMethodSelectionMessage, payload))
            return METHOD_UP_AUTH
        if METHOD_NO_AUTH in cms_msg.methods:
            payload['method'] = METHOD_NO_AUTH
            LOGGER.info(
                "client=%s method=METHOD_UP_AUTH", client_sock.getpeername()
            )
            sendall(client_sock, build(ServerMethodSelectionMessage, payload))
            return METHOD_NO_AUTH
        LOGGER.error("ClientMethodSelectionMessage unsupported method")
        sendall(client_sock, build(ServerMethodSelectionMessage, payload))
        return METHOD_NA

    def _handle_client(self, client_sock):
        """Handle SOCKS proxy client"""
        method = self._handle_method_selection(client_sock)
        if method == METHOD_NA:
            return
        if method == METHOD_UP_AUTH:
            if not self._handle_authentication(client_sock):
                return
        self._handle_request(client_sock)

    def serve(self):
        """Start serving clients"""
        new_client_sock = create_socket(self.config.sock_timeout)
        bind_and_listen(
            new_client_sock, self.config.bind_addr, self.config.bind_port
        )
        LOGGER.info(
            "serving on %s:%d",
            self.config.bind_addr,
            self.config.bind_port,
        )
        while not self.term_evt.is_set():
            if active_count() > self.config.max_threads:
                sleep(3)
                continue
            try:
                client_sock, _ = new_client_sock.accept()
                client_sock.setblocking(1)
            except TimeoutError:
                continue
            except OSError:
                LOGGER.exception("accept failed")
                continue
            except TypeError:
                LOGGER.exception("type error")
                return
            client_thread = Thread(
                target=self._handle_client, args=(client_sock,)
            )
            client_thread.start()
        new_client_sock.close()
