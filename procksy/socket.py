"""Socket module
"""
import typing as t
from select import select
from socket import (
    AF_INET,
    SOL_SOCKET,
    SOCK_STREAM,
    SO_REUSEADDR,
    socket,
    inet_pton,
    inet_ntop,
)
from .logging import LOGGER


def create_socket(timeout: int):
    """Create an INET, STREAMing socket"""
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(timeout)
    except OSError:
        LOGGER.exception("socket failed")
        return None
    return sock


def bind_and_listen(sock, addr: str, port: int) -> bool:
    """Bind the socket to address and listen for new connections"""
    try:
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.bind((addr, port))
    except OSError:
        LOGGER.exception("bind failed")
        sock.close()
        return False
    try:
        sock.listen(10)
    except OSError:
        LOGGER.exception("listen failed")
        sock.close()
        return False
    return True


def connect(sock, peer_name: t.Tuple[bytes, int]):
    """Connect to desired destination"""
    try:
        sock.connect(peer_name)
    except OSError:
        LOGGER.exception("connect failed")
        return False
    return True


def sendall(sock, data: bytes) -> bool:
    """Send data"""
    try:
        sock.sendall(data)
    except OSError:
        LOGGER.exception("sendall failed")
        if sock != 0:
            sock.close()
        return False
    return True


def recv(sock, buffer_size: int) -> t.Optional[bytes]:
    """Receive data"""
    try:
        data = sock.recv(buffer_size)
    except OSError:
        LOGGER.exception("recv failed")
        if sock != 0:
            sock.close()
        return None
    return data


def send(sock, data: bytes) -> bool:
    """Send data"""
    try:
        sock.send(data)
    except OSError:
        LOGGER.exception("send failed")
        if sock != 0:
            sock.close()
        return False
    return True


def proxy(client_sock, dest_sock, buffer_size: int) -> bool:
    """Forward data between peers"""
    try:
        reader, _, _ = select([client_sock, dest_sock], [], [], 1)
    except OSError:
        LOGGER.exception("select failed")
        return False
    if not reader:
        return True
    for sock in reader:
        data = recv(sock, buffer_size)
        if not data:
            return False
        status = (
            send(client_sock, data)
            if sock is dest_sock
            else send(dest_sock, data)
        )
        if not status:
            return False
    return True


def encode_addr(addr: str) -> bytes:
    """Encode given address"""
    return inet_pton(AF_INET, addr)


def decode_addr(addr: bytes) -> str:
    """Decode given address depending on its type"""
    return inet_ntop(AF_INET, addr)
