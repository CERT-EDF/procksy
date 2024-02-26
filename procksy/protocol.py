"""Protocol module
"""
import typing as t
from construct import (
    Enum,
    Array,
    Bytes,
    Const,
    Int8ub,
    Struct,
    Switch,
    Int16ub,
    StreamError,
    this,
)


VER_UP_AUTH = b'\x01'
VER_SOCKS_V5 = b'\x05'
ADDR_TYPE_IPV4 = 'IPV4'
ADDR_TYPE_IPV6 = 'IPV6'
ADDR_TYPE_DOMAINNAME = 'DOMAINNAME'
COMMAND_BIND = 'BIND'
COMMAND_UDP_ASSOCIATE = 'UDP_ASSOCIATE'
COMMAND_CONNECT = 'CONNECT'
METHOD_NA = 0xFF
METHOD_NO_AUTH = 0x00
METHOD_UP_AUTH = 0x02
RESPONSE_SUCCEEDED = 'SUCCEEDED'
RESPONSE_SERVER_FAILURE = 'SERVER_FAILURE'
RESPONSE_CONNECTION_NOT_ALLOWED = 'CONNECTION_NOT_ALLOWED'
RESPONSE_NETWORK_UNREACHABLE = 'NETWORK_UNREACHABLE'
RESPONSE_HOST_UNREACHABLE = 'HOST_UNREACHABLE'
RESPONSE_CONNECTION_REFUSED = 'CONNECTION_REFUSED'
RESPONSE_TTL_EXPIRED = 'TTL_EXPIRED'
RESPONSE_COMMAND_NOT_SUPPORTED = 'COMMAND_NOT_SUPPORTED'
RESPONSE_ADDR_TYPE_NOT_SUPPORTED = 'ADDR_TYPE_NOT_SUPPORTED'
STATUS_FAILURE = 0xFF
STATUS_SUCCESS = 0x00
# Client Method Selection Message
# +----+----------+----------+
# |VER | NMETHODS | METHODS  |
# +----+----------+----------+
ClientMethodSelectionMessage = Struct(
    'version' / Const(VER_SOCKS_V5),
    'nmethods' / Int8ub,
    'methods' / Array(this.nmethods, Int8ub),
)
# Server Method Selection Message
# +----+--------+
# |VER | METHOD |
# +----+--------+
ServerMethodSelectionMessage = Struct(
    'version' / Const(VER_SOCKS_V5),
    'method' / Int8ub,
)
# Client Request Message
# +----+-----+-------+------+----------+----------+
# |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
# +----+-----+-------+------+----------+----------+
LString = Struct(
    'size' / Int8ub,
    'value' / Bytes(this.size),
)
ClientRequestMessage = Struct(
    'version' / Const(VER_SOCKS_V5),
    'command' / Enum(Int8ub, CONNECT=0x01, BIND=0x02, UDP_ASSOCIATE=0x03),
    'reserved' / Const(b'\x00'),
    'addr_type' / Enum(Int8ub, IPV4=0x01, DOMAINNAME=0x03, IPV6=0x04),
    'addr'
    / Switch(
        this.addr_type,
        {
            ADDR_TYPE_IPV4: Bytes(4),
            ADDR_TYPE_IPV6: Bytes(16),
            ADDR_TYPE_DOMAINNAME: LString,
        },
    ),
    'port' / Int16ub,
)
# Server Reply Message
# +----+-----+-------+------+----------+----------+
# |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
# +----+-----+-------+------+----------+----------+
ServerReplyMessage = Struct(
    'version' / Const(VER_SOCKS_V5),
    'response'
    / Enum(
        Int8ub,
        SUCCEEDED=0x00,
        SERVER_FAILURE=0x01,
        CONNECTION_NOT_ALLOWED=0x02,
        NETWORK_UNREACHABLE=0x03,
        HOST_UNREACHABLE=0x04,
        CONNECTION_REFUSED=0x05,
        TTL_EXPIRED=0x06,
        COMMAND_NOT_SUPPORTED=0x07,
        ADDR_TYPE_NOT_SUPPORTED=0x08,
    ),
    'reserved' / Const(b'\x00'),
    'addr_type' / Enum(Int8ub, IPV4=0x01, DOMAINNAME=0x03, IPV6=0x04),
    'addr'
    / Switch(
        this.addr_type,
        {
            ADDR_TYPE_IPV4: Bytes(4),
            ADDR_TYPE_IPV6: Bytes(16),
            ADDR_TYPE_DOMAINNAME: LString,
        },
    ),
    'port' / Int16ub,
)
# Client Basic Auth Message
# +-----+------------+----------+
# | VER |  USERNAME  | PASSWORD |
# +-----+------------+----------+
ClientBasicAuthMessage = Struct(
    'version' / Const(VER_UP_AUTH),
    'username' / LString,
    'password' / LString,
)
# Server Basic Auth Status Message
# +-----+--------+
# | VER | STATUS |
# +-----+--------+
ServerBasicAuthStatusMessage = Struct(
    'version' / Const(VER_UP_AUTH),
    'status' / Int8ub,
)


def build(msg_struct: Struct, payload: t.Mapping[str, t.Any]):
    """Build message from payload"""
    return msg_struct.build(payload)


def parse(msg_struct: Struct, data: bytes):
    """Safe message parsing handling StreamError"""
    try:
        return msg_struct.parse(data)
    except StreamError:
        return None
