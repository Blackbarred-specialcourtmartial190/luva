"""ICS protocol parsers."""

from luva.parsers.base import BaseParser
from luva.parsers.bacnet import BACnetParser
from luva.parsers.dnp3 import DNP3Parser
from luva.parsers.enip import ENIPParser
from luva.parsers.iec104 import IEC104Parser
from luva.parsers.ge_srtp import GeSrtpParser
from luva.parsers.modbus import ModbusParser
from luva.parsers.mqtt import MQTTParser
from luva.parsers.omron_fins import OmronFinsParser
from luva.parsers.opcua import OPCUAParser
from luva.parsers.s7comm import S7Parser
from luva.parsers.snmp import SNMPParser

ALL_PARSER_CLASSES: tuple[type[BaseParser], ...] = (
    ModbusParser,
    S7Parser,
    DNP3Parser,
    OPCUAParser,
    ENIPParser,
    IEC104Parser,
    BACnetParser,
    MQTTParser,
    SNMPParser,
    OmronFinsParser,
    GeSrtpParser,
)

__all__ = [
    "ALL_PARSER_CLASSES",
    "BaseParser",
    "BACnetParser",
    "DNP3Parser",
    "ENIPParser",
    "GeSrtpParser",
    "IEC104Parser",
    "ModbusParser",
    "MQTTParser",
    "OmronFinsParser",
    "OPCUAParser",
    "S7Parser",
    "SNMPParser",
]
