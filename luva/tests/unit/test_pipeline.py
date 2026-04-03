"""Unit tests for analysis pipeline helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisPipeline
from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.bacnet import BACnetParser
from luva.parsers.dnp3 import DNP3Parser
from luva.parsers.enip import ENIPParser
from luva.parsers.ge_srtp import GeSrtpParser
from luva.parsers.iec104 import IEC104Parser
from luva.parsers.modbus import ModbusParser
from luva.parsers.omron_fins import OmronFinsParser
from luva.parsers.mqtt import MQTTParser
from luva.parsers.opcua import OPCUAParser
from luva.parsers.s7comm import S7Parser
from luva.parsers.snmp import SNMPParser


def test_load_parsers_modbus_only() -> None:
    """Only Modbus parser is loaded when config restricts protocols."""
    cfg = AnalysisConfig(input_files=[], protocols=["modbus"])
    pipe = AnalysisPipeline(cfg)
    assert len(pipe.parsers) == 1
    assert isinstance(pipe.parsers[0], ModbusParser)


def test_load_parsers_opcua_only() -> None:
    cfg = AnalysisConfig(input_files=[], protocols=["opcua"])
    pipe = AnalysisPipeline(cfg)
    assert len(pipe.parsers) == 1
    assert isinstance(pipe.parsers[0], OPCUAParser)


def test_load_parsers_all_defaults() -> None:
    """Default protocol list loads every registered parser."""
    cfg = AnalysisConfig(input_files=[], protocols=[])
    pipe = AnalysisPipeline(cfg)
    types = {type(p) for p in pipe.parsers}
    assert types == {
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
    }


def test_parser_dispatch_matches_port_only_subset() -> None:
    """When dst is Modbus TCP, only Modbus is tried among Modbus+MQTT parsers."""
    cfg = AnalysisConfig(input_files=[], protocols=["modbus", "mqtt"])
    pipe = AnalysisPipeline(cfg)
    pkt = PacketMetadata(
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        length=80,
        src_port=40000,
        dst_port=502,
        transport="TCP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        payload=b"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a",
    )
    ix = pipe._parser_indices_for_packet(pkt)
    assert ix == [0]
    assert isinstance(pipe.parsers[ix[0]], ModbusParser)
