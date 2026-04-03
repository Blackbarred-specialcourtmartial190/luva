#!/usr/bin/env bash
# Re-download public ICS sample PCAPs (see SOURCES.txt).
set -euo pipefail
cd "$(dirname "$0")"
BASE_WS="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"
BASE_GH="https://raw.githubusercontent.com/w3h/icsmaster/master/pcap"

curl -fsSL -o modbus_icsmaster_part1.pcap "${BASE_GH}/modbus/modbus_test_data_part1.pcap"
curl -fsSL -o s7comm_wireshark_reading_plc_status.pcap "${BASE_WS}/s7comm_reading_plc_status.pcap"
curl -fsSL -o dnp3_wireshark_read.pcap "${BASE_WS}/dnp3_read.pcap"
curl -fsSL -o iec104_wireshark.pcap "${BASE_WS}/iec104.pcap"
curl -fsSL -o opcua_icsmaster_method.pcap "${BASE_GH}/opc/opc-ua-ap-method-wireshark-freeze.pcap"
curl -fsSL -o enip_icsmaster_test.pcap "${BASE_GH}/enip/enip_test.pcap"
ls -la
