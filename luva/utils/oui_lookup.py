"""OUI lookup — vendor hints from MAC prefixes common in OT environments."""

from __future__ import annotations

# Common OT vendor OUIs (first three octets, colon-separated)
ICS_OUI_DATABASE: dict[str, str] = {
    # Siemens
    "00:0E:8C": "Siemens AG",
    "00:1B:1B": "Siemens AG",
    "00:1C:06": "Siemens AG",
    "00:50:56": "VMware (virtual)",
    "08:00:06": "Siemens AG",
    "A8:F7:E0": "Siemens AG",
    "64:9F:F7": "Siemens AG",

    # Schneider Electric / Modicon
    "00:00:54": "Schneider Electric",
    "00:80:F4": "Schneider Electric (Modicon)",
    "00:20:D5": "Schneider Electric",

    # Allen-Bradley / Rockwell
    "00:00:BC": "Rockwell Automation (Allen-Bradley)",
    "00:01:01": "Rockwell Automation",
    "00:1D:9C": "Rockwell Automation",

    # ABB
    "00:02:99": "ABB",
    "00:21:99": "ABB",
    "00:24:2B": "ABB",

    # Honeywell
    "00:40:84": "Honeywell",
    "00:D0:2B": "Honeywell",

    # Emerson / Fisher-Rosemount
    "00:11:57": "Emerson Process Management",
    "00:A0:68": "Emerson Electric",

    # GE / Fanuc
    "00:04:A5": "GE Intelligent Platforms",
    "00:60:E9": "GE Fanuc Automation",

    # Yokogawa
    "00:01:E5": "Yokogawa Electric",
    "00:A0:6E": "Yokogawa Electric",

    # Phoenix Contact
    "00:A0:45": "Phoenix Contact",
    "EC:E5:13": "Phoenix Contact",

    # Beckhoff
    "00:01:05": "Beckhoff Automation",

    # Wago
    "00:30:DE": "Wago Kontakttechnik",

    # Moxa
    "00:90:E8": "Moxa Technologies",

    # Hirschmann (Belden)
    "00:80:63": "Hirschmann Automation",

    # Cisco
    "00:1A:A1": "Cisco Systems",
    "00:17:94": "Cisco Systems",
    "00:1B:54": "Cisco Systems",

    # HP
    "00:1A:4B": "Hewlett-Packard",
    "3C:D9:2B": "Hewlett-Packard",

    # Virtualization
    "00:0C:29": "VMware (virtual)",
    "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
}


def lookup_oui(mac_address: str) -> str | None:
    """Return vendor name from MAC OUI prefix, if known.

    Args:
        mac_address: MAC as AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF.

    Returns:
        Vendor string or None.
    """
    if not mac_address:
        return None

    # Normalize to colon-separated uppercase
    mac_clean = mac_address.upper().replace("-", ":").replace(".", ":")
    parts = mac_clean.split(":")

    # Expect six octets
    if len(parts) != 6:
        return None

    oui_prefix = ":".join(parts[:3])
    return ICS_OUI_DATABASE.get(oui_prefix)


def is_broadcast_mac(mac_address: str) -> bool:
    """True if all-FF broadcast MAC."""
    if not mac_address:
        return False
    clean = mac_address.upper().replace("-", ":").replace(".", ":")
    return clean == "FF:FF:FF:FF:FF:FF"


def is_multicast_mac(mac_address: str) -> bool:
    """True if I/G bit set (multicast)."""
    if not mac_address:
        return False
    clean = mac_address.upper().replace("-", ":").replace(".", ":")
    try:
        first_octet = int(clean.split(":")[0], 16)
        return bool(first_octet & 0x01)
    except (ValueError, IndexError):
        return False
