"""
HSIG node dataclasses — five-layer model per IBOM paper Section 4.2
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Layer(Enum):
    L1_SAFETY   = 1   # Safety-critical functions
    L2_DRIVER   = 2   # OS / device drivers
    L3_FIRMWARE = 3   # Firmware binaries
    L4_MMIO     = 4   # Memory-mapped interfaces (primary layer)
    L5_RTL      = 5   # RTL / hardware modules


class AccessMode(Enum):
    READ_ONLY  = "read-only"
    WRITE_ONLY = "write-only"
    READ_WRITE = "read-write"


@dataclass
class TemporalValidity:
    valid_from:          str
    valid_until:         Optional[str] = None
    validity_condition:  Optional[str] = None
    last_verified:       Optional[str] = None


@dataclass
class SafetyMeta:
    safety_critical:  bool  = False
    safety_standard:  str   = ""
    integrity_level:  str   = ""           # ASIL-D, SIL-3, DAL-A, etc.
    failure_mode:     str   = ""


@dataclass
class HSIGNode:
    node_id:      str
    name:         str
    layer:        Layer
    description:  str           = ""
    safety:       Optional[SafetyMeta]       = None
    temporal:     Optional[TemporalValidity] = None
    # Layer-4 specific
    base_address: Optional[int] = None
    size_bytes:   int           = 4
    access_mode:  Optional[AccessMode] = None
    peripheral:   str           = ""
    # Layer-5 specific
    source_hash:  Optional[str] = None
    rtl_type:     str           = ""       # verilog, vhdl, hls-generated
