"""
CMSIS-SVD parser → HSIG Layer 4 (MMIO) nodes + Layer 5 IMPLEMENTS edges.

Implements the extraction pipeline described in IBOM paper Section 6.1:
  SVD/IP-XACT file → Parser → HSIG Builder (node creation, edge typing)

Supports CMSIS-SVD schema v1.1. Pure stdlib — no external dependencies.
"""
import xml.etree.ElementTree as ET
import hashlib
import re
from pathlib import Path
from typing import List, Tuple, Optional
import sys, os
sys.path.insert(0, str(Path(__file__).parent.parent))

from hsig import (HSIG, HSIGNode, HSIGEdge, Layer, AccessMode,
                  EdgeType, Provenance, SafetyMeta, TemporalValidity)

# Safety classification heuristics based on peripheral name patterns
SAFETY_PATTERNS = {
    r'BRAKE|BRAKING':   ('ISO-26262', 'ASIL-D', 'Loss of braking actuation'),
    r'ABS':             ('ISO-26262', 'ASIL-B', 'Loss of anti-lock braking'),
    r'SAFETY|SAFE_MON': ('ISO-26262', 'ASIL-D', 'Loss of safety monitoring'),
    r'AIRBAG':          ('ISO-26262', 'ASIL-D', 'Loss of airbag deployment'),
    r'STEER':           ('ISO-26262', 'ASIL-C', 'Loss of steering control'),
}

ACCESS_MAP = {
    'read-only':  AccessMode.READ_ONLY,
    'write-only': AccessMode.WRITE_ONLY,
    'read-write': AccessMode.READ_WRITE,
}


def _classify_safety(peripheral_name: str) -> Optional[SafetyMeta]:
    name_upper = peripheral_name.upper()
    for pattern, (std, level, failure) in SAFETY_PATTERNS.items():
        if re.search(pattern, name_upper):
            return SafetyMeta(
                safety_critical=True,
                safety_standard=std,
                integrity_level=level,
                failure_mode=failure,
            )
    return None


def _svd_hash(svd_path: str) -> str:
    with open(svd_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def parse_svd(svd_path: str, hsig: HSIG,
              hw_revision: str = "hw-rev-1.0",
              verified_date: str = "2026-05-15") -> dict:
    """
    Parse a CMSIS-SVD file and populate the HSIG with:
      - L4 nodes: one per register (interface-level granularity)
      - L5 nodes: one per peripheral (hardware module)
      - IMPLEMENTS edges: L5 peripheral → L4 register nodes

    Returns extraction statistics.
    """
    tree = ET.parse(svd_path)
    root = tree.getroot()
    svd_hash = _svd_hash(svd_path)

    device_name = (root.findtext('name') or 'UnknownDevice').strip()
    peripherals = root.find('peripherals')

    stats = {
        'device': device_name,
        'peripherals': 0,
        'registers': 0,
        'l4_nodes': 0,
        'l5_nodes': 0,
        'implements_edges': 0,
        'safety_critical_interfaces': 0,
    }

    if peripherals is None:
        return stats

    for periph in peripherals.findall('peripheral'):
        p_name    = (periph.findtext('name') or '').strip()
        p_desc    = (periph.findtext('description') or '').strip()
        p_base    = periph.findtext('baseAddress') or '0x0'
        base_addr = int(p_base, 16)

        # Create L5 node for the peripheral (hardware module)
        l5_id = f"L5-{p_name}"
        safety = _classify_safety(p_name)
        l5_node = HSIGNode(
            node_id=l5_id,
            name=p_name,
            layer=Layer.L5_RTL,
            description=p_desc,
            safety=safety,
            base_address=base_addr,
            peripheral=p_name,
            rtl_type='hardware-module',
        )
        hsig.add_node(l5_node)
        stats['l5_nodes'] += 1
        stats['peripherals'] += 1

        # Parse registers → L4 nodes
        registers_el = periph.find('registers')
        if registers_el is None:
            continue

        for reg in registers_el.findall('register'):
            r_name   = (reg.findtext('name') or '').strip()
            r_desc   = (reg.findtext('description') or '').strip()
            r_offset = int(reg.findtext('addressOffset') or '0x0', 16)
            r_access = (reg.findtext('access') or 'read-write').strip()
            reg_addr  = base_addr + r_offset

            interface_id = f"IF-{p_name}-{r_name}"
            reg_safety   = _classify_safety(p_name)  # inherit peripheral safety

            l4_node = HSIGNode(
                node_id=interface_id,
                name=f"{p_name}.{r_name}",
                layer=Layer.L4_MMIO,
                description=r_desc,
                safety=reg_safety,
                base_address=reg_addr,
                size_bytes=4,
                access_mode=ACCESS_MAP.get(r_access, AccessMode.READ_WRITE),
                peripheral=p_name,
                temporal=TemporalValidity(
                    valid_from=hw_revision,
                    last_verified=verified_date,
                ),
            )
            hsig.add_node(l4_node)
            stats['l4_nodes'] += 1
            stats['registers'] += 1
            if reg_safety and reg_safety.safety_critical:
                stats['safety_critical_interfaces'] += 1

            # IMPLEMENTS edge: L5 peripheral → L4 register
            edge_id = f"IMPL-{p_name}-{r_name}"
            impl_edge = HSIGEdge(
                edge_id=edge_id,
                edge_type=EdgeType.IMPLEMENTS,
                source_id=l5_id,
                target_id=interface_id,
                provenance=Provenance(
                    source_artifact_type='CMSIS-SVD',
                    source_artifact_ref=svd_path,
                    source_hash=svd_hash,
                ),
                valid_from=hw_revision,
                last_verified=verified_date,
            )
            hsig.add_edge(impl_edge)
            stats['implements_edges'] += 1

    return stats
