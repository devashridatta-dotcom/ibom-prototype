"""
HLS synthesis metadata parser → HSIG GENERATED-FROM edges.

In a production implementation this hooks into the AMD Vitis HLS toolchain
at the interface synthesis stage to extract AST-to-register-map bindings.
This module provides:
  1. A mock HLS synthesis report fixture (what Vitis HLS would emit)
  2. The GENERATED-FROM edge generator consuming that report

See IBOM paper Section 6.2: AST-to-RTL binding pseudocode.
"""
import hashlib
from typing import List, Dict
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hsig import (HSIG, HSIGNode, HSIGEdge, Layer, EdgeType,
                  Provenance, TemporalValidity)


# Mock HLS synthesis metadata — what Vitis HLS xo metadata would contain.
# Two builds of signal_processing_v1.2.c with different optimization flags
# demonstrating the HLS Lineage Break (Use Case 2 from the paper).

HLS_REPORTS = [
    {
        "build_id": "SIGPROC-BUILD-001",
        "source_file": "signal_processing_v1.2.c",
        "source_hash": "sha256:a3f9c1d2e8b7f4a1c6d3e9b2f5a8c4d7",
        "function_name": "signal_process_top",
        "hls_tool": "Vitis HLS 2024.2",
        "target_device": "xczu9eg-ffvb1156-2-e",
        "constraints_file": "constraints/signal_proc_default.tcl",
        "constraints_hash": "sha256:b2e8f3a1c7d4e9b2f5a8c4d7e1b6f3a9",
        "optimization_flags": {
            "loop_unroll": 1,
            "pipeline_ii": "disabled",
            "data_width": 32,
        },
        "timestamp": "2026-05-10T14:32:00Z",
        "generated_interfaces": [
            {"name": "THRESHOLD",     "offset": 0x10, "width": 32, "access": "read-write",
             "desc": "Signal processing threshold value"},
            {"name": "GAIN",          "offset": 0x14, "width": 32, "access": "read-write",
             "desc": "Signal gain multiplier"},
            {"name": "CTRL",          "offset": 0x00, "width": 32, "access": "read-write",
             "desc": "Control register (AP_START/AP_DONE/AP_IDLE)"},
            {"name": "STATUS",        "offset": 0x04, "width": 32, "access": "read-only",
             "desc": "Status register"},
            {"name": "OUTPUT_VALID",  "offset": 0x18, "width": 32, "access": "read-only",
             "desc": "Output data valid flag"},
        ],
        "axi_base_address": 0x43C00000,
        "drift_injected": False,
    },
    {
        # Same source, different optimization — pipeline-ii enabled → register offset shift
        "build_id": "SIGPROC-BUILD-002",
        "source_file": "signal_processing_v1.2.c",
        "source_hash": "sha256:a3f9c1d2e8b7f4a1c6d3e9b2f5a8c4d7",  # SAME source hash
        "function_name": "signal_process_top",
        "hls_tool": "Vitis HLS 2024.2",
        "target_device": "xczu9eg-ffvb1156-2-e",
        "constraints_file": "constraints/signal_proc_optimized.tcl",
        "constraints_hash": "sha256:f7c3a2d9e1b8f4a5c6d2e9b3f7a1c4d8",  # DIFFERENT
        "optimization_flags": {
            "loop_unroll": 1,
            "pipeline_ii": 1,      # ← changed — causes register offset shift
            "data_width": 32,
        },
        "timestamp": "2026-05-20T09:15:00Z",
        "generated_interfaces": [
            {"name": "THRESHOLD",     "offset": 0x18, "width": 32, "access": "read-write",
             "desc": "Signal processing threshold value"},  # SHIFTED from 0x10 to 0x18
            {"name": "GAIN",          "offset": 0x1C, "width": 32, "access": "read-write",
             "desc": "Signal gain multiplier"},             # SHIFTED
            {"name": "CTRL",          "offset": 0x00, "width": 32, "access": "read-write",
             "desc": "Control register (AP_START/AP_DONE/AP_IDLE)"},
            {"name": "STATUS",        "offset": 0x04, "width": 32, "access": "read-only",
             "desc": "Status register"},
            {"name": "PIPELINE_LAT",  "offset": 0x08, "width": 32, "access": "read-only",
             "desc": "Pipeline latency measurement (NEW — added by pipelining)"},
            {"name": "OUTPUT_VALID",  "offset": 0x20, "width": 32, "access": "read-only",
             "desc": "Output data valid flag"},             # SHIFTED
        ],
        "axi_base_address": 0x43C00000,
        "drift_injected": True,  # flag for demo
    }
]


def _source_node_id(source_file: str, function_name: str) -> str:
    return f"L5-SRC-{function_name}"


def _rtl_node_id(build_id: str, reg_name: str) -> str:
    return f"L5-RTL-{build_id}"


def parse_hls_report(hsig: HSIG, report: dict, build_label: str = "") -> dict:
    """
    Process one HLS synthesis report and emit GENERATED-FROM edges into the HSIG.

    For each HLS build:
    1. Create an L5 source node (software function)
    2. Create L4 interface nodes for each generated AXI register
    3. Emit GENERATED-FROM edge: source → L4 register nodes
    """
    build_id    = report["build_id"]
    source_file = report["source_file"]
    source_hash = report["source_hash"]
    func_name   = report["function_name"]
    base_addr   = report["axi_base_address"]

    # L5 source function node
    src_node_id = _source_node_id(source_file, func_name)
    if not hsig.get_node(src_node_id):
        src_node = HSIGNode(
            node_id=src_node_id,
            name=func_name,
            layer=Layer.L5_RTL,
            description=f"HLS source function: {source_file}::{func_name}",
            source_hash=source_hash,
            rtl_type='hls-source',
        )
        hsig.add_node(src_node)

    stats = {
        'build_id': build_id,
        'source_file': source_file,
        'source_hash_unchanged': True,
        'generated_interfaces': 0,
        'generated_from_edges': 0,
        'pipeline_ii': report['optimization_flags'].get('pipeline_ii'),
        'constraints_hash': report['constraints_hash'],
    }

    for iface in report["generated_interfaces"]:
        reg_addr    = base_addr + iface["offset"]
        iface_id    = f"IF-HLS-{build_id}-{iface['name']}"

        l4_node = HSIGNode(
            node_id=iface_id,
            name=f"HLS.{func_name}.{iface['name']}",
            layer=Layer.L4_MMIO,
            description=iface["desc"],
            base_address=reg_addr,
            size_bytes=iface["width"] // 8,
            peripheral=f"HLS-{func_name}",
            temporal=TemporalValidity(
                valid_from=build_id,
                validity_condition=f"active_build == '{build_id}'",
                last_verified=report["timestamp"],
            ),
        )
        hsig.add_node(l4_node)
        stats['generated_interfaces'] += 1

        # GENERATED-FROM edge: L5 source → L4 AXI register
        edge_id = f"GENF-{build_id}-{iface['name']}"
        gen_edge = HSIGEdge(
            edge_id=edge_id,
            edge_type=EdgeType.GENERATED_FROM,
            source_id=src_node_id,
            target_id=iface_id,
            provenance=Provenance(
                source_artifact_type='source-file',
                source_artifact_ref=source_file,
                source_hash=source_hash,
                synthesis_chain={
                    "hls_tool":         report["hls_tool"],
                    "target_device":    report["target_device"],
                    "constraints_file": report["constraints_file"],
                    "constraints_hash": report["constraints_hash"],
                    "optimization_flags": report["optimization_flags"],
                    "timestamp":        report["timestamp"],
                    "register_offset":  hex(iface["offset"]),
                },
            ),
            valid_from=build_id,
            last_verified=report["timestamp"],
        )
        hsig.add_edge(gen_edge)
        stats['generated_from_edges'] += 1

    return stats


def parse_all_hls_reports(hsig: HSIG) -> list:
    """Parse all fixture HLS reports and return per-build statistics."""
    results = []
    for i, report in enumerate(HLS_REPORTS):
        stats = parse_hls_report(hsig, report, build_label=f"build-{i+1}")
        results.append(stats)
    return results
