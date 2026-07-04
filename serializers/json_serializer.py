"""
IBOM JSON serializer — HSIG → IBOM document per paper Section 7.2 schema.
"""
import json
import hashlib
from datetime import datetime
from typing import Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hsig import HSIG, Layer, EdgeType
from drift.detector import DriftEvent


def _node_to_dict(node) -> Optional[dict]:
    if node.layer != Layer.L4_MMIO:
        return None
    d = {
        "interface-id":  node.node_id,
        "name":          node.name,
        "type":          "mmio-region",
        "base-address":  hex(node.base_address) if node.base_address is not None else None,
        "size-bytes":    node.size_bytes,
        "layer":         node.layer.value,
        "peripheral":    node.peripheral,
    }
    if node.access_mode:
        d["access-mode"] = node.access_mode.value
    if node.temporal:
        d["temporal-validity"] = {
            "valid-from":          node.temporal.valid_from,
            "valid-until":         node.temporal.valid_until,
            "validity-condition":  node.temporal.validity_condition,
            "last-verified":       node.temporal.last_verified,
        }
    if node.safety:
        d["safety-relevance"] = {
            "safety-critical":  node.safety.safety_critical,
            "safety-standard":  node.safety.safety_standard,
            "integrity-level":  node.safety.integrity_level,
            "failure-mode":     node.safety.failure_mode,
        }
    return d


def _edge_to_dict(edge) -> dict:
    d = {
        "relationship-id": edge.edge_id,
        "type":            edge.edge_type.value,
        "source-id":       edge.source_id,
        "target-id":       edge.target_id,
    }
    if edge.valid_from:
        d["temporal-validity"] = {
            "valid-from":          edge.valid_from,
            "valid-until":         edge.valid_until,
            "validity-condition":  edge.validity_condition,
            "last-verified":       edge.last_verified,
        }
    if edge.provenance:
        prov = {
            "source-artifact-type": edge.provenance.source_artifact_type,
            "source-artifact-ref":  edge.provenance.source_artifact_ref,
        }
        if edge.provenance.source_purl:
            prov["source-purl"] = edge.provenance.source_purl
        if edge.provenance.source_hash:
            prov["source-hash"] = edge.provenance.source_hash
        if edge.provenance.validation_evidence:
            prov["validation-evidence"] = edge.provenance.validation_evidence
        if edge.provenance.synthesis_chain:
            prov["synthesis-chain"] = edge.provenance.synthesis_chain
        d["provenance"] = prov
    if edge.access_pattern:
        ap = {"access-type": edge.access_pattern.access_type}
        if edge.access_pattern.sequence:
            ap["sequence"] = edge.access_pattern.sequence
        if edge.access_pattern.timing_constraint:
            ap["timing-constraint"] = edge.access_pattern.timing_constraint
        d["access-pattern"] = ap
    if edge.trust_boundary:
        d["trust-boundary"] = {
            "source-domain":       edge.trust_boundary.source_domain,
            "target-domain":       edge.trust_boundary.target_domain,
            "source-privilege":    edge.trust_boundary.source_privilege,
            "target-privilege":    edge.trust_boundary.target_privilege,
            "attestation-required": edge.trust_boundary.attestation_required,
            "crossing-controls":   edge.trust_boundary.crossing_controls,
        }
    return d


def serialize_ibom(hsig: HSIG,
                   sbom_ref: str = "sbom-brakecontrol-3.1.2.cdx.json",
                   hbom_ref: str = "hbom-brakecontrol-hw-rev2.json",
                   drift_assertions: Optional[list] = None) -> dict:
    """Serialize HSIG to IBOM JSON document per paper schema."""
    interfaces = []
    for node in hsig._nodes.values():
        nd = _node_to_dict(node)
        if nd:
            interfaces.append(nd)

    relationships = [_edge_to_dict(e) for e in hsig._edges.values()]

    doc = {
        "ibomVersion": "0.1",
        "metadata": {
            "timestamp":  datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generator":  "ibom-prototype v0.1",
            "component": {
                "name":    hsig.component_name,
                "version": hsig.component_version,
                "purl":    f"pkg:generic/{hsig.component_name.lower().replace(' ','-')}@{hsig.component_version}",
            },
            "linked-artifacts": {
                "sbom": {
                    "format": "CycloneDX",
                    "version": "1.7",
                    "ref":  sbom_ref,
                    "hash": f"sha256:{hashlib.sha256(sbom_ref.encode()).hexdigest()[:16]}...",
                },
                "hbom": {
                    "format": "CISA-HBOM",
                    "ref":  hbom_ref,
                    "hash": f"sha256:{hashlib.sha256(hbom_ref.encode()).hexdigest()[:16]}...",
                },
            },
        },
        "interfaces":    interfaces,
        "relationships": relationships,
        "drift-assertions": drift_assertions or [],
        "statistics": hsig.stats(),
    }
    return doc


def save_ibom(doc: dict, path: str) -> None:
    with open(path, 'w') as f:
        json.dump(doc, f, indent=2)
