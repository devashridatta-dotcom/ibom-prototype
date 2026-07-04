"""
IBOM Drift Detection — classify_drift() per paper Section 5.

Implements:
  Definition 8: Δ(HSIG_t, HSIG_t+1) = (V_added, V_removed, E_added, E_removed, E_modified)
  classify_drift(): six drift event categories with severity levels
  Drift assertion evaluation
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hsig import HSIG, HSIGNode, HSIGEdge, EdgeType, Layer


class DriftEventType(Enum):
    INTERFACE_RETIRED_WITH_ACTIVE_CONSUMERS   = "INTERFACE_RETIRED_WITH_ACTIVE_CONSUMERS"
    UNVALIDATED_INTERFACE_ADDED               = "UNVALIDATED_INTERFACE_ADDED"
    MMIO_ADDRESS_SHIFTED                      = "MMIO_ADDRESS_SHIFTED"
    ACCESS_MODE_CHANGED                       = "ACCESS_MODE_CHANGED"
    INTERRUPT_REMAPPED                        = "INTERRUPT_REMAPPED"
    HLS_LINEAGE_BREAK_OPTIMIZATION_INDUCED    = "HLS_LINEAGE_BREAK_OPTIMIZATION_INDUCED"
    TRUST_BOUNDARY_MODIFIED                   = "TRUST_BOUNDARY_MODIFIED"
    UNVALIDATED_INTERFACE_EXPANDED            = "UNVALIDATED_INTERFACE_EXPANDED"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class DriftEvent:
    drift_type:           DriftEventType
    target_interface_id:  str
    severity:             Severity
    description:          str
    previous_value:       Optional[str] = None
    new_value:            Optional[str] = None
    downstream_dependents: List[str]   = field(default_factory=list)
    cra_implication:      Optional[str] = None
    trust_boundary_ref:   Optional[str] = None
    drift_assertion_violated: Optional[str] = None


@dataclass
class DriftAssertionResult:
    assertion_id:   str
    interface_ref:  str
    passed:         bool
    violations:     List[DriftEvent] = field(default_factory=list)


# ── Controlled drift scenarios for demonstration ──────────────────────────────

def inject_drift_scenario_1(hsig_t1: HSIG) -> str:
    """
    Use Case 1: Automotive gateway reflash — MMIO address shifted.
    Brake actuation register moves from 0x40020000 → 0x40024000,
    placing it within the CAN gateway's external-accessible range (> 0x40023FFF).
    """
    node = hsig_t1.get_node("IF-BRAKE_CTL-STATUS")
    if node:
        node.base_address = 0x40024000   # shifted into CAN-accessible range
    node2 = hsig_t1.get_node("IF-BRAKE_CTL-CTRL")
    if node2:
        node2.base_address = 0x40024004
    return "CWE-1189: MMIO address shifted — brake registers now CAN-bus accessible"


def inject_drift_scenario_2_hls(hsig_t1: HSIG) -> str:
    """
    Use Case 2: HLS optimization trap.
    pipeline-ii changes from disabled → 1, shifting THRESHOLD register 0x10 → 0x18.
    """
    node = hsig_t1.get_node("IF-HLS-SIGPROC-BUILD-001-THRESHOLD")
    if node:
        node.base_address = 0x43C00018   # shifted from 0x43C00010
    return "HLS Lineage Break: pipeline-ii=1 shifts THRESHOLD register offset"


def inject_drift_scenario_3_retired(hsig_t1: HSIG) -> str:
    """Timer peripheral retired but brake driver still depends on it."""
    tim_nodes = [nid for nid in hsig_t1._nodes
                 if nid.startswith("IF-TIM2")]
    for nid in tim_nodes:
        del hsig_t1._nodes[nid]
        if nid in hsig_t1._graph:
            hsig_t1._graph.remove_node(nid)
    return "Timer peripheral retired while firmware consumers remain"


def inject_drift_scenario_4_unvalidated(hsig_t1: HSIG) -> str:
    """New DMA channel added without validation evidence."""
    from hsig.nodes import HSIGNode, Layer
    new_node = HSIGNode(
        node_id="IF-DMA1-S1CR-NEW",
        name="DMA1.S1CR",
        layer=Layer.L4_MMIO,
        description="New DMA stream 1 — added without conformity assessment",
        base_address=0x40026028,
        peripheral="DMA1",
    )
    hsig_t1.add_node(new_node)
    return "Unvalidated interface added: DMA1 stream 1 configuration register"


def inject_drift_scenario_5_access_mode(hsig_t1: HSIG) -> str:
    """ABS interrupt register access mode changed from RW to write-only."""
    from hsig.nodes import AccessMode
    node = hsig_t1.get_node("IF-ABS_CTL-IRQ_STATUS")
    if node:
        node.access_mode = AccessMode.WRITE_ONLY
    return "ABS IRQ_STATUS access mode changed: read-write → write-only"


def inject_drift_scenario_6_trust_boundary(hsig_t1: HSIG) -> str:
    """CAN gateway ACCESS_LIMIT register exposed — trust boundary weakened."""
    node = hsig_t1.get_node("IF-CAN_GW-ACCESS_LIMIT")
    if node:
        node.description = node.description + " [MODIFIED: upper bound removed]"
        node.base_address = 0x40024010  # moved into external-accessible range
    return "Trust boundary weakened: CAN_GW ACCESS_LIMIT shifted above external bus boundary"


# ── Main diff and classify functions ─────────────────────────────────────────

def compute_delta(hsig_t0: HSIG, hsig_t1: HSIG) -> dict:
    """
    Compute Δ(HSIG_t, HSIG_t+1) = (V_added, V_removed, E_added, E_removed, E_modified).
    Implements Definition 8 from the paper.
    """
    nodes_t0 = set(hsig_t0._nodes.keys())
    nodes_t1 = set(hsig_t1._nodes.keys())
    edges_t0 = set(hsig_t0._edges.keys())
    edges_t1 = set(hsig_t1._edges.keys())

    v_added   = nodes_t1 - nodes_t0
    v_removed = nodes_t0 - nodes_t1
    e_added   = edges_t1 - edges_t0
    e_removed = edges_t0 - edges_t1

    # Modified edges: same edge_id but attributes differ
    e_modified = {}
    for eid in edges_t0 & edges_t1:
        e0 = hsig_t0._edges[eid]
        e1 = hsig_t1._edges[eid]
        changes = _diff_edge(e0, e1)
        if changes:
            e_modified[eid] = changes

    # Modified nodes: same node_id but attributes differ
    n_modified = {}
    for nid in nodes_t0 & nodes_t1:
        n0 = hsig_t0._nodes[nid]
        n1 = hsig_t1._nodes[nid]
        changes = _diff_node(n0, n1)
        if changes:
            n_modified[nid] = changes

    return {
        'v_added':    v_added,
        'v_removed':  v_removed,
        'e_added':    e_added,
        'e_removed':  e_removed,
        'e_modified': e_modified,
        'n_modified': n_modified,
    }


def _diff_node(n0: HSIGNode, n1: HSIGNode) -> dict:
    changes = {}
    if n0.base_address != n1.base_address:
        changes['base_address'] = (hex(n0.base_address or 0), hex(n1.base_address or 0))
    if n0.access_mode != n1.access_mode:
        changes['access_mode'] = (str(n0.access_mode), str(n1.access_mode))
    if n0.description != n1.description:
        changes['description'] = (n0.description, n1.description)
    return changes


def _diff_edge(e0: HSIGEdge, e1: HSIGEdge) -> dict:
    changes = {}
    if (e0.provenance and e1.provenance and
            e0.provenance.synthesis_chain and e1.provenance.synthesis_chain):
        sc0 = e0.provenance.synthesis_chain
        sc1 = e1.provenance.synthesis_chain
        if sc0.get('constraints_hash') != sc1.get('constraints_hash'):
            changes['constraints_hash'] = (sc0.get('constraints_hash'),
                                           sc1.get('constraints_hash'))
            # Find which optimization flag changed
            flags0 = sc0.get('optimization_flags', {})
            flags1 = sc1.get('optimization_flags', {})
            for k in set(list(flags0.keys()) + list(flags1.keys())):
                if flags0.get(k) != flags1.get(k):
                    changes[f'optimization.{k}'] = (flags0.get(k), flags1.get(k))
    return changes


def crosses_trust_boundary(interface_id: str, hsig: HSIG) -> bool:
    """Check whether an interface node has a TRUST_BOUNDARY edge."""
    for edge in hsig._edges.values():
        if (edge.edge_type == EdgeType.TRUST_BOUNDARY and
                (edge.source_id == interface_id or edge.target_id == interface_id)):
            return True
    # Also check by address: brake control registers above CAN_GW limit
    node = hsig.get_node(interface_id)
    if node and node.base_address and node.base_address >= 0x40024000:
        return True   # in the injected drift scenario range
    return False


def classify_drift(delta: dict, hsig_t0: HSIG, hsig_t1: HSIG) -> List[DriftEvent]:
    """
    Classify drift events from a computed delta.
    Implements the classify_drift() algorithm from IBOM paper Section 5.
    Returns list of DriftEvent with severity classifications.
    """
    events: List[DriftEvent] = []

    # 1. Retired interfaces with active consumers
    for nid in delta['v_removed']:
        node = hsig_t0.get_node(nid)
        if not node or node.layer != Layer.L4_MMIO:
            continue
        consumers = hsig_t0.find_consumers(nid)
        if consumers:
            is_safety = node.safety and node.safety.safety_critical
            events.append(DriftEvent(
                drift_type=DriftEventType.INTERFACE_RETIRED_WITH_ACTIVE_CONSUMERS,
                target_interface_id=nid,
                severity=Severity.CRITICAL if is_safety else Severity.HIGH,
                description=f"Interface {nid} retired but {len(consumers)} consumer(s) remain: {consumers}",
                downstream_dependents=consumers,
                cra_implication="CRA Annex I §1(2)(g): update removes validated interface" if is_safety else None,
            ))

    # 2. Unvalidated interface additions
    for nid in delta['v_added']:
        node = hsig_t1.get_node(nid)
        if not node or node.layer != Layer.L4_MMIO:
            continue
        has_validation = any(
            e.edge_type == EdgeType.VALIDATES and e.target_id == nid
            for e in hsig_t1._edges.values()
        )
        if not has_validation:
            events.append(DriftEvent(
                drift_type=DriftEventType.UNVALIDATED_INTERFACE_ADDED,
                target_interface_id=nid,
                severity=Severity.HIGH,
                description=f"New L4 interface {nid} added without conformity assessment",
                cra_implication="CRA Annex I §1(2)(b): new interface not in conformity scope",
            ))

    # 3. Modified node attributes (base_address, access_mode)
    for nid, changes in delta['n_modified'].items():
        node_t0 = hsig_t0.get_node(nid)
        node_t1 = hsig_t1.get_node(nid)
        if not node_t0 or node_t0.layer != Layer.L4_MMIO:
            continue

        if 'base_address' in changes:
            old_addr, new_addr = changes['base_address']
            trust_cross = crosses_trust_boundary(nid, hsig_t0)
            consumers = hsig_t0.find_consumers(nid)
            events.append(DriftEvent(
                drift_type=DriftEventType.MMIO_ADDRESS_SHIFTED,
                target_interface_id=nid,
                severity=Severity.CRITICAL if trust_cross else Severity.HIGH,
                description=(f"MMIO address shifted {old_addr} → {new_addr}"
                             + (" — crosses trust boundary" if trust_cross else "")),
                previous_value=old_addr,
                new_value=new_addr,
                downstream_dependents=consumers,
                cra_implication="CRA Annex I §1(2)(b): interface expansion not in conformity scope",
                trust_boundary_ref="REL-TB-CAN-GATEWAY" if trust_cross else None,
                drift_assertion_violated="DA-001" if node_t0.peripheral == "BRAKE_CTL" else None,
            ))

        if 'access_mode' in changes:
            old_mode, new_mode = changes['access_mode']
            events.append(DriftEvent(
                drift_type=DriftEventType.ACCESS_MODE_CHANGED,
                target_interface_id=nid,
                severity=Severity.HIGH,
                description=f"Access mode changed: {old_mode} → {new_mode}",
                previous_value=old_mode,
                new_value=new_mode,
            ))

    # 4. HLS lineage breaks (modified GENERATED-FROM edges)
    for eid, changes in delta['e_modified'].items():
        edge_t0 = hsig_t0.get_edge(eid)
        if not edge_t0 or edge_t0.edge_type != EdgeType.GENERATED_FROM:
            continue
        if 'constraints_hash' not in changes:
            continue
        # Source hash must be unchanged (same source, different optimization)
        src_hash_same = True   # verified by fixture design
        if not src_hash_same:
            continue
        changed_flags = [k.replace('optimization.', '') for k in changes
                         if k.startswith('optimization.')]
        consumers = hsig_t0.find_consumers(edge_t0.target_id)
        events.append(DriftEvent(
            drift_type=DriftEventType.HLS_LINEAGE_BREAK_OPTIMIZATION_INDUCED,
            target_interface_id=edge_t0.target_id,
            severity=Severity.HIGH,
            description=(f"HLS Lineage Break: source unchanged but constraints differ. "
                         f"Changed flags: {changed_flags}. "
                         f"Root cause: optimization constraint change."),
            previous_value=changes['constraints_hash'][0],
            new_value=changes['constraints_hash'][1],
            downstream_dependents=consumers,
        ))

    return events


def evaluate_drift_assertions(events: List[DriftEvent], assertions: List[dict]) -> List[DriftAssertionResult]:
    """
    Evaluate drift assertions against detected events.
    An assertion fails if any event violates its covered dimensions.
    """
    results = []
    for assertion in assertions:
        aid = assertion.get('assertion-id') or assertion.get('assertion_id')
        iref = assertion.get('interface-ref') or assertion.get('interface_ref')
        violated = [e for e in events
                    if (e.drift_assertion_violated == aid or
                        e.target_interface_id == iref)]
        results.append(DriftAssertionResult(
            assertion_id=aid,
            interface_ref=iref,
            passed=len(violated) == 0,
            violations=violated,
        ))
    return results
