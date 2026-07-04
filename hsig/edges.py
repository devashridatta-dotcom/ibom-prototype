"""
HSIG typed edge dataclasses — six relationship types per IBOM paper Section 4.3
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class EdgeType(Enum):
    IMPLEMENTS      = "IMPLEMENTS"       # L5 → L4
    EXPOSES         = "EXPOSES"          # L4 → L2/L3
    CONSUMES        = "CONSUMES"         # L2/L3 → L4 (mechanically extracted)
    GENERATED_FROM  = "GENERATED-FROM"  # L5 → L5 (HLS synthesis lineage)
    DEPENDS_ON      = "DEPENDS-ON"       # L1/L2/L3 → L4 (validated)
    TRUST_BOUNDARY  = "TRUST-BOUNDARY"  # L* → L* (security domain crossing)
    VALIDATES       = "VALIDATES"        # external → E
    RECONFIGURES    = "RECONFIGURES"     # update → L4/L5


@dataclass
class Provenance:
    source_artifact_type: str           # SBOM, HBOM, source-file, conformity-assessment
    source_artifact_ref:  str
    source_purl:          Optional[str] = None
    source_hash:          Optional[str] = None
    validation_evidence:  List[dict]    = field(default_factory=list)
    # HLS synthesis chain — populated for GENERATED-FROM edges
    synthesis_chain:      Optional[dict] = None


@dataclass
class AccessPattern:
    sequence:          List[str]     = field(default_factory=list)
    timing_constraint: Optional[str] = None
    access_type:       str           = "read-write"


@dataclass
class TrustBoundaryMeta:
    source_domain:       str
    target_domain:       str
    source_privilege:    str
    target_privilege:    str
    attestation_required: bool = True
    crossing_controls:   List[str] = field(default_factory=list)


@dataclass
class HSIGEdge:
    edge_id:       str
    edge_type:     EdgeType
    source_id:     str
    target_id:     str
    provenance:    Optional[Provenance]       = None
    access_pattern: Optional[AccessPattern]  = None
    trust_boundary: Optional[TrustBoundaryMeta] = None
    # Temporal validity on the edge
    valid_from:    Optional[str] = None
    valid_until:   Optional[str] = None
    validity_condition: Optional[str] = None
    last_verified: Optional[str] = None
