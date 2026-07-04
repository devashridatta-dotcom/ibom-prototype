# IBOM Prototype — Reference Implementation

Interface Bill of Materials (IBOM) framework prototype.
Companion to: "Interface Bill of Materials (IBOM): A Framework for Hardware-Software
Interface Lifecycle Assurance in Cyber-Physical Supply Chains" — SCORED '26.

## What this demonstrates

- **RQ1**: Machine-readable hardware-software interface representation spanning L1–L5
- **RQ2**: Automated drift detection across 6 controlled scenarios (6/6 = 100%)
- **RQ3**: Full pipeline in <15ms; 88.9% precision/recall on MMIO edge extraction

## Structure

```
ibom-prototype/
├── hsig/           # HSIG = (V, E, P) formal model — nodes, edges, graph
├── parsers/        # SVD parser, firmware analyzer (LLVM pass sim), HLS parser
├── drift/          # classify_drift() algorithm + 6 injection scenarios
├── serializers/    # IBOM JSON serializer (paper Section 7.2 schema)
├── eval/
│   ├── fixtures/   # STM32F407-style CMSIS-SVD fixture
│   └── stm32f4_demo.py  # Full end-to-end demo
└── output/         # Generated IBOM JSON + drift report
```

## Usage

```bash
cd ibom-prototype
python3 eval/stm32f4_demo.py
```

Requires: Python 3.11+, networkx (`pip install networkx`)

## Key results (BrakeControlECU model)

| Metric                     | Value         |
|----------------------------|---------------|
| L4 interface nodes         | 35            |
| Total HSIG edges           | 66            |
| CONSUMES precision         | 88.9%         |
| CONSUMES recall            | 88.9%         |
| Drift detection rate       | 6/6 (100%)    |
| SBOM-only detection rate   | 0/6 (0%)      |
| Total pipeline time        | <15ms         |

## Drift scenarios detected

1. MMIO address shift → brake registers enter CAN external-accessible range (CWE-1189)
2. HLS optimization trap → pipeline-ii=1 shifts THRESHOLD register 0x10→0x18
3. Timer peripheral retired with active firmware consumers
4. Unvalidated DMA channel added without conformity assessment
5. ABS IRQ_STATUS access mode changed read-write → write-only
6. CAN gateway trust boundary weakened — ACCESS_LIMIT shifted

All 6 detected by IBOM. All 6 missed by SBOM-only analysis.

## IBOM schema

See `output/ibom_brakecontrol_baseline.json` for a complete generated IBOM document
conforming to the paper's Section 7.2 schema with BOM-triad PURL cross-referencing.

## Standardization

CycloneDX Issue #959: https://github.com/CycloneDX/specification/issues/959
ENISA CRA consultation: June 2026
