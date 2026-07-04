"""
HSIG graph — networkx DiGraph wrapper implementing HSIG = (V, E, P)
"""
import networkx as nx
from typing import Dict, List, Optional, Tuple
from .nodes import HSIGNode, Layer
from .edges import HSIGEdge, EdgeType


class HSIG:
    """
    Hardware-Software Interaction Graph per IBOM paper Definition 5.
    G = (V, E, P) where P = (tau, rho, sigma).
    """

    def __init__(self, component_name: str, component_version: str):
        self.component_name    = component_name
        self.component_version = component_version
        self._graph = nx.DiGraph()
        self._nodes: Dict[str, HSIGNode] = {}
        self._edges: Dict[str, HSIGEdge] = {}

    # ── Node operations ────────────────────────────────────────────────────

    def add_node(self, node: HSIGNode) -> None:
        self._nodes[node.node_id] = node
        self._graph.add_node(
            node.node_id,
            layer=node.layer.value,
            name=node.name,
            base_address=node.base_address,
        )

    def get_node(self, node_id: str) -> Optional[HSIGNode]:
        return self._nodes.get(node_id)

    def nodes_by_layer(self, layer: Layer) -> List[HSIGNode]:
        return [n for n in self._nodes.values() if n.layer == layer]

    # ── Edge operations ────────────────────────────────────────────────────

    def add_edge(self, edge: HSIGEdge) -> None:
        self._edges[edge.edge_id] = edge
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_id=edge.edge_id,
            edge_type=edge.edge_type.value,
        )

    def get_edge(self, edge_id: str) -> Optional[HSIGEdge]:
        return self._edges.get(edge_id)

    def edges_by_type(self, edge_type: EdgeType) -> List[HSIGEdge]:
        return [e for e in self._edges.values() if e.edge_type == edge_type]

    def find_consumers(self, interface_node_id: str) -> List[str]:
        """Return node IDs that CONSUME or DEPEND_ON the given L4 interface."""
        consumers = []
        for edge in self._edges.values():
            if (edge.target_id == interface_node_id and
                    edge.edge_type in (EdgeType.CONSUMES, EdgeType.DEPENDS_ON)):
                consumers.append(edge.source_id)
        return consumers

    # ── Safety-critical path analysis (Definition 6) ──────────────────────

    def safety_critical_paths(self) -> List[List[str]]:
        """
        Return all paths from L1 safety nodes through at least one L4 node.
        Implements Definition 6: path pi is safety-critical if L1 -> ... -> L4.
        """
        l1_nodes = [n.node_id for n in self.nodes_by_layer(Layer.L1_SAFETY)]
        l4_nodes = {n.node_id for n in self.nodes_by_layer(Layer.L4_MMIO)}
        paths = []
        for src in l1_nodes:
            for tgt in l4_nodes:
                try:
                    for path in nx.all_simple_paths(self._graph, src, tgt, cutoff=6):
                        if any(n in l4_nodes for n in path):
                            paths.append(path)
                except nx.NetworkXNoPath:
                    pass
        return paths

    # ── Statistics ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "component":  f"{self.component_name}@{self.component_version}",
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_layer": {
                layer.name: len(self.nodes_by_layer(layer))
                for layer in Layer
            },
            "edges_by_type": {
                et.value: len(self.edges_by_type(et))
                for et in EdgeType
            },
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (f"HSIG({self.component_name}@{self.component_version}: "
                f"{s['total_nodes']} nodes, {s['total_edges']} edges)")
