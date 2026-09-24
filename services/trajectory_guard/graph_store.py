"""NetworkX graph backend for executed-event data lineage."""
from __future__ import annotations
import networkx as nx


class LineageGraph:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def ingest(self, event: dict) -> None:
        if event.get('state') not in {'completed', 'COMPLETED'}:
            return
        output = event.get('result_ref') or event.get('output_ref')
        if not output:
            return
        labels = set(event.get('taint_labels', []))
        refs = event.get('provenance_refs', [])
        self.graph.add_node(output, labels=labels)
        for ref in refs:
            self.graph.add_node(ref, labels=self.graph.nodes.get(ref, {}).get('labels', set()))
            self.graph.add_edge(ref, output, kind='DERIVED_FROM')

    def ancestry(self, ref: str) -> set[str]:
        return nx.ancestors(self.graph, ref) if ref in self.graph else set()

    def labels(self, ref: str) -> set[str]:
        if ref not in self.graph:
            return set()
        return set().union(*(self.graph.nodes[n].get('labels', set()) for n in self.ancestry(ref) | {ref}))
