"""
attack_graph.py — Build per-session attack chain graphs using NetworkX.

A directed graph where:
  - Nodes are MITRE technique IDs (e.g. T1082, T1083)
  - Edges represent observed transitions between techniques
  - Edge weight = frequency of that transition
  - Node attributes: technique_name, tactic, count (times observed)

Published as JSON (NetworkX node_link_data) in MitreSession.attack_graph.
Used by Week 10 Grafana dashboard for attack timeline visualisation.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict

import networkx as nx
from networkx.readwrite import json_graph

from models import TechniqueMatch

log = logging.getLogger(__name__)


def _node_link_data_compat(graph):
    """
    Return NetworkX node-link JSON in a stable shape across NetworkX versions.

    Supported variants seen in NetworkX:
    - newer: node_link_data(G, nodes="nodes", edges="links")
    - older: node_link_data(G, link="links")
    - fallback: node_link_data(G)

    The returned shape is normalised to contain "nodes" and "links".
    """
    from networkx.readwrite import json_graph

    data = None
    last_error = None

    for kwargs in (
        {"nodes": "nodes", "edges": "links"},
        {"link": "links"},
        {},
    ):
        try:
            data = json_graph.node_link_data(graph, **kwargs)
            break
        except TypeError as e:
            last_error = e
            continue
        except Exception as e:
            last_error = e
            break

    if data is None:
        try:
            log.warning("node_link_data compatibility failed: %s", last_error)
        except Exception:
            pass
        return {
            "directed": graph.is_directed(),
            "multigraph": graph.is_multigraph(),
            "graph": {},
            "nodes": [],
            "links": [],
        }

    if "edges" in data and "links" not in data:
        data["links"] = data.pop("edges")

    data.setdefault("nodes", [])
    data.setdefault("links", [])
    data.setdefault("graph", {})
    data.setdefault("directed", graph.is_directed())
    data.setdefault("multigraph", graph.is_multigraph())

    return data


class AttackGraphBuilder:
    """
    Maintains a per-session directed graph of technique transitions.
    Call add_technique() for each TechniqueMatch as it arrives.
    Call build() at session close to get the final serialisable graph.
    """

    def __init__(self):
        self._graph = nx.DiGraph()
        self._sequence: list[TechniqueMatch] = []
        self._node_counts: dict[str, int] = defaultdict(int)

    def add_technique(self, match: TechniqueMatch) -> None:
        """Add one technique observation to the graph."""
        tid = match.technique_id

        # Add or update node
        if not self._graph.has_node(tid):
            self._graph.add_node(
                tid,
                technique_name=match.technique_name,
                tactic=match.tactic,
                tactic_id=match.tactic_id,
                count=0,
            )

        self._graph.nodes[tid]["count"] += 1
        self._node_counts[tid] += 1

        # Add edge from previous technique, if any
        if self._sequence:
            prev = self._sequence[-1].technique_id
            if self._graph.has_edge(prev, tid):
                self._graph[prev][tid]["weight"] += 1
            else:
                self._graph.add_edge(prev, tid, weight=1)

        self._sequence.append(match)

    def build(self) -> dict:
        """
        Return the attack graph as a JSON-serialisable dict using node-link format.
        Returns an empty graph if no techniques were observed.
        """
        if not self._sequence:
            return {
                "directed": True,
                "multigraph": False,
                "graph": {},
                "nodes": [],
                "links": [],
            }

        try:
            return _node_link_data_compat(self._graph)
        except Exception as e:
            log.exception("Failed to serialise attack graph after compatibility fallback: %s", e)
            return {
                "directed": True,
                "multigraph": False,
                "graph": {},
                "nodes": [],
                "links": [],
            }

    def get_attack_path(self) -> list[str]:
        """Return the ordered list of unique tactics observed, preserving first occurrence order."""
        seen: list[str] = []
        seen_set: set[str] = set()

        for match in self._sequence:
            if match.tactic not in seen_set:
                seen.append(match.tactic)
                seen_set.add(match.tactic)

        return seen

    def get_technique_sequence(self) -> list[str]:
        """Return the ordered list of technique IDs as they were observed."""
        return [m.technique_id for m in self._sequence]

    def get_phase_sequence(self) -> list[str]:
        """
        Return the ordered list used for HMM scoring.

        Current implementation returns technique IDs because TechniqueMatch
        does not expose a separate phase field here.
        """
        return [m.technique_id for m in self._sequence]

    def summary(self) -> dict:
        """Return a human-readable summary of the attack graph."""
        return {
            "node_count": self._graph.number_of_nodes(),
            "edge_count": self._graph.number_of_edges(),
            "technique_sequence": self.get_technique_sequence(),
            "attack_path": self.get_attack_path(),
            "most_observed_technique": max(
                self._node_counts,
                key=self._node_counts.get,
                default="",
            ),
        }


def build_session_graph(technique_matches: list[TechniqueMatch]) -> dict:
    """
    Convenience function: build an attack graph from a complete list
    of TechniqueMatch objects at session close.
    """
    builder = AttackGraphBuilder()

    for match in technique_matches:
        builder.add_technique(match)

    return builder.build()
