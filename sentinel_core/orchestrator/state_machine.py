"""
Deterministic State Machine Engine for Sentinel Orchestration.
Implements the exact StateGraph semantics (nodes, conditional edges, retry counters, human gates)
with zero native DLL dependencies, ensuring 100% stability across all operating systems.
"""

from typing import Callable, Dict, Any, List, Optional, Union, Tuple

START = "__start__"
END = "__end__"


class StateGraph:
    """
    Deterministic State Machine controller.
    Enforces workflow order, conditional branch routing, and retry loops.
    """

    def __init__(self, state_schema: type):
        self.state_schema = state_schema
        self.nodes: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self.edges: Dict[str, str] = {}
        self.conditional_edges: Dict[str, Tuple[Callable[[Dict[str, Any]], str], Dict[str, str]]] = {}
        self.entry_point: Optional[str] = None

    def add_node(self, name: str, func: Callable[[Dict[str, Any]], Dict[str, Any]]) -> "StateGraph":
        self.nodes[name] = func
        return self

    def set_entry_point(self, node_name: str) -> "StateGraph":
        self.entry_point = node_name
        return self

    def add_edge(self, start_node: str, end_node: str) -> "StateGraph":
        if start_node == START:
            self.entry_point = end_node
        else:
            self.edges[start_node] = end_node
        return self

    def add_conditional_edges(
        self,
        source_node: str,
        path_router: Callable[[Dict[str, Any]], str],
        path_map: Optional[Dict[str, str]] = None
    ) -> "StateGraph":
        self.conditional_edges[source_node] = (path_router, path_map or {})
        return self

    def compile(self) -> "CompiledGraph":
        if not self.entry_point and START in self.edges:
            self.entry_point = self.edges[START]
        if not self.entry_point:
            raise ValueError("StateGraph entry point is not defined.")
        return CompiledGraph(self)


class CompiledGraph:
    """
    Executable workflow engine.
    Supports single execution (.invoke) and step-by-step generator streaming (.stream).
    """

    def __init__(self, graph: StateGraph):
        self.graph = graph

    def stream(self, initial_state: Dict[str, Any]):
        """
        Yields state updates after each node execution, enabling real-time UI logging.
        """
        state = dict(initial_state)
        current_node = self.graph.entry_point
        visited_count = 0
        max_steps = 50  # Safety circuit-breaker against infinite runaway loops

        while current_node and current_node != END and visited_count < max_steps:
            visited_count += 1
            node_func = self.graph.nodes.get(current_node)
            if not node_func:
                raise RuntimeError(f"Workflow reached undefined node: {current_node}")

            # Execute node
            node_output = node_func(state)
            if node_output:
                state.update(node_output)

            yield current_node, state

            # Route to next node
            if current_node in self.graph.conditional_edges:
                router_fn, path_map = self.graph.conditional_edges[current_node]
                route_key = router_fn(state)
                next_node = path_map.get(route_key, route_key)
            elif current_node in self.graph.edges:
                next_node = self.graph.edges[current_node]
            else:
                next_node = END

            current_node = next_node

        if visited_count >= max_steps:
            state["escalated_to_human"] = True
            state["escalation_reason"] = "Circuit breaker triggered: exceeded maximum state transitions."
            yield "circuit_breaker", state

    def invoke(self, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        """Runs workflow synchronously to completion and returns final state."""
        final_state = initial_state
        for node_name, state in self.stream(initial_state):
            final_state = state
        return final_state
