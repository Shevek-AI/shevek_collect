"""Bound YAML construction before aliases or merge keys can amplify input."""
from __future__ import annotations

import yaml
from yaml.nodes import MappingNode, SequenceNode

MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 50_000
MAX_EXPANDED_NODES = 100_000
MAX_DEPTH = 64
MAX_DOCUMENTS = 200


class YamlLimitError(ValueError):
    pass


class BoundedSafeLoader(yaml.SafeLoader):
    def __init__(self, stream: str):
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0
        self._merges = 0
        self._flattening: set[int] = set()

    def compose_node(self, parent, index):
        self._nodes += 1
        self._depth += 1
        try:
            if self._nodes > MAX_NODES or self._depth > MAX_DEPTH:
                raise YamlLimitError("yaml_node_or_depth_limit")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_document(self, node):
        # Count the expanded graph with memoization, before construction. Reject
        # cycles as downstream JSON serializers cannot represent them safely.
        active: set[int] = set()
        weights: dict[int, int] = {}

        def weight(current, depth=0):
            identity = id(current)
            if identity in active or depth > MAX_DEPTH:
                raise YamlLimitError("yaml_recursive_alias_or_depth_limit")
            if identity in weights:
                return weights[identity]
            active.add(identity)
            total = 1
            children = (
                [child for pair in current.value for child in pair]
                if isinstance(current, MappingNode)
                else current.value if isinstance(current, SequenceNode) else []
            )
            for child in children:
                total += weight(child, depth + 1)
                if total > MAX_EXPANDED_NODES:
                    raise YamlLimitError("yaml_expansion_limit")
            active.remove(identity)
            weights[identity] = total
            return total

        weight(node)
        return super().construct_document(node)

    def flatten_mapping(self, node):
        identity = id(node)
        if identity in self._flattening:
            raise YamlLimitError("yaml_recursive_merge")
        self._flattening.add(identity)
        try:
            # The expanded-graph check precedes this operation, and this second
            # bound caps aggregate merge work across all nodes in a document.
            self._merges += len(node.value)
            if self._merges > MAX_EXPANDED_NODES:
                raise YamlLimitError("yaml_merge_limit")
            super().flatten_mapping(node)
            if len(node.value) > MAX_EXPANDED_NODES:
                raise YamlLimitError("yaml_merge_limit")
        finally:
            self._flattening.remove(identity)


def load_documents(content: str, *, max_documents: int = MAX_DOCUMENTS) -> list[object]:
    if len(content.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise YamlLimitError("yaml_byte_limit")
    loader = BoundedSafeLoader(content)
    try:
        documents = []
        while loader.check_data():
            if len(documents) >= max_documents:
                raise YamlLimitError("yaml_document_limit")
            documents.append(loader.get_data())
        return documents
    finally:
        loader.dispose()


def load_config_yaml(content: str) -> object:
    documents = load_documents(content, max_documents=1)
    return documents[0] if documents else None
