from itertools import chain
import functools
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import groupby
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Tuple

if TYPE_CHECKING:
    from typing_extensions import Self, assert_never

from cachi2.core.models.sbom import Component, Property, SPDXPackage, SPDXRelation


def merge_component_properties(components: Iterable[Component]) -> list[Component]:
    """Sort and de-duplicate components while merging their `properties`."""
    components = sorted(components, key=Component.key)
    grouped_components = groupby(components, key=Component.key)

    def merge_component_group(component_group: Iterable[Component]) -> Component:
        component_group = list(component_group)
        prop_sets = (PropertySet.from_properties(c.properties) for c in component_group)
        merged_prop_set = functools.reduce(PropertySet.merge, prop_sets)
        component = component_group[0]
        return component.model_copy(update={"properties": merged_prop_set.to_properties()})

    return [merge_component_group(g) for _, g in grouped_components]


@dataclass(frozen=True)
class PropertySet:
    """Represents the semantic meaning of the set of Properties of a single Component."""

    found_by: Optional[str] = None
    missing_hash_in_file: frozenset[str] = field(default_factory=frozenset)
    npm_bundled: bool = False
    npm_development: bool = False
    pip_package_binary: bool = False
    bundler_package_binary: bool = False

    @classmethod
    def from_properties(cls, props: Iterable[Property]) -> "Self":
        """Convert a list of SBOM component properties to a PropertySet."""
        found_by = None
        missing_hash_in_file = []
        npm_bundled = False
        npm_development = False
        pip_package_binary = False
        bundler_package_binary = False

        for prop in props:
            if prop.name == "cachi2:found_by":
                found_by = prop.value
            elif prop.name == "cachi2:missing_hash:in_file":
                missing_hash_in_file.append(prop.value)
            elif prop.name == "cdx:npm:package:bundled":
                npm_bundled = True
            elif prop.name == "cdx:npm:package:development":
                npm_development = True
            elif prop.name == "cachi2:pip:package:binary":
                pip_package_binary = True
            elif prop.name == "cachi2:bundler:package:binary":
                bundler_package_binary = True
            else:
                assert_never(prop.name)

        return cls(
            found_by,
            frozenset(missing_hash_in_file),
            npm_bundled,
            npm_development,
            pip_package_binary,
            bundler_package_binary,
        )

    def to_properties(self) -> list[Property]:
        """Convert a PropertySet to a list of SBOM component properties."""
        props = []
        if self.found_by:
            props.append(Property(name="cachi2:found_by", value=self.found_by))
        props.extend(
            Property(name="cachi2:missing_hash:in_file", value=filepath)
            for filepath in self.missing_hash_in_file
        )
        if self.npm_bundled:
            props.append(Property(name="cdx:npm:package:bundled", value="true"))
        if self.npm_development:
            props.append(Property(name="cdx:npm:package:development", value="true"))
        if self.pip_package_binary:
            props.append(Property(name="cachi2:pip:package:binary", value="true"))
        if self.bundler_package_binary:
            props.append(Property(name="cachi2:bundler:package:binary", value="true"))

        return sorted(props, key=lambda p: (p.name, p.value))

    def merge(self, other: "Self") -> "Self":
        """Combine two PropertySets."""
        cls = type(self)
        return cls(
            found_by=self.found_by or other.found_by,
            missing_hash_in_file=self.missing_hash_in_file | other.missing_hash_in_file,
            npm_bundled=self.npm_bundled and other.npm_bundled,
            npm_development=self.npm_development and other.npm_development,
            pip_package_binary=self.pip_package_binary or other.pip_package_binary,
            bundler_package_binary=self.bundler_package_binary or other.bundler_package_binary,
        )


def merge_two_relationships(rel1, rel2):
    pass

def merge_relationships(sboms_to_merge) -> Tuple[List[SPDXRelation], List[SPDXPackage]]:
    """Merge SPDX relationships.

    Function takes relationships lists and unified list of packages.
    For relationhips lists, map and inverse map of relations are created. SPDX document usually
    contains virtual package which serves as "envelope" for all real packages. These virtual
    packages are searched in the relationships and their ID is stored as middle element.
    """

    # None of these entities are actually used outside of the function.
    # It is safe to mutate them.
    doc_ids: List[str] = [s.SPDXID for s in sboms_to_merge]
    _packages = list(chain.from_iterable(s.packages for s in sboms_to_merge))
    relationships_list = [s.relationships for s in sboms_to_merge]

    def create_direct_and_inverse_relationshipos_maps(
        relationships: List[SPDXRelation],
    ) -> Tuple[Optional[str], Dict[str, List[str]], Dict[str, str]]:
        direct_map: Dict[str, List[str]] = defaultdict(list)
        inverse_map: Dict[str, str] = {}

        for rel in relationships:
            spdx_id, related_spdx = rel.spdxElementId, rel.relatedSpdxElement
            direct_map[spdx_id].append(related_spdx)
            inverse_map[related_spdx] = spdx_id
        return direct_map, inverse_map

    def find_root(direct_map, inverse_map, doc_id=None):
        # A root is either an element that no other element is related to
        # or a document id as a fallback:
        return next((spdx_id for spdx_id in direct_map if spdx_id not in inverse_map), doc_id)

    package_ids = {pkg.SPDXID for pkg in _packages}
    # this is a terrible name, but I don't want to overspend on it ATM.
    preprocessed_sbom_data = []
    for relationships, doc_id in zip(relationships_list, doc_ids):
        dir_map, inv_map = create_direct_and_inverse_relationshipos_maps(relationships)
        root = find_root(dir_map, inv_map, doc_id)
        preprocessed_sbom_data.append((dir_map, inv_map, root))
    root_ids = list(zip(*preprocessed_sbom_data))[2]

    envelopes = []
    for _map, _inv_map, root_id in preprocessed_sbom_data:
        envelope = next((r for r, c in _map.items() if _inv_map.get(r) == root_id), None)
        envelopes.append(envelope)

    merged_relationships = []

    def process_relation(
        rel: SPDXRelation,
        root_main: Optional[str],
        root_other: Optional[str],
        envelope_main: str,
        envelope_other: Optional[str],
    ) -> None:
        new_rel = SPDXRelation(
            spdxElementId=root_main if rel.spdxElementId == root_other else rel.spdxElementId,
            relatedSpdxElement=(
                root_main if rel.relatedSpdxElement == root_other else rel.relatedSpdxElement
            ),
            relationshipType=rel.relationshipType,
        )
        if new_rel.spdxElementId == envelope_other:
            new_rel.spdxElementId = envelope_main
        if new_rel.spdxElementId in package_ids or new_rel.relatedSpdxElement in package_ids:
            merged_relationships.append(new_rel)

    envelope_main = next((e for e in envelopes if e is not None), None)
    if envelope_main is None:
        _packages.append(
            SPDXPackage(
                SPDXID="SPDXRef-DocumentRoot-File-",
                name="",
            )
        )
        envelope_main = "SPDXRef-DocumentRoot-File-"
    merged_relationships.append(
        SPDXRelation(
            spdxElementId=root_ids[0],
            relatedSpdxElement="SPDXRef-DocumentRoot-File-",
            relationshipType="DESCRIBES",
        )
    )

    root_main = root_ids[0]

    for relationships, root_id, envelope in zip(relationships_list, root_ids, envelopes):
        for rel in relationships:
            process_relation(rel, root_main, root_id, envelope_main, envelope)

    # Filter envelope packages. TODO: make this a function
    for envelope in envelopes:
        if envelope == envelope_main:
            continue
        envelope_package = next((p for p in _packages if p.SPDXID == envelope), None)
        if envelope_package is not None:
            _packages.pop(_packages.index(envelope_package))
    return merged_relationships, _packages
