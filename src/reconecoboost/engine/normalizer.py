"""Normalizer — many tools, one truth.

Turns tool-shaped ``ParsedRecord`` objects into canonical, deduplicated
entities, merging multi-source facts (a URL seen by both katana and gau becomes
one entity with two provenance sources) and resolving natural keys. It also
deduplicates relation edges. This is the boundary where domain canonicalization
lives (architecture doc 08/10).

It does not persist anything — it returns in-memory entities/relations for the
persistence and graph layers to store.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.entities import CanonicalEntity, Provenance, Relation, canonical_key
from .parser import ParsedRecord

# Re-exported for callers that import it from the engine namespace.
__all__ = ["Normalizer", "NormalizationResult", "canonical_key"]


@dataclass
class NormalizationResult:
    """The Normalizer's output: deduplicated entities and relations."""

    entities: list[CanonicalEntity] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)


class Normalizer:
    """Canonicalizes and deduplicates parsed records into entities + relations."""

    def normalize(
        self,
        records: list[ParsedRecord],
        relations: list[Relation] | None = None,
    ) -> NormalizationResult:
        entities: dict[tuple[str, str], CanonicalEntity] = {}
        rel_index: dict[tuple[str, str, str, str, str], Relation] = {}

        for record in records:
            ckey = canonical_key(record.asset_type, record.key)
            identity = (record.asset_type, ckey)

            entity = entities.get(identity)
            if entity is None:
                entity = CanonicalEntity(
                    asset_type=record.asset_type,
                    canonical_key=ckey,
                    attributes={},
                    sources=[],
                )
                entities[identity] = entity

            self._merge_attributes(entity, record.attributes)
            self._add_source(entity, record)

            for rel in record.relations:
                rel_index.setdefault(rel.identity, rel)

        for rel in relations or []:
            rel_index.setdefault(rel.identity, rel)

        return NormalizationResult(
            entities=list(entities.values()),
            relations=list(rel_index.values()),
        )

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _merge_attributes(entity: CanonicalEntity, new: dict) -> None:
        for attr_key, value in new.items():
            if value is None:
                continue
            # Last non-null write wins; richer merge strategies can come later.
            entity.attributes[attr_key] = value

    @staticmethod
    def _add_source(entity: CanonicalEntity, record: ParsedRecord) -> None:
        if not record.tool:
            return
        for existing in entity.sources:
            if existing.tool == record.tool and existing.raw_ref == record.raw_ref:
                return
        entity.sources.append(Provenance(tool=record.tool, raw_ref=record.raw_ref))
