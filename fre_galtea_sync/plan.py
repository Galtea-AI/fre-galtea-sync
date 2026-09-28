"""Compare the specifications the rulebook needs with the ones Galtea holds.

This module does not talk to Galtea. It takes the existing specifications as plain
records, so the same plan drives both a dry run and a write.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .render import SpecContent, rule_id_from_name, spec_content
from .rulebook import Rulebook


@dataclass(frozen=True)
class ExistingSpec:
    id: str
    name: str
    description: str
    type: str
    test_type: str | None
    test_variant: str | None


@dataclass(frozen=True)
class Change:
    rule_id: str
    state: str  # "new", "changed", "unchanged", "removed"
    fingerprint: str | None
    spec_id: str | None
    content: SpecContent | None
    changed_fields: tuple[str, ...] = ()


@dataclass
class Plan:
    changes: list[Change]
    unmanaged: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)

    def count(self, state: str) -> int:
        return sum(1 for c in self.changes if c.state == state)


def _differences(existing: ExistingSpec, wanted: SpecContent) -> tuple[str, ...]:
    pairs = {
        "name": (existing.name, wanted.name),
        "description": (existing.description, wanted.description),
        "type": (existing.type, wanted.type),
        "test_type": (existing.test_type, wanted.test_type),
        "test_variant": (existing.test_variant, wanted.test_variant),
    }
    return tuple(k for k, (have, want) in pairs.items() if have != want)


def build(rulebook: Rulebook, existing: list[ExistingSpec]) -> Plan:
    managed: dict[str, ExistingSpec] = {}
    plan = Plan(changes=[])
    for spec in existing:
        rule_id = rule_id_from_name(spec.name)
        if rule_id is None:
            plan.unmanaged.append(spec.name)
        elif rule_id in managed:
            plan.duplicates.append(spec.name)
        else:
            managed[rule_id] = spec

    for rule in rulebook.rules:
        wanted = spec_content(rule)
        have = managed.pop(rule.id, None)
        if have is None:
            plan.changes.append(Change(rule.id, "new", rule.fingerprint(), None, wanted))
            continue
        diff = _differences(have, wanted)
        state = "changed" if diff else "unchanged"
        plan.changes.append(Change(rule.id, state, rule.fingerprint(), have.id, wanted, diff))

    for rule_id, spec in sorted(managed.items()):
        plan.changes.append(Change(rule_id, "removed", None, spec.id, None))
    return plan
