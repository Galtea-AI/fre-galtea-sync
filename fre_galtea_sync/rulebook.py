"""Read the Fraud Rule Engine rulebook into plain rule records.

The source of rule content is the Z3 rulebook JSON, the one FRE file that holds the
rules of every tier with their conditions. The Cedar policies tell which rules Cedar
enforces; every other rule is a Drools rule. The Cedar policies and the Drools rule files
are also read to report drift: a Cedar policy that tests other attributes than the Z3
model, an enforced rule that the Z3 rulebook does not contain, or a Z3 rule that no
engine enforces.

The rule content depends on two files, the Z3 rulebook and the Cedar policies, so the
commit and the "modified" state cover both.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

Z3_RULEBOOK = Path("packages/z3-prover/sample_rulebook.json")
CEDAR_POLICIES = Path("packages/cedar-policy/policies/tier1_blocks.cedar")
DROOLS_RULES = Path("packages/drools-engine/src/main/resources/rules")

_CEDAR_HEADER = re.compile(r"^// ([A-Z0-9]+(?:-[A-Z0-9]+)+):", re.MULTILINE)
_CEDAR_ATTR = re.compile(r"\b(?:resource|principal)\.([A-Za-z_][A-Za-z0-9_]*)")
_DROOLS_RULE = re.compile(r'^rule "([^"]+)"', re.MULTILINE)


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: object


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    tier: int
    action: str
    risk: int
    queue: str
    salience: int
    conditions: tuple[Condition, ...]
    depends_on: tuple[str, ...]
    engine: str  # "cedar" or "drools"

    def fingerprint(self) -> str:
        """Hash of the rule content. Two rules with the same content have the same hash."""
        payload = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "tier": self.tier,
            "action": self.action,
            "risk": self.risk,
            "queue": self.queue,
            "salience": self.salience,
            "conditions": [[c.field, c.op, c.value] for c in self.conditions],
            "depends_on": list(self.depends_on),
            "engine": self.engine,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]


@dataclass
class Rulebook:
    rules: list[Rule]
    commit: str | None
    path: str = str(Z3_RULEBOOK)
    modified: bool = False  # the Z3 rulebook or the Cedar policies have changes that are not committed
    warnings: list[str] = field(default_factory=list)

    def by_id(self) -> dict[str, Rule]:
        return {r.id: r for r in self.rules}

    def digest(self) -> str:
        """Hash of the whole rulebook content. The same rules give the same hash in any order."""
        joined = ",".join(sorted(r.fingerprint() for r in self.rules))
        return hashlib.sha256(joined.encode()).hexdigest()[:12]

    def facts(self) -> dict[str, str]:
        """The rulebook state as Galtea version facts. The same rulebook always gives the same facts."""
        facts = {"rulebook.path": self.path, "rulebook.digest": self.digest()}
        if self.commit:
            facts["rulebook.commit"] = self.commit
        return facts

    def version_name(self) -> str:
        if not self.commit:
            return f"rulebook-{self.digest()}"
        name = f"rulebook-{self.commit[:12]}"
        return f"{name}-modified-{self.digest()[:6]}" if self.modified else name


def cedar_policies(text: str) -> dict[str, set[str]]:
    """Map each Cedar rule ID (from its header comment) to the attributes its policy tests."""
    headers = list(_CEDAR_HEADER.finditer(text))
    policies: dict[str, set[str]] = {}
    for i, match in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        policies[match.group(1)] = set(_CEDAR_ATTR.findall(text[match.end():end]))
    return policies


def drools_rule_ids(rules_dir: Path) -> set[str]:
    """The rule names declared in the Drools rule files."""
    if not rules_dir.is_dir():
        return set()
    return {m for f in sorted(rules_dir.glob("*.drl")) for m in _DROOLS_RULE.findall(f.read_text())}


def _git_commit(repo: Path, *paths: Path) -> str | None:
    """Last commit that touched any of the files, or None outside a git checkout."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--format=%H", "--", *map(str, paths)],
            capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def _git_modified(repo: Path, *paths: Path) -> bool:
    """True when any of the files differs from its last commit."""
    try:
        out = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--", *map(str, paths)],
                             capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return bool(out.stdout.strip())


def load(repo: Path, rulebook_path: Path = Z3_RULEBOOK, cedar_path: Path = CEDAR_POLICIES) -> Rulebook:
    raw = json.loads((repo / rulebook_path).read_text())
    cedar_file = repo / cedar_path
    cedar = cedar_policies(cedar_file.read_text()) if cedar_file.exists() else {}

    rules: list[Rule] = []
    warnings: list[str] = []
    for item in raw["rules"]:
        conditions = tuple(Condition(c["field"], c["op"], c["value"]) for c in item.get("conditions", []))
        rule = Rule(
            id=item["id"],
            name=item["name"],
            category=item.get("cat", ""),
            tier=int(item["tier"]),
            action=item["action"],
            risk=int(item["risk"]),
            queue=item["queue"],
            salience=int(item["salience"]),
            conditions=conditions,
            depends_on=tuple(item.get("depends_on", [])),
            engine="cedar" if item["id"] in cedar else "drools",
        )
        rules.append(rule)

        if rule.id in cedar:
            z3_fields = {c.field for c in conditions}
            cedar_fields = cedar[rule.id]
            if z3_fields != cedar_fields:
                warnings.append(
                    f"{rule.id}: the Z3 model tests {sorted(z3_fields)}, "
                    f"the Cedar policy tests {sorted(cedar_fields)}"
                )

    ids = {r.id for r in rules}
    for cedar_id in sorted(set(cedar) - ids):
        warnings.append(f"{cedar_id}: enforced by Cedar, absent from the Z3 rulebook")
    drools = drools_rule_ids(repo / DROOLS_RULES)
    for drools_id in sorted(drools - ids):
        warnings.append(f"{drools_id}: enforced by Drools, absent from the Z3 rulebook")
    if drools:
        for rule_id in sorted(ids - drools - set(cedar)):
            warnings.append(f"{rule_id}: in the Z3 rulebook, enforced by neither Cedar nor Drools")
    for rule in rules:
        for dep in rule.depends_on:
            if dep not in ids:
                warnings.append(f"{rule.id}: depends on {dep}, which is not in the rulebook")

    return Rulebook(rules=rules, commit=_git_commit(repo, rulebook_path, cedar_path), path=str(rulebook_path),
                    modified=_git_modified(repo, rulebook_path, cedar_path), warnings=warnings)
