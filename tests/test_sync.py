"""Tests on a small rulebook built in a temporary FRE-shaped checkout."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from fre_galtea_sync import plan, render, rulebook

CEDAR = """
// =====
// WT-003: FATF High-Risk Jurisdiction
forbid (principal, action == FRE::Action::"wire_transfer", resource)
when { ["IR"].contains(resource.beneficiaryCountry) && resource.amountGbp > 1000 };
// =====
// T1-FROZEN: Frozen Account
forbid (principal, action, resource) when { principal.accountFrozen == true };
"""

DRL = """
rule "WT-002"
    salience 800
when
then
end

rule "DC-005"
    salience 1000
when
then
end
"""

RULES = [
    {"id": "WT-003", "name": "FATF High-Risk Jurisdiction", "cat": "WT", "tier": 1, "action": "BLOCK",
     "risk": 95, "queue": "SANCTIONS_COMPLIANCE", "salience": 1000,
     "conditions": [{"field": "beneficiaryCountryRisk", "op": ">=", "value": 8},
                    {"field": "amountGbp", "op": ">", "value": 1000}], "depends_on": []},
    {"id": "WT-002", "name": "Structuring / Smurfing Pattern", "cat": "WT", "tier": 3, "action": "FLAG",
     "risk": 80, "queue": "AML_STRUCTURING", "salience": 800,
     "conditions": [{"field": "wireCount24h", "op": ">=", "value": 3}], "depends_on": ["WT-003"]},
]


def make_repo(rules=RULES) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / rulebook.Z3_RULEBOOK).parent.mkdir(parents=True)
    (root / rulebook.Z3_RULEBOOK).write_text(json.dumps({"schema": [], "rules": rules}))
    (root / rulebook.CEDAR_POLICIES).parent.mkdir(parents=True)
    (root / rulebook.CEDAR_POLICIES).write_text(CEDAR)
    (root / rulebook.DROOLS_RULES).mkdir(parents=True)
    (root / rulebook.DROOLS_RULES / "tier1_blocks.drl").write_text(DRL)
    return root


def as_existing(p: plan.Plan) -> list[plan.ExistingSpec]:
    return [plan.ExistingSpec(f"spec-{c.rule_id}", c.content.name, c.content.description, c.content.type,
                              c.content.test_type, c.content.test_variant) for c in p.changes if c.content]


class RulebookTest(unittest.TestCase):
    def test_engine_and_drift_warnings(self):
        book = rulebook.load(make_repo())
        by_id = book.by_id()
        self.assertEqual(by_id["WT-003"].engine, "cedar")
        self.assertEqual(by_id["WT-002"].engine, "drools")
        self.assertTrue(any(w.startswith("WT-003: the Z3 model tests") for w in book.warnings))
        self.assertIn("T1-FROZEN: enforced by Cedar, absent from the Z3 rulebook", book.warnings)
        self.assertIn("DC-005: enforced by Drools, absent from the Z3 rulebook", book.warnings)
        self.assertFalse(any("enforced by neither" in w for w in book.warnings))
        self.assertFalse(any(w.startswith("WT-002") for w in book.warnings))

    def test_fingerprint_tracks_content(self):
        rule = rulebook.load(make_repo()).by_id()["WT-003"]
        self.assertEqual(rule.fingerprint(), replace(rule).fingerprint())
        self.assertNotEqual(rule.fingerprint(), replace(rule, risk=90).fingerprint())


    def test_facts_follow_rule_content(self):
        book = rulebook.load(make_repo())
        self.assertEqual(book.facts(), rulebook.load(make_repo(list(reversed(RULES)))).facts())
        self.assertEqual(set(book.facts()), {"rulebook.path", "rulebook.digest"})  # no git checkout
        rules = json.loads(json.dumps(RULES))
        rules[0]["conditions"][1]["value"] = 500
        self.assertNotEqual(book.digest(), rulebook.load(make_repo(rules)).digest())
        self.assertEqual(book.version_name(), f"rulebook-{book.digest()}")


    def test_git_commit_and_modified_state(self):
        repo = make_repo()
        git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "rulebook"], check=True)
        clean = rulebook.load(repo)
        self.assertFalse(clean.modified)
        self.assertEqual(clean.version_name(), f"rulebook-{clean.commit[:12]}")
        cedar = repo / rulebook.CEDAR_POLICIES
        cedar.write_text(cedar.read_text().replace("// T1-FROZEN", "// WT-002"))
        edited = rulebook.load(repo)
        self.assertTrue(edited.modified)
        self.assertNotEqual(clean.digest(), edited.digest())
        self.assertTrue(edited.version_name().startswith(f"rulebook-{clean.commit[:12]}-modified-"))


class RenderTest(unittest.TestCase):
    def test_description_carries_the_facts(self):
        book = rulebook.load(make_repo())
        wt003 = render.spec_content(book.by_id()["WT-003"]).description
        self.assertIn("the amount is more than £1,000", wt003)
        self.assertIn("forbid policy", wt003)
        self.assertTrue(wt003.startswith("WT-003 (FATF High-Risk Jurisdiction) blocks a transaction when"))
        self.assertIn("beneficiary country has a risk score of at least 8", wt003)
        wt002 = render.spec_content(book.by_id()["WT-002"]).description
        self.assertIn("depends on WT-003", wt002)
        self.assertIn("another rule has already blocked", wt002)

    def test_rule_without_conditions(self):
        rule = replace(rulebook.load(make_repo()).by_id()["WT-002"], conditions=())
        self.assertIn("when no condition is stated.", render.spec_content(rule).description)

    def test_rule_id_from_name(self):
        self.assertEqual(render.rule_id_from_name("T1-SANCTIONS: Sanctions Screening"), "T1-SANCTIONS")
        self.assertIsNone(render.rule_id_from_name("Explanations use the Finding, Detail, Fix format"))
        self.assertIsNone(render.rule_id_from_name("Note: something"))


class PlanTest(unittest.TestCase):
    def test_first_run_creates_everything(self):
        p = plan.build(rulebook.load(make_repo()), [])
        self.assertEqual((p.count("new"), p.count("changed"), p.count("removed")), (2, 0, 0))

    def test_second_run_changes_nothing(self):
        book = rulebook.load(make_repo())
        again = plan.build(book, as_existing(plan.build(book, [])))
        self.assertEqual(again.count("unchanged"), 2)
        self.assertEqual(again.count("new") + again.count("changed") + again.count("removed"), 0)

    def test_threshold_change_is_one_changed_rule(self):
        before = as_existing(plan.build(rulebook.load(make_repo()), []))
        rules = json.loads(json.dumps(RULES))
        rules[0]["conditions"][1]["value"] = 500
        after = plan.build(rulebook.load(make_repo(rules)), before)
        self.assertEqual((after.count("changed"), after.count("unchanged")), (1, 1))
        changed = next(c for c in after.changes if c.state == "changed")
        self.assertEqual((changed.rule_id, changed.changed_fields), ("WT-003", ("description",)))

    def test_removed_rule_and_unmanaged_spec(self):
        existing = as_existing(plan.build(rulebook.load(make_repo()), []))
        existing.append(plan.ExistingSpec("spec-x", "Explanations use the Finding, Detail, Fix format",
                                          "...", "POLICY", "QUALITY", "rag"))
        p = plan.build(rulebook.load(make_repo(RULES[:1])), existing)
        self.assertEqual([c.rule_id for c in p.changes if c.state == "removed"], ["WT-002"])
        self.assertEqual(p.unmanaged, ["Explanations use the Finding, Detail, Fix format"])


if __name__ == "__main__":
    unittest.main()
