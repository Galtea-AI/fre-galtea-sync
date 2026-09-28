"""Sync the Fraud Rule Engine rulebook to Galtea Policy specifications.

    python -m fre_galtea_sync --fre-repo ../Fraud-Rule-Engine                        # dry run
    python -m fre_galtea_sync --fre-repo ../Fraud-Rule-Engine --product-id P --apply

A dry run reads Galtea when --product-id is given, and never writes.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import plan as planner
from . import rulebook


def _report(book: rulebook.Rulebook, plan: planner.Plan, version: dict | None, results: list[dict]) -> dict:
    written = {r["rule_id"]: r for r in results}
    return {
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rulebook_commit": book.commit,
        "rulebook_modified": book.modified,
        "facts": book.facts(),
        "version": version,
        "summary": {s: plan.count(s) for s in ("new", "changed", "unchanged", "removed")},
        "warnings": book.warnings,
        "unmanaged_specifications": plan.unmanaged,
        "duplicate_specifications": plan.duplicates,
        "rules": [
            {
                "rule_id": c.rule_id,
                "state": c.state,
                "fingerprint": c.fingerprint,
                "changed_fields": list(c.changed_fields),
                "spec_id": written.get(c.rule_id, {}).get("spec_id", c.spec_id),
                "action": written.get(c.rule_id, {}).get("action", "none"),
            }
            for c in plan.changes
        ],
    }


def _print_summary(report: dict, applied: bool) -> None:
    s = report["summary"]
    mode = "applied" if applied else "dry run"
    modified = ", modified" if report["rulebook_modified"] else ""
    print(f"Rulebook commit {report['rulebook_commit'] or 'unknown'}{modified} ({mode})")
    print(f"  new {s['new']}, changed {s['changed']}, unchanged {s['unchanged']}, removed {s['removed']}")
    if report["version"]:
        v = report["version"]
        print(f"  version {v['name']}: {'created' if v['created'] else 'existing'} ({v['id']})")
    for row in report["rules"]:
        if row["state"] != "unchanged":
            extra = f" [{', '.join(row['changed_fields'])}]" if row["changed_fields"] else ""
            print(f"  {row['state']:9} {row['rule_id']}{extra}")
    for w in report["warnings"]:
        print(f"  warning: {w}")
    if report["duplicate_specifications"]:
        print(f"  warning: duplicate specifications ignored: {report['duplicate_specifications']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fre_galtea_sync", description=__doc__.splitlines()[0])
    ap.add_argument("--fre-repo", type=Path, required=True, help="path to a Fraud Rule Engine checkout")
    ap.add_argument("--rulebook", type=Path, default=rulebook.Z3_RULEBOOK,
                    help=f"Z3 rulebook path inside the checkout (default: {rulebook.Z3_RULEBOOK})")
    ap.add_argument("--product-id", help="Galtea product that holds the specifications")
    ap.add_argument("--apply", action="store_true", help="write the plan to Galtea")
    ap.add_argument("--report", type=Path, help="write the run report as JSON to this file")
    ap.add_argument("--print-specs", action="store_true", help="print the rendered specifications")
    args = ap.parse_args(argv)

    if args.apply and not args.product_id:
        ap.error("--apply needs --product-id")

    book = rulebook.load(args.fre_repo, args.rulebook)
    existing: list[planner.ExistingSpec] = []
    if args.product_id:
        from . import galtea_cli
        existing = galtea_cli.list_specifications(args.product_id)
    plan = planner.build(book, existing)

    if args.print_specs:
        for c in plan.changes:
            if c.content:
                print(f"\n## {c.content.name}\n{c.content.description}")

    version = None
    results: list[dict] = []
    if args.apply:
        from . import galtea_cli
        description = f"Fraud Rule Engine rulebook {book.path}" + (f" at commit {book.commit}." if book.commit else ".")
        if book.modified:
            description += " The rulebook or the Cedar policies had changes that were not committed."
        version = galtea_cli.version_for_rulebook(args.product_id, book.facts(), book.version_name(), description)
        results = galtea_cli.apply(args.product_id, plan.changes)

    report = _report(book, plan, version, results)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    _print_summary(report, args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
