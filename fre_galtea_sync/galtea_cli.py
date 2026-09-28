"""Galtea access through the `galtea` CLI.

The CLI handles authentication (`galtea login` or `GALTEA_API_KEY`). Request bodies
are sent as JSON on stdin. This is the only module that writes to Galtea.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from .plan import Change, ExistingSpec


class GalteaError(RuntimeError):
    pass


def _run(args: list[str], body: dict[str, Any] | None = None) -> Any:
    proc = subprocess.run(
        ["galtea", *args, "-o", "json"],
        input=json.dumps(body) if body is not None else "",
        capture_output=True, text=True,
    )
    out = proc.stdout.strip()
    data = json.loads(out) if out else None
    if proc.returncode != 0 or (isinstance(data, dict) and "error" in data and "message" in data):
        message = data.get("message") if isinstance(data, dict) else proc.stderr.strip()
        raise GalteaError(f"galtea {' '.join(args)}: {message or proc.stderr.strip()}")
    return data


def _list_all(resource: str, product_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = _run([resource, "list", "--product-ids", product_id, "--limit", "100", "--offset", str(offset)]) or []
        rows.extend(page)
        if len(page) < 100:
            return rows
        offset += 100


def list_specifications(product_id: str) -> list[ExistingSpec]:
    return [
        ExistingSpec(id=s["id"], name=s["name"], description=s["description"], type=s["type"],
                     test_type=s.get("testType"), test_variant=s.get("testVariant"))
        for s in _list_all("specifications", product_id)
    ]


def version_for_rulebook(product_id: str, facts: dict[str, str], name: str, description: str) -> dict[str, Any]:
    """The product version whose facts are the rulebook state. Galtea creates it when no version holds them."""
    known = {v["id"] for v in _list_all("versions", product_id)}
    version = _run(["versions", "get-or-create"], {"productId": product_id, "facts": facts, "name": name})
    created = version["id"] not in known
    if created:
        _run(["versions", "update", version["id"]], {"description": description})
    return {"id": version["id"], "name": version["name"], "number": version.get("number"),
            "facts": version.get("facts"), "created": created}


def apply(product_id: str, changes: list[Change]) -> list[dict[str, str]]:
    """Write the plan to Galtea. Returns one result row per change that touched Galtea."""
    results: list[dict[str, str]] = []
    for change in changes:
        if change.state == "new":
            c = change.content
            created = _run(["specifications", "create"], {
                "productId": product_id, "name": c.name, "description": c.description,
                "type": c.type, "testType": c.test_type, "testVariant": c.test_variant,
            })
            results.append({"rule_id": change.rule_id, "action": "created", "spec_id": created["id"]})
        elif change.state == "changed":
            c = change.content
            fields = {"name": c.name, "description": c.description, "type": c.type,
                      "testType": c.test_type, "testVariant": c.test_variant}
            wanted = {"test_type": "testType", "test_variant": "testVariant"}
            body = {wanted.get(f, f): fields[wanted.get(f, f)] for f in change.changed_fields}
            _run(["specifications", "update", change.spec_id], body)
            results.append({"rule_id": change.rule_id, "action": "updated", "spec_id": change.spec_id})
        elif change.state == "removed":
            _run(["specifications", "delete", change.spec_id])
            results.append({"rule_id": change.rule_id, "action": "deleted", "spec_id": change.spec_id})
    return results
