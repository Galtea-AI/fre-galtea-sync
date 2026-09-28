# fre-galtea-sync

Sync the [Fraud Rule Engine](https://github.com/farishaddad/Fraud-Rule-Engine) (FRE) rulebook to [Galtea](https://galtea.ai) Policy specifications, one specification per rule.

The specifications describe what the FRE Explanation Agent must state correctly when it explains a transaction decision, a Z3 finding or a rule fix. Galtea can then generate tests from them and score the agent's explanations rule by rule.

## What a run does

1. Reads the rulebook from `packages/z3-prover/sample_rulebook.json`, the Cedar policies from `packages/cedar-policy/policies/tier1_blocks.cedar` and the Drools rules from `packages/drools-engine/src/main/resources/rules/`.
2. Renders one Policy specification per rule. The name is `<rule ID>: <rule name>`.
3. Compares the result with the specifications in the Galtea product and sorts every rule into new, changed, unchanged or removed.
4. With `--apply`: gets the product version whose [facts](https://docs.galtea.ai/concepts/product/version#version-facts) are the rulebook state, or creates it as `rulebook-<commit>`. Then it creates, updates or deletes specifications.
5. Prints a summary and, with `--report`, writes a JSON report with one row per rule.

The version facts are the rulebook path (`rulebook.path`), the last commit that touched the rulebook or the Cedar policies (`rulebook.commit`) and a hash of the rule content (`rulebook.digest`). The hash also changes with edits that are not committed; such a version is named `rulebook-<commit>-modified-<hash>`.

A second run on the same rulebook changes nothing. The script manages only specifications whose name starts with a rule ID. Other specifications in the product stay untouched.

The run also reports drift between the Z3 model and the enforced rules: a Cedar policy that tests an attribute the Z3 model does not, a Cedar or Drools rule that the Z3 rulebook does not contain, or a Z3 rule that no engine enforces.

## Use

Requires Python 3.10 or later and the [Galtea CLI](https://docs.galtea.ai/cli/installation), signed in with `galtea login` or `GALTEA_API_KEY`.

```bash
# Dry run: render and compare, write nothing
python -m fre_galtea_sync --fre-repo ../Fraud-Rule-Engine --print-specs

# Compare with a Galtea product, write nothing
python -m fre_galtea_sync --fre-repo ../Fraud-Rule-Engine --product-id <product-id>

# Write to Galtea
python -m fre_galtea_sync --fre-repo ../Fraud-Rule-Engine --product-id <product-id> --apply --report report.json
```

## Tests

```bash
python -m unittest discover -s tests
```

## Limits

- A changed rule updates its specification in place. Specification versions are coming soon in Galtea; until then, the product version with the rulebook facts records which rulebook each evaluation ran against.
- The Z3 rulebook is a model of the enforced rules. A rule that is enforced but absent from the Z3 rulebook gets no specification; the run reports it as a warning.

## Licence

Apache License 2.0. Copyright 2026 Galtea AI. See [LICENSE](LICENSE).
