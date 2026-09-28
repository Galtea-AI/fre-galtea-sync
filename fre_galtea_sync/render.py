"""Turn one FRE rule into the Galtea Policy specification that the Explanation Agent is held to.

The product under test is the FRE Explanation Agent, not the rules engine. Each
specification therefore states the rule as ground truth and then states what the agent
must get right when it explains a decision, a Z3 finding or a fix that involves the rule.
"""
from __future__ import annotations

from dataclasses import dataclass

from .rulebook import Condition, Rule

SPEC_TYPE = "POLICY"
# The API names the Accuracy dataset type QUALITY.
DATASET_TYPE = "QUALITY"
DATASET_VARIANT = "rag"

_ACTIONS = {"BLOCK": "blocks", "FLAG": "flags", "STEP_UP": "requires step-up authentication for"}
_OUTCOMES = {"BLOCK": "that it blocks the transaction", "FLAG": "that it flags the transaction",
             "STEP_UP": "that it requires step-up authentication"}
_CMP = {">": "more than", ">=": "at least", "<": "less than", "<=": "at most", "==": "", "!=": "not"}

# Plain-English wording for each field of the FRE rulebook schema. {cmp} is the comparison
# ("at least", "more than", ...), {v} the formatted value. Booleans have a true and a false form.
_FIELDS: dict[str, str | tuple[str, str]] = {
    "authFailuresLast24h": "the customer had {cmp} {v} authentication failures in the last 24 hours",
    "minutesSinceLastAuthFailure": "the last authentication failure was {cmp} {v} minutes ago",
    "daysSinceLastDebit": "the last debit on the account was {cmp} {v} days ago",
    "wireCount24h": "the account sent {cmp} {v} wires in the last 24 hours",
    "wireSum24h": "the wires of the last 24 hours total {cmp} {v}",
    "wireMax24h": "the largest wire of the last 24 hours is {cmp} {v}",
    "beneficiaryCountryRisk": "the beneficiary country has a risk score of {cmp} {v}",
    "amountGbp": "the amount is {cmp} {v}",
    "cardTxCount1h": "the card made {cmp} {v} transactions in the last hour",
    "declinedCount1h": "{cmp} {v} transactions were declined in the last hour",
    "achCreditSum6h": "the ACH credits of the last 6 hours total {cmp} {v}",
    "originatorReturnRate30d": "the originator's 30-day return rate is {cmp} {v}",
    "availableCreditPct": "the available credit is {cmp} {v} of the limit",
    "spendVelocitySignal": "spending in the last 7 days is {cmp} {v} times the weekly average",
    "recentCredentialChange": ("the credentials changed recently", "the credentials did not change recently"),
    "isSanctioned": ("the customer is on a sanctions list", "the customer is not on a sanctions list"),
    "accountFrozen": ("the account is frozen", "the account is not frozen"),
    "impossibleTravelDetected": ("impossible travel is detected", "no impossible travel is detected"),
    "payeeNameMismatch": ("the payee name on the cheque does not match the account name",
                          "the payee name on the cheque matches the account name"),
    "chequeDateValid": ("the cheque date is valid", "the cheque date is not valid"),
    "chequeSerialPresented": ("the cheque serial number was already presented",
                              "the cheque serial number was not presented before"),
    "fundsSourceCleared": ("the source funds have cleared", "the source funds have not cleared"),
}
_MONEY = {"amountGbp", "wireSum24h", "wireMax24h", "achCreditSum6h"}
_PERCENT = {"originatorReturnRate30d", "availableCreditPct"}


@dataclass(frozen=True)
class SpecContent:
    name: str
    description: str
    type: str = SPEC_TYPE
    test_type: str = DATASET_TYPE
    test_variant: str = DATASET_VARIANT


def spec_name(rule: Rule) -> str:
    return f"{rule.id}: {rule.name}"


def rule_id_from_name(name: str) -> str | None:
    """The rule ID a managed specification name starts with, or None for any other name."""
    head, sep, _ = name.partition(": ")
    if not sep or "-" not in head or not head.replace("-", "").isalnum() or head.upper() != head:
        return None
    return head


def _value(field: str, value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if field in _PERCENT and isinstance(value, (int, float)):
        return f"{value * 100:g}%"
    if field in _MONEY and isinstance(value, (int, float)):
        return f"£{value:,}"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def _condition(c: Condition) -> str:
    wording = _FIELDS.get(c.field)
    if isinstance(wording, tuple) and isinstance(c.value, bool) and c.op in ("==", "!="):
        holds = c.value == (c.op == "==")
        return wording[0] if holds else wording[1]
    if isinstance(wording, str) and not isinstance(c.value, bool):
        return " ".join(wording.format(cmp=_CMP.get(c.op, c.op), v=_value(c.field, c.value)).split())
    return f"{c.field} {c.op} {_value(c.field, c.value)}"


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _title(rule: Rule) -> str:
    """The rule ID and name; a comma pair when the name has its own brackets."""
    return f"{rule.id}, {rule.name}," if "(" in rule.name else f"{rule.id} ({rule.name})"


def spec_content(rule: Rule) -> SpecContent:
    action = _ACTIONS.get(rule.action, rule.action.lower())
    when = _join([_condition(c) for c in rule.conditions]) if rule.conditions else "no condition is stated"

    facts = [
        f"{_title(rule)} {action} a transaction when {when}.",
        f"It is a Tier {rule.tier} rule with risk score {rule.risk}, and it sends the transaction to the {rule.queue} queue.",
    ]
    if rule.conditions:
        fields = list(dict.fromkeys(c.field for c in rule.conditions))
        subject = "the condition tests" if len(rule.conditions) == 1 else "the conditions test"
        facts.append(f"In the rulebook, {subject} {_join(fields)}.")
    if rule.engine == "cedar":
        facts.append("Cedar enforces it as a forbid policy, so no Drools rule, salience value or velocity signal can override the block.")
    else:
        facts.append(f"Drools runs it at salience {rule.salience}.")
    if rule.tier >= 2:
        facts.append("It does not fire if another rule has already blocked the transaction.")
    for dep in rule.depends_on:
        facts.append(f"It depends on {dep}, which runs first.")

    salience = "" if rule.engine == "cedar" else f", salience {rule.salience}"
    obligation = (
        f"When the agent explains a decision, a Z3 finding or a rule fix that involves {rule.id}, it gets these facts right: "
        f"the rule ID, {_OUTCOMES.get(rule.action, rule.action)}, Tier {rule.tier}{salience}, "
        f"each condition that triggered with its value from the transaction, and the {rule.queue} queue. "
        "It does not add a condition, threshold or outcome that the rule does not have."
    )
    return SpecContent(name=spec_name(rule), description=" ".join(facts) + " " + obligation)
