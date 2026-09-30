"""``analyze()`` -- the unified deterministic sweep.

The engine's four rules were implemented one at a time, each with its own test
module, and each was called directly and concatenated by hand. That was honest
while the rule set was incomplete, because a sweep that quietly omitted a rule
returns a list indistinguishable from one that found nothing. The rule set is
finished, so the concatenation moves out of the callers and into a function that
can be tested.

What is actually at stake here is not the concatenation -- that is four lines.
It is the five decisions a sweep can get wrong without any test noticing:

**Ordering.** `Severity` is a `StrEnum`, so it orders alphabetically by value:
`CRITICAL, HIGH, INFO, LOW, MEDIUM`. Anyone who writes `sorted(key=severity)`
gets a list that is wrong in a way that looks sorted. The rank is therefore
spelled out, and the test recomputes the key independently rather than trusting
the implementation's own helper.

**Grouping.** Findings are per (rule, subject), not per person, so one person can
legitimately carry two. A sweep that grouped by `user_id`, or that kept "the
worst finding", would pass every per-rule test in this suite and quietly delete
Carol's second fact.

**Deduplication.** The tempting cleanup is to drop findings with a repeated id.
That converts a rule bug -- two rules emitting the same id -- into a *missing*
finding, which no reader can distinguish from a rule that found nothing. The
tests below require the opposite: uniqueness is asserted, and a collision raises.

**Errors.** A `try`/`except` around each rule is the other tempting addition: it
makes the sweep "robust". It also makes a crashed rule look like a clean one.
The contract is that a rule's exception reaches the caller.

**Timestamps.** Each rule derives `created_at` from settings. If the sweep
re-stamped them, a rule that had stopped reading settings would still look
correct, and the sweep would have started reading a clock it must not read.

Two notes about this file's relationship to the specification.

The oracle file, ``fixtures/oracles/expected_findings.json``, says nothing about
ordering, because it was written before any of this existed and orders findings
per persona by narrative weight. The ordering asserted in
:func:`test_findings_are_ordered_by_user_then_severity_rank_then_id` is therefore
**engine-authored presentation policy**, not an oracle-derived requirement, and
is marked as such there -- the same distinction Rule C's D6 completeness test
carries.

Four tests below reach a rule by patching it out, and they patch
``app.engine.<rule module>.<sweep function>`` rather than anything inside
``analyzer.py``. That is a deliberate testability seam: it requires the sweep to
call each rule through its module rather than binding the function name into its
own namespace, which also makes it obvious at the call site which module owns
which rule. It is the only implementation detail this file pins.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import pkgutil
import typing
from collections import Counter
from datetime import UTC, datetime
from types import MappingProxyType

import pytest
from pydantic import TypeAdapter

from app.core.config import Settings
from app.core.enums import Severity
from app.ingestion import InMemoryDataset
from app.schemas.domain.finding import FORBIDDEN_CONCLUSION_PHRASES, Finding

from app.engine.analyzer import analyze
from app.engine.duplicate_identity import detect_duplicate_identities
from app.engine.ghost_access import detect_ghost_access
from app.engine.privileged_usage import detect_rarely_used_privileged_permissions
from app.engine.utilization import detect_low_utilization

AWARE = TypeAdapter(datetime)

WINDOW_START = "2026-07-01T06:00:00Z"
WINDOW_END = "2026-09-29T06:00:00Z"

#: The fixture set's total, measured from the oracle rather than predicted: Rule A
#: emits four findings (Alice, Bob, Gina, Ivan), Rule B two (Carol, Erin), Rule C
#: one (Henry) and Rule D one (Carol). Dave and Frank are the negative controls.
_EXPECTED_FINDING_COUNT = 8

#: Explicit, because ``Severity`` is a ``StrEnum`` and would otherwise sort as
#: CRITICAL, HIGH, INFO, LOW, MEDIUM. Kept as a literal so the test recomputes the
#: contract instead of importing the implementation's own table.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

#: Where each rule's sweep lives. Patching here rather than inside ``analyzer``
#: leaves the sweep free to organise itself however it likes, as long as it calls
#: each rule through its own module.
_SWEEP_PATHS = {
    "app.engine.utilization.detect_low_utilization": detect_low_utilization,
    "app.engine.privileged_usage.detect_rarely_used_privileged_permissions": (
        detect_rarely_used_privileged_permissions
    ),
    "app.engine.duplicate_identity.detect_duplicate_identities": (
        detect_duplicate_identities
    ),
    "app.engine.ghost_access.detect_ghost_access": detect_ghost_access,
}

_ALLOWED_IMPORT_ROOTS = frozenset(
    {"__future__", "collections", "collections.abc", "datetime", "typing", "app"}
)

#: Names whose presence in ``analyzer.py`` would mean it had taken on a dependency
#: the engine's purity forbids: a clock, a filesystem, user input, or randomness.
_IMPURE_NAMES = frozenset(
    {"open", "print", "input", "now", "utcnow", "today", "uuid4", "random"}
)


def _at(text: str) -> datetime:
    return AWARE.validate_python(text)


def _stub_rules(monkeypatch: pytest.MonkeyPatch, replacements: dict | None = None):
    """Replace all four sweeps, defaulting each to "finds nothing"."""
    replacements = replacements or {}
    for path in _SWEEP_PATHS:
        monkeypatch.setattr(path, replacements.get(path, lambda dataset, settings: []))


def _oracle_entries(persona: dict) -> list[dict]:
    """A persona's primary finding plus any it is expected to carry from a
    different rule."""
    return [persona["finding"], *persona.get("additional_findings", [])]


def _expected_pairs(oracle: dict) -> Counter:
    """(user, finding type) pairs the oracle expects, counting the negatives.

    ``NO_FINDING`` is excluded: it names the *absence* of a finding and is
    asserted separately, in :func:`test_every_persona_matches_its_oracle_entry`.
    """
    pairs: Counter = Counter()
    for persona in oracle["personas"]:
        for entry in _oracle_entries(persona):
            if entry["type"] != "NO_FINDING":
                pairs[(persona["user_id"], entry["type"])] += 1
    return pairs


def _empty_dataset() -> InMemoryDataset:
    """A dataset with no facts in it at all.

    Hand-built rather than a trimmed fixture, because the boundary being tested
    is "the sweep has nothing to work with", and a dataset assembled from real
    files would always have something.
    """
    return InMemoryDataset(
        users=(),
        identities=(),
        entitlements=(),
        slices=MappingProxyType({}),
        window=(_at(WINDOW_START), _at(WINDOW_END)),
        coverage_manifest=(),
        rejections=(),
        unattributable_actors=(),
        generated_at=_at(WINDOW_END),
    )


# --------------------------------------------------------------------------- #
# What the sweep returns
# --------------------------------------------------------------------------- #


def test_the_fixture_produces_exactly_the_expected_findings(dataset, settings, oracle):
    """The union of all four rules over the whole fixture set.

    The literal count is asserted alongside the oracle comparison so that the
    oracle itself changing is visible as a failure rather than absorbed by it.
    """
    findings = analyze(dataset, settings)

    assert len(findings) == _EXPECTED_FINDING_COUNT
    assert Counter((f.user_id, f.type.value) for f in findings) == _expected_pairs(oracle)


def test_every_persona_matches_its_oracle_entry(dataset, settings, oracle):
    """Each persona's finding, field for field, now that one call returns them all.

    The per-rule test modules assert this for the rule that owns each persona.
    Asserting it again here is not redundant: it is the check that the sweep
    returns the same findings those rules produce, rather than a filtered,
    merged or re-derived subset of them.
    """
    findings = analyze(dataset, settings)
    by_key = {(f.user_id, f.type.value): f for f in findings}

    for persona in oracle["personas"]:
        expected = [e for e in _oracle_entries(persona) if e["type"] != "NO_FINDING"]

        if not expected:
            carried = [f for f in findings if f.user_id == persona["user_id"]]
            assert carried == [], persona["user_id"]
            continue

        for entry in expected:
            key = (persona["user_id"], entry["type"])
            assert key in by_key, f"missing {key}"

            finding = by_key[key]
            assert finding.status.value == entry["status"]
            assert finding.severity.value == entry["severity"]
            assert finding.recommendation.value == entry["recommendation"]
            assert finding.evidence_completeness.value == entry["evidence_completeness"]


def test_the_signature_takes_a_dataset_and_settings_and_returns_findings():
    """The contract in ``engine/__init__.py`` and ``README.md``, pinned.

    Checked through ``get_type_hints`` rather than by comparing annotation
    strings, so a future ``from __future__ import annotations`` change or a
    ``TYPE_CHECKING`` import cannot make this pass while the real signature has
    drifted.
    """
    signature = inspect.signature(analyze)
    assert list(signature.parameters) == ["dataset", "settings"]

    for name in ("dataset", "settings"):
        assert signature.parameters[name].default is inspect.Parameter.empty

    hints = typing.get_type_hints(analyze)
    assert hints["dataset"] is InMemoryDataset
    assert hints["settings"] is Settings
    assert hints["return"] == list[Finding]


def test_the_result_equals_the_four_rule_sweeps_concatenated(dataset, settings):
    """The sweep is a concatenation, not a re-implementation.

    Compared as a multiset of ids *and* field for field, so that a sweep which
    returned the right findings with something altered in them -- a summary, a
    status, a timestamp -- fails here rather than silently becoming the thing
    the rest of the suite asserts against.
    """
    direct = [f for sweep in _SWEEP_PATHS.values() for f in sweep(dataset, settings)]
    analysed = analyze(dataset, settings)

    assert Counter(f.id for f in analysed) == Counter(f.id for f in direct)
    assert {f.id: f.model_dump() for f in analysed} == {
        f.id: f.model_dump() for f in direct
    }


def test_findings_are_ordered_by_user_then_severity_rank_then_id(dataset, settings):
    """A total, reproducible order -- and its two halves are separate claims.

    ``user_id`` first keeps one person's findings adjacent: Carol carries a
    CRITICAL ghost-access finding and a MEDIUM rarely-used-permission finding, and
    they are two facts about one human, not two humans. Severity-descending inside
    a person leads with the more consequential of them, which is also the order
    the oracle narrates her in.

    **Engine-authored, not oracle-derived.** The oracle file asserts no ordering.
    The severity rank in particular is a choice: sorting by `Severity` directly
    would order alphabetically by value and put INFO above MEDIUM. Marked here so
    that a future reader can tell a specification requirement from a presentation
    decision, and change the latter without thinking they are breaking the former.

    The expected order is recomputed from the findings themselves rather than
    compared against a hard-coded id list, so the test does not need rewriting
    every time the fixture set grows -- and it is a total order, because
    ``finding.id`` is unique, so no tie-break by iteration order is possible.
    """
    findings = analyze(dataset, settings)

    expected = sorted(
        findings, key=lambda f: (f.user_id, _SEVERITY_RANK[f.severity], f.id)
    )
    assert [f.id for f in findings] == [f.id for f in expected]

    carol = [f for f in findings if f.user_id == "u_carol"]
    assert len(carol) == 2, "the fixture set's one two-finding persona"
    assert [f.severity for f in carol] == [Severity.CRITICAL, Severity.MEDIUM]
    assert [f.type.value for f in carol] == [
        "GHOST_ACCESS",
        "RARELY_USED_PRIVILEGED_PERMISSION",
    ]


def test_analyze_is_re_exported_from_the_engine_package():
    """Importable from ``app.engine``, not only from ``app.engine.analyzer``.

    Checked dynamically rather than by importing it at module scope, because a
    module-scope import would turn a missing re-export into a collection error
    that takes the whole file down instead of failing one named test.
    """
    package = importlib.import_module("app.engine")
    assert getattr(package, "analyze", None) is analyze


# --------------------------------------------------------------------------- #
# Dispatch and uniqueness
# --------------------------------------------------------------------------- #


def _rule_ids_the_engine_defines() -> set[str]:
    """Every ``RULE_ID`` in the engine package, discovered rather than listed.

    Walked from the package's own modules so that adding a fifth rule module is
    enough to make :func:`test_every_rule_id_the_engine_defines_appears_in_the_output`
    fail until the sweep calls it. A hard-coded list of four would keep passing
    after a rule was added and never wired up, which is the bug the test exists
    to catch.
    """
    package = importlib.import_module("app.engine")
    rule_ids: set[str] = set()

    for module_info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"app.engine.{module_info.name}")
        rule_id = getattr(module, "RULE_ID", None)
        if isinstance(rule_id, str):
            rule_ids.add(rule_id)

    return rule_ids


def test_every_rule_id_the_engine_defines_appears_in_the_output(dataset, settings):
    """No rule exists that the sweep forgets to run.

    Assumes the fixture set is built so that every rule fires at least once,
    which is true today -- A four times, B twice, C once, D once -- and is itself
    a property worth pinning, because a rule that stopped firing on the fixture
    would otherwise disappear from the engine's coverage without a failure.
    """
    defined = _rule_ids_the_engine_defines()
    fired = {rid for f in analyze(dataset, settings) for rid in f.rules_triggered}

    assert defined, "expected the engine package to define at least one rule"
    assert fired == defined
    assert len(fired) == len(_SWEEP_PATHS)


def test_no_finding_id_or_evidence_id_is_duplicated(dataset, settings):
    """Uniqueness is asserted, never repaired.

    A sweep that "handled" duplicates by dropping one would pass every other test
    in this file while hiding a rule bug behind a missing finding. Evidence ids
    are checked in the same sweep because they are the ids a reviewer clicks
    through, and a collision there silently mis-attributes an evidence row to the
    wrong finding.
    """
    findings = analyze(dataset, settings)

    finding_ids = [f.id for f in findings]
    assert len(finding_ids) == len(set(finding_ids))

    evidence_ids = [e.evidence_id for f in findings for e in f.evidence]
    assert evidence_ids, "expected the fixture set to produce evidence"
    assert len(evidence_ids) == len(set(evidence_ids))


def test_two_rules_claiming_one_finding_id_raise_value_error(dataset, settings, monkeypatch):
    """A collision is a bug, and a bug must not be returned as a finding list.

    Two rules are made to return the same finding object, which is what a future
    rule set would do if two rules ever claimed one subject with one id scheme.
    The error must name the colliding id: a bare ``ValueError`` would leave a
    reader grepping the whole engine for where it came from.
    """
    clash = detect_low_utilization(dataset, settings)[0]

    _stub_rules(
        monkeypatch,
        {
            "app.engine.utilization.detect_low_utilization": lambda d, s: [clash],
            "app.engine.ghost_access.detect_ghost_access": lambda d, s: [clash],
        },
    )

    with pytest.raises(ValueError) as raised:
        analyze(dataset, settings)

    assert clash.id in str(raised.value)


# --------------------------------------------------------------------------- #
# Errors, timestamps, purity
# --------------------------------------------------------------------------- #


def test_a_failing_rule_propagates_its_exception(dataset, settings, monkeypatch):
    """A crashed rule must not look like a rule that found nothing.

    This is the run-time form of the argument that kept ``analyze()`` out of the
    package until the rule set was complete: a caller who receives a finding list
    cannot tell a complete sweep from a partial one, so the only safe thing to do
    with a failure is refuse to produce a list at all.
    """

    class RuleBlewUp(RuntimeError):
        pass

    def explode(dataset, settings):
        raise RuleBlewUp("rule failed")

    _stub_rules(
        monkeypatch, {"app.engine.ghost_access.detect_ghost_access": explode}
    )

    with pytest.raises(RuleBlewUp):
        analyze(dataset, settings)


def test_a_rules_created_at_is_never_restamped(dataset, settings, monkeypatch):
    """The sweep reads no clock, so it cannot stamp one.

    A rule is given a deliberately wrong timestamp: if the sweep re-stamped
    findings from settings, this value would come back replaced and the test would
    fail. The finding must come back equal field for field, which also rules out
    a sweep that copies findings while "normalising" them.
    """
    stamp = datetime(1999, 1, 1, tzinfo=UTC)
    odd = detect_low_utilization(dataset, settings)[0].model_copy(
        update={"created_at": stamp}
    )

    _stub_rules(
        monkeypatch,
        {"app.engine.utilization.detect_low_utilization": lambda d, s: [odd]},
    )

    findings = analyze(dataset, settings)

    assert [f.created_at for f in findings] == [stamp]
    assert [f.model_dump() for f in findings] == [odd.model_dump()]


def test_two_runs_produce_identical_findings_in_identical_order(dataset, settings):
    """Determinism is asserted across the whole list, not just its contents.

    Order is part of the answer: a reviewer comparing two runs of a review needs
    the same list, and a diff of two differently-ordered lists of the same
    findings is unreadable. Blueprint Rule 2 says "identical dataset in, identical
    findings out", and this is where that becomes a claim about this function.
    """
    first = analyze(dataset, settings)
    second = analyze(dataset, settings)

    assert [f.id for f in first] == [f.id for f in second]
    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


def test_analyze_does_not_mutate_the_dataset(dataset, settings):
    """The input is frozen and pure, and this is the test that says so.

    ``dataset_fingerprint()`` deliberately covers neither ``generated_at`` nor
    ``rejections``, so both are captured explicitly -- those are exactly the two
    dataset-level facts Rule C reaches for, and a sweep that "helpfully" filled
    in a missing ``generated_at`` would corrupt a fact it does not own without
    changing the fingerprint.
    """
    before = (
        dataset.dataset_fingerprint(),
        dataset.generated_at,
        dataset.rejections,
        dataset.identities,
        len(dataset.users),
    )

    analyze(dataset, settings)

    after = (
        dataset.dataset_fingerprint(),
        dataset.generated_at,
        dataset.rejections,
        dataset.identities,
        len(dataset.users),
    )
    assert before == after


def test_an_empty_dataset_produces_no_findings(settings):
    """No users is an empty answer, not an error.

    The sweep must not treat "nothing to analyse" as a failure. It also must not
    invent a dataset-level finding to say so -- a clean result and a silent one
    are the same thing here, and the personas, not the sweep, are where the
    distinction between "no findings" and "insufficient evidence" is drawn.
    """
    assert analyze(_empty_dataset(), settings) == []


def test_the_analyzer_module_imports_nothing_impure():
    """Purity, checked against the source rather than promised in a docstring.

    The engine's determinism rests on a rule being unable to reach a clock, a
    connection or a model. Imports are allow-listed and a handful of impure names
    are denied outright, so a ``datetime.now()`` or an ``open()`` added later
    fails here rather than producing findings that differ between runs.
    """
    module = importlib.import_module("app.engine.analyzer")
    source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "the engine uses absolute imports only"
            assert node.module is not None
            imported.add(node.module)

    assert imported, "expected the analyzer to import the rules it sweeps"

    def permitted(module_name: str) -> bool:
        return any(
            module_name == root or module_name.startswith(f"{root}.")
            for root in _ALLOWED_IMPORT_ROOTS
        )

    assert sorted(m for m in imported if not permitted(m)) == []

    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)

    assert sorted(called & _IMPURE_NAMES) == []


def test_no_finding_uses_language_its_persona_forbids(dataset, settings, oracle):
    """Rule 6, swept across the union rather than per rule.

    Two lists are applied. The global one is the contract's own rejected
    vocabulary -- ``unnecessary``, ``safe to remove``, ``automatically revoke``
    and the rest -- and the per-persona one is the oracle's ``must_not_say``,
    which names the words a specific finding must never be explained with. The
    second is the stricter of the two: Alice's zero usage must not be described
    as ``unused`` even though it demonstrably is, because that word is the first
    step on the road to "so remove it".

    Evidence descriptions are included, not just summaries. A finding whose
    summary is careful and whose evidence rows say "safe to delete" has still
    told a reviewer to delete something.
    """
    forbidden: dict[str, list[str]] = {
        persona["user_id"]: persona.get("must_not_say", [])
        for persona in oracle["personas"]
    }

    for finding in analyze(dataset, settings):
        haystack = " ".join(
            [finding.summary, finding.recommendation.value]
            + [e.description for e in finding.evidence]
        ).lower()

        for phrase in FORBIDDEN_CONCLUSION_PHRASES:
            assert phrase not in haystack, f"{finding.id} says {phrase!r}"

        for phrase in forbidden.get(finding.user_id, []):
            assert phrase not in haystack, f"{finding.id} says {phrase!r}"
