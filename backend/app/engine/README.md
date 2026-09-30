# Phase 2 — the deterministic engine

Phase 1 fixed the boundary; Phase 2 fills it in, one rule at a time.

## Status

| Rule | Module | State |
|---|---|---|
| D — ghost access | `ghost_access.py` | **implemented**, tested in `tests/test_rule_d.py` |
| A — privilege utilization | `utilization.py` | **implemented**, tested in `tests/test_rule_a.py` |
| B — low-usage privileged access | — | finding behaviour delivered by Rule A (see below) |
| C — break-glass protection | — | finding behaviour delivered by Rule A (see below) |

### Where Rules B and C went

The blueprint describes three privilege findings — low-privilege-usage (A),
rarely-used privileged permission (B) and break-glass protection (C) — as three
rules. They are one decision, and splitting them is how they come to disagree:
all three compare capabilities granted against capabilities observed, and the
difference is only which way the answer is allowed to lean. `utilization.py`
therefore answers all three at once, and the blueprint's B and C *findings* are
emitted from it:

* `HIGH_PRIVILEGE_LOW_USAGE` — the review-required case (Bob);
* `PROTECTED_BREAK_GLASS` — the do-nothing case (Alice);
* `INSUFFICIENT_EVIDENCE` — the cannot-say case (Gina, Ivan).

Not implemented, and deliberately not quietly folded in: Erin's
`RARELY_USED_PRIVILEGED_PERMISSION` (a per-permission judgement, a different
unit of analysis from the capability sets this rule compares) and Henry's
`DUPLICATE_IDENTITY` (an identity-resolution finding, not a usage one).

**`analyze()` is still deliberately absent, and its absence is still the honest
answer.** The contract below describes the finished engine. Writing it now would
produce a function that returns a *complete-looking* finding list which silently
omits the Erin and Henry findings above — and a caller cannot tell "no findings"
from "that rule does not exist yet". The rules are therefore called directly:

```python
from app.engine.ghost_access import detect_ghost_access
from app.engine.utilization import detect_low_utilization

findings = detect_ghost_access(dataset, settings) + detect_low_utilization(
    dataset, settings
)
```

`analyze()` lands when the rule set is complete, and it becomes the only caller
of each rule.

## The contract

```python
def analyze(dataset: InMemoryDataset, settings: Settings) -> list[Finding]: ...
```

Pure. No database session, no HTTP client, no clock. Everything a rule may
consider is reachable from `dataset`; everything that decides how strict a rule
is comes from `settings`.

## The rules this design has to keep

These come from the blueprint and are the reason the contract looks the way it
does. They are restated here because Phase 2 is where they get broken by
accident.

1. **Python decides.** The engine produces findings. Nothing else does.
2. **Deterministic and independently testable.** Identical dataset in, identical
   findings out — across processes and across runs.
3. **The AI does not decide.** It is not called from here.
4. **Coverage gates usage.** `ActivitySlice.usage_observation` returns `UNKNOWN`
   unless coverage is `COMPLETE`. Branch on `NONE_OBSERVED`, never on "no
   events" — those are different questions and only one of them is answerable
   from an empty list.
5. **Missing evidence is not safe.** A user whose telemetry never arrived gets
   `INSUFFICIENT_EVIDENCE`, not a clean result. Ivan's malformed timestamp and
   Gina's missing proxy export are the fixtures that prove it.
6. **Unused is not unnecessary.** `Recommendation` has no revoke-like member, and
   `Finding.summary` rejects a list of forbidden conclusion phrases at
   validation time. Alice's break-glass role must survive an access review
   untouched *even though* we can prove she never used it — that case is the
   sharpest test in the suite, because the evidence genuinely supports "unused"
   and the answer must still not be "remove it".
7. **Denied activity is not usage.** `ActivityEvent.denied` marks a call the
   source rejected. It is evidence the credential was live; it is not evidence
   the entitlement was used. Count only successful events.

## What Phase 2 consumes

- `tests/fixtures/oracles/` — the expected finding set per persona. Write the
  rules against these; they are the specification, and they were written before
  the engine so that they can fail honestly.
- `Settings.low_utilization_threshold` and
  `Settings.min_observed_events_for_confidence` — the thresholds, in config
  rather than in code, so a reviewer can see and change them without a release.
- `Settings.protected_role_patterns` / `always_protected_roles` — break-glass
  classification is policy, and policy is configuration.

## Definition of done for Phase 2

Every scenario in blueprint §16 produces its expected finding, the oracle file
is the assertion rather than a description, and the engine's own tests run with
no database in the loop.
