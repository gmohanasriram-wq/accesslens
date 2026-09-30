# Phase 2 — the deterministic engine

Phase 1 fixed the boundary; Phase 2 fills it in, one rule at a time.

## Status

| Rule | Module | State |
|---|---|---|
| D — ghost access | `ghost_access.py` | **implemented**, tested in `tests/test_rule_d.py` |
| A — privilege utilization | `utilization.py` | **implemented**, tested in `tests/test_rule_a.py` |
| B — rarely-used privileged permission | `privileged_usage.py` | **implemented**, tested in `tests/test_rule_b.py` |
| C — duplicate identity | `duplicate_identity.py` | **implemented**, tested in `tests/test_rule_c.py` |
| — the unified sweep | `analyzer.py` | **implemented**, tested in `tests/test_analyzer.py` |

Note the collision in the blueprint's own numbering. Blueprint §8's "Rule B" is
*low-usage* privileged access and §8's "Rule C" is break-glass protection; both
are the same computation as Rule A and are delivered by `utilization.py` (see
below). §16's matrix row "rarely used privileged permission" is a different
question about a capability *subset*, and that is `privileged_usage.py` — the
Rule B of this table, and of the task that specified it.

### Where the blueprint's Rules B and C went

The blueprint describes three privilege findings — low-privilege-usage (A),
low-usage privileged access (its "B") and break-glass protection (its "C") — as
three rules. They are one decision, and splitting them is how they come to
disagree: all three compare capabilities granted against capabilities observed,
and the difference is only which way the answer is allowed to lean.
`utilization.py` therefore answers all three at once, and the blueprint's
findings are emitted from it:

* `HIGH_PRIVILEGE_LOW_USAGE` — the review-required case (Bob);
* `PROTECTED_BREAK_GLASS` — the do-nothing case (Alice);
* `INSUFFICIENT_EVIDENCE` — the cannot-say case (Gina, Ivan).

`privileged_usage.py` is a genuinely different rule and is not a fourth branch
of that one. It asks whether the *dangerous subset* of a grant has ever been
exercised, which is a question about a set and has no ratio in it — Erin uses 9
of her 17 capabilities and has never once touched `IAM_WRITE`, `KMS_WRITE`,
`LOGS_WRITE`, `S3_DELETE`, `REPO_ADMIN` or `ORG_ADMIN`. It fires exactly where
the utilisation rule declines, so the two partition the space rather than
overlap in it, and it reports independently of the others: Carol carries a
`GHOST_ACCESS` finding and a `RARELY_USED_PRIVILEGED_PERMISSION` finding at the
same time, because they are two different facts about her.

`duplicate_identity.py` is a third kind of rule again, and the only one that reads
no activity at all. Henry holds two Okta accounts sharing one login; the
directory cannot say which of them is the one in use, so nothing he did can be
attributed to a single principal. Because the claim is about the directory and
not about telemetry, coverage gating has nothing to say about it — a truncated
CloudTrail export must not silence a directory defect.

## The entry point

```python
from app.engine import analyze

findings = analyze(dataset, settings)
```

`analyze()` lives in `analyzer.py` and is re-exported from the package. It is the
only supported way to obtain findings: calling a rule directly returns a list
that looks complete and is not, which is exactly the ambiguity that kept this
function out of the package until the rule set was finished. The rule modules
stay importable because a rule is tested in isolation by calling it, but that is
a test-time affordance rather than a production one.

Four things it pins, all of them places a sweep goes wrong quietly:

- **Ordered output.** Findings come back sorted by `(user_id, severity
  descending, finding.id)`. A review is read per person, so a person's findings
  stay together, worse-first. The severity rank is written out explicitly,
  because `Severity` is a `StrEnum` and orders alphabetically by value —
  `CRITICAL, HIGH, INFO, LOW, MEDIUM` — which is not the order anyone means. The
  oracle file asserts no ordering, so this is the engine's own presentation
  choice.
- **No deduplication.** Findings are per (rule, subject), not per person: Carol
  carries a ghost-access finding and a rarely-used-permission finding at once
  because they are two facts. Dropping a duplicate would turn a rule bug into a
  *missing* finding, so a colliding id raises `ValueError` naming both ids.
- **Errors propagate.** No `try`/`except`. A caught rule exception produces a
  partial list that looks complete — the same indistinguishability that made a
  premature `analyze()` dishonest.
- **No re-stamping.** Each rule sets `created_at` from `settings`; the sweep
  never touches it. Re-stamping would mutate rule-owned data and hide a rule
  that had stopped deriving its timestamp from configuration.

Execution order is A → B → C → D, fixed for reproducibility and carrying no
meaning: all four rules are pure functions of the same immutable dataset and
share no state, so no ordering can change the result. Each rule is called through
its own module, which keeps "which module owns which rule" visible at the call
site.

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
- `Settings.privileged_capabilities` — which capabilities are dangerous enough
  that never exercising one deserves a reviewer's attention. Also policy:
  "`S3_DELETE` is destructive" is a decision an organisation makes and must be
  able to revisit without a release. It is deliberately *not*
  `high_risk_entitlement_roles`, which classifies a role by name; this
  classifies a capability, so `REPO_ADMIN` means the same thing however it was
  granted.

## Definition of done for Phase 2

Every scenario in blueprint §16 produces its expected finding, the oracle file
is the assertion rather than a description, and the engine's own tests run with
no database in the loop. Reached in production through `analyze()`, which is the
only caller of each rule.
