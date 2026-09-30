"""The deterministic security engine.

Phase 1 fixed the boundary; Phase 2 is filling it in, one rule at a time. Rule D
(ghost access) lives in :mod:`app.engine.ghost_access`, tested in
``tests/test_rule_d.py``. Rule A -- privilege utilisation, which also emits the
low-usage and break-glass findings the blueprint assigns to its "Rules B and C"
-- lives in :mod:`app.engine.utilization`, tested in ``tests/test_rule_a.py``.
Rule B (a rarely-exercised privileged capability, which is a different question
from low utilisation and fires exactly where Rule A declines) lives in
:mod:`app.engine.privileged_usage`, tested in ``tests/test_rule_b.py``. Rule C
(duplicate identity, a directory fact rather than a usage one) lives in
:mod:`app.engine.duplicate_identity`, tested in ``tests/test_rule_c.py``.

The rule set is now complete, so the sweep it was waiting for exists::

    analyze(dataset: InMemoryDataset, settings: Settings) -> list[Finding]

:func:`analyze` lives in :mod:`app.engine.analyzer` and is re-exported here. It
is the only supported way to obtain findings. Until it existed the four rules
were concatenated by hand by their callers, which meant a caller could not tell
a complete finding list from one that was missing a whole class of finding --
the argument for leaving it out is the argument for it being the single entry
point now that it can honestly be complete.

Individual rule modules stay importable, because a rule is tested in isolation
by calling it. That is a test-time affordance, not a production one.

Why it is a pure function, and why that is a security property rather than a
style preference:

* **Deterministic.** Same dataset, same findings, every time. A rule that could
  read the clock, the database or the network could produce a different answer
  from identical facts, and a finding whose conclusion cannot be reproduced is
  not evidence.
* **Independently testable.** With no database and no HTTP in scope, a rule is
  tested by constructing a dataset and asserting on findings. No fixtures, no
  mocks, no session. Blueprint Rule 2 ("detection logic must be deterministic
  and independently testable") is satisfied structurally rather than by
  discipline.
* **The AI cannot reach the decision.** Phase 4's layer consumes findings; it is
  not on the path that produces them. Rule 3 holds because there is no route
  from this module to a model.

What the engine must consult before concluding anything about usage: an
``ActivitySlice`` carries its own coverage, and
:attr:`~app.schemas.domain.activity.ActivitySlice.usage_observation` returns
``UNKNOWN`` unless coverage is ``COMPLETE``. A rule that branches on
``NONE_OBSERVED`` therefore cannot match a user whose telemetry never arrived --
Rule 7 ("missing evidence must not be treated as safe") is enforced by the data
model, not remembered by each detector.

What the engine must never do:

* recommend revoking access (:class:`~app.core.enums.Recommendation` deliberately
  has no revoke-like member -- Rule 6, "unused is not unnecessary", made
  unrepresentable rather than merely discouraged);
* treat ``NONE_OBSERVED`` as evidence of redundancy when the entitlement is
  protected (Alice's break-glass role is *supposed* to be unused);
* conclude anything at all from an ``UNKNOWN`` observation.

Phase 2 implements the rule set against the oracles in
``tests/fixtures/oracles/``.
"""

from __future__ import annotations

from app.engine.analyzer import analyze

__all__: list[str] = ["analyze"]
