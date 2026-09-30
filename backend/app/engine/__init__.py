"""The deterministic security engine.

Phase 1 fixed the boundary; Phase 2 is filling it in, one rule at a time. Rule D
(ghost access) lives in :mod:`app.engine.ghost_access`, tested in
``tests/test_rule_d.py``. Rule A -- privilege utilisation, which also emits the
low-usage and break-glass findings the blueprint assigns to Rules B and C --
lives in :mod:`app.engine.utilization`, tested in ``tests/test_rule_a.py``.

``analyze()`` is deliberately still not defined here, because the rule set is
still incomplete: the rarely-used-privileged-permission and duplicate-identity
findings have no implementation, and a sweep that quietly omitted them would be
indistinguishable from a sweep that found nothing else. The caller of an access
review must never have to guess which of those they are looking at. See
``README.md`` in this package for what exists, what does not, and why.

The contract, once all four rules exist::

    analyze(dataset: InMemoryDataset, settings: Settings) -> list[Finding]

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

__all__: list[str] = []
