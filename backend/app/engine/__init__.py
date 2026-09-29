"""The deterministic security engine.

Empty by design in Phase 1. This module is the boundary, and the boundary is
the part that had to be fixed first: the interface below is what Phase 2
implements, and what Phase 1's fixtures and test oracles are written against.

The contract::

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
