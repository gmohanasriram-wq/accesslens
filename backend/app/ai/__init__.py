"""The AI explanation layer.

Empty by design in Phase 1. Phase 4 fills it. The boundary is documented now
because it is the one boundary in this system that must not drift: an AI that
can quietly become the decision-maker turns an auditable access review into an
unaccountable one.

What this layer is for, once it exists: explaining a finding a human is already
looking at, summarising the evidence behind it, and drafting the questions an
investigator should ask next. Investigation support, not adjudication.

What it must never do:

* **Decide.** It does not produce, rank, suppress or modify a finding. Findings
  come from :mod:`app.engine` and from nowhere else.
* **Change access.** Nothing here revokes, disables, or schedules anything. The
  blueprint keeps a human in the loop for every security-changing action, and no
  code path in this package will be an exception.
* **Assert an absence it cannot see.** "This user has no unused access" is not a
  safe sentence to generate from data with coverage gaps, and the model will not
  know that unless the prompt refuses to hide it.

**The output denylist.** Any AI-produced text is checked, before display, for
the following, and rejected if present:

| Forbidden output | Why |
| --- | --- |
| Any revocation or removal instruction | Rules 5, 6 — a human approves every security-changing action, and "unused" is not "unnecessary" |
| A conclusion about a user whose coverage is not `COMPLETE` | Rule 7 — missing evidence is not safe |
| A severity or risk level not already on the finding | Rule 3 — the model does not get to re-grade the deterministic result |
| A statement that access *is* necessary | The engine can show usage; necessity is an owner's judgement, not an inference |

The list is a denylist rather than an allowlist because explanation is
open-ended by nature and cannot be enumerated. It is enforced on the way out,
after generation, so it holds regardless of what the model was asked or how it
answered.

**Why the model is not on the decision path at all.** Not because it would be
unreliable in principle, but because a finding has to be reproducible and
defensible to an auditor months later. A reviewer can re-run the engine and get
the same answer. The same cannot be said of a sampled generation, so the
deterministic engine stays the only source of findings and this layer stays
downstream of it.
"""

from __future__ import annotations

__all__: list[str] = []
