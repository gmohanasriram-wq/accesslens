# Phase 4 — the AI layer (not yet implemented)

This package is intentionally empty. It exists in Phase 1 only to mark the
boundary and to record what the boundary is for.

**One sentence:** the AI explains findings; it does not make them.

## Placement

```
raw data  ->  ingestion  ->  InMemoryDataset  ->  engine (deterministic)  ->  Finding
                                                                               |
                                                          ai (explanation)  <--+
                                                                               |
                                                             API  ->  reviewer -> human approves
```

The model sits to the *right* of the arrow that produces findings, and there is
no arrow back. It can read a `Finding`; it cannot write one, rank one, suppress
one, or change its severity. It is also not on the path to any action: the
reviewer is, and the reviewer is a person.

## What it will be asked to do

- Turn a `Finding` and its `Evidence` list into prose a non-specialist can read.
- Summarise a ghost-access timeline (`HR termination -> IdP disable -> activity`)
  as a sequence, which is how Carol's finding has to be rendered to be
  convincing.
- Draft the questions an investigator should ask — "was this token rotated?",
  "who else held the break-glass role?" — without answering them.
- Explain *why* a user is `INSUFFICIENT_EVIDENCE`, in terms of the coverage gaps
  the engine recorded.

## What it must never do

Enforced by the denylist in `app/ai/__init__.py`, applied to generated text
before display:

1. No revocation or removal instructions — a human approves every
   security-changing action.
2. No conclusion about a user whose coverage is not `COMPLETE` — missing
   evidence is not safe.
3. No severity or risk level the finding does not already carry — the model does
   not re-grade the deterministic result.
4. No claim that access *is* necessary — necessity is an owner's judgement.

A denylist, not an allowlist, because explanation is open-ended; it is applied
after generation so it holds whatever the model was asked.

## Why not let it decide

Not a claim that a model would get it wrong. A finding has to be reproducible
and defensible to an auditor months later, and the engine can be re-run to get
the same answer while a generation cannot. Determinism is the product feature;
the model is the accessibility layer on top of it.

## Verification for Phase 4

Any test suite here has to include a case where a persona with a coverage gap is
put in front of the layer and the output is asserted **not** to contain a
conclusion — the shape of failure that matters is a confident sentence about a
user we could not see.
