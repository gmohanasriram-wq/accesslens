"""The unified sweep: ``analyze()``, the engine's only entry point.

Until now the four rules were called directly and concatenated by hand, because
a sweep over an incomplete rule set returns a *complete-looking* finding list
that silently omits a whole class of finding -- and a caller cannot tell "no
findings" from "that rule does not exist yet". The rule set is now complete, so
the concatenation moves in here where it can be tested rather than remembered.

The contract is one pure function::

    analyze(dataset: InMemoryDataset, settings: Settings) -> list[Finding]

Five decisions shape it, and each one is a place where a sweep can go wrong
quietly.

**Order of execution is A, B, C, D, and it is not observable.** All four rules
are pure functions of the same immutable dataset and share no state, so no
ordering can change the result. The order is fixed for reproducibility, not
because it carries meaning -- a test asserting that one rule was *called* before
another would be asserting nothing, so the tests assert the output instead.

**The output order is a total order, and it is presentation policy.** Findings
are sorted by ``(user_id, severity rank descending, finding.id)``. User-major
keeps one person's findings adjacent, because a review is read per person and a
person who carries two findings carries two facts about themselves; scattering
them across the list would invite a reviewer to count them as two people's
problems. Severity-descending inside a person leads with the more consequential
fact. The severity rank is spelled out explicitly because ``Severity`` is a
``StrEnum`` and therefore orders *alphabetically* by value -- ``CRITICAL, HIGH,
INFO, LOW, MEDIUM`` -- which is not the order anyone means. The oracle file
asserts no ordering at all, so this half of the contract is the engine's own
choice, marked as such in the tests.

**Multiple findings for one person are preserved, and nothing is deduplicated.**
Findings are per (rule, subject), not per person: Carol carries a ghost-access
finding and a rarely-used-privileged-permission finding at the same time because
they are two different facts about her. Merging them would destroy the
independence the rules were built to have, and dropping a duplicate id would
turn a rule bug -- two rules claiming one finding -- into a *missing* finding,
which is indistinguishable from a rule that found nothing. So a collision is
raised as a ``ValueError`` naming both ids, loudly, at the boundary.

**Rule errors propagate.** There is no ``try``/``except`` here on purpose. A rule
that raises is a bug, and catching it would produce a partial finding list that
looks complete -- precisely the failure mode this module exists to prevent. The
same reasoning that kept ``analyze()`` out of the package until the rule set was
finished applies to swallowing an exception at run time.

**Each rule stamps its own ``created_at`` from ``settings``, and this function
never touches it.** Re-stamping would mutate rule-owned data and would mask a
rule that had stopped deriving its timestamp from settings. It is also what
keeps this function pure: no clock is read here, so two runs over one dataset
produce findings that compare equal field for field, including their timestamps.
"""

from __future__ import annotations

from app.core.config import Settings
from app.core.enums import Severity
from app.engine import (
    duplicate_identity,
    ghost_access,
    privileged_usage,
    utilization,
)
from app.ingestion import InMemoryDataset
from app.schemas.domain.finding import Finding

__all__ = ["analyze"]


#: Written out rather than taken from ``Severity``'s own order. ``Severity`` is a
#: ``StrEnum``, so ``sorted(key=severity)`` orders alphabetically by value --
#: ``CRITICAL, HIGH, INFO, LOW, MEDIUM`` -- which puts INFO above MEDIUM and is
#: not the order anyone means. Ranking worst-first makes higher severity sort
#: earlier under a plain ascending sort.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _reject_duplicate_ids(findings: list[Finding]) -> None:
    """Refuse to return a list in which two findings claim the same id.

    Findings are keyed by id -- a dossier is a lookup -- so a collision forked
    from two rules claiming one subject would mean one of them silently
    mis-attributing evidence or vanishing. Raising is the only honest handling:
    the alternative, dropping one, converts a rule bug into a *missing* finding,
    which no reader can tell from a rule that found nothing.

    The message names the id, because a bare ``ValueError`` from a sweep over
    four rules leaves a reader grepping the whole engine for its origin.
    """
    seen: set[str] = set()

    for finding in findings:
        if finding.id in seen:
            raise ValueError(
                f"two findings share the id {finding.id!r}. Findings are keyed by "
                "id, so returning both would silently drop or mis-attribute one; "
                "the collision is a rule bug, not a result to be merged away."
            )
        seen.add(finding.id)


def analyze(dataset: InMemoryDataset, settings: Settings) -> list[Finding]:
    """Run every rule over the dataset and return one ordered finding list.

    The only supported way for a caller to obtain findings. Rules are otherwise
    unreachable in production -- calling one directly would return a list that
    looks complete and is not.

    Pure and deterministic: the same dataset and settings produce the same
    findings in the same order on every run and on every machine. No database,
    no HTTP client, no clock, no model. See the module docstring for the
    ordering, deduplication and error-handling decisions this pins.

    Each rule is called through its own module rather than through a name bound
    into this one, so that which module owns which rule stays visible at the call
    site -- and so a test can replace one rule without reaching inside this
    function.
    """
    findings: list[Finding] = []

    # A -> B -> C -> D. The order is fixed for reproducibility and carries no
    # meaning: all four rules are pure functions of the same immutable dataset
    # and share no state, so no ordering can change the result.
    findings.extend(utilization.detect_low_utilization(dataset, settings))
    findings.extend(
        privileged_usage.detect_rarely_used_privileged_permissions(dataset, settings)
    )
    findings.extend(duplicate_identity.detect_duplicate_identities(dataset, settings))
    findings.extend(ghost_access.detect_ghost_access(dataset, settings))

    _reject_duplicate_ids(findings)

    # Total order, so no tie-break by iteration order is possible: finding.id is
    # unique, which the check above has just established. User-major keeps one
    # person's findings adjacent -- Carol carries two facts about herself and
    # must not be read as two people's problems.
    return sorted(
        findings,
        key=lambda finding: (
            finding.user_id,
            _SEVERITY_RANK[finding.severity],
            finding.id,
        ),
    )
