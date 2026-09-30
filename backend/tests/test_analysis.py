"""The findings surface: what ``analyze()`` produces, as HTTP.

Phase 2 built the engine and left it unreachable. ``analyze()`` is called by
tests and by nothing else, so a reviewer cannot see a finding, and the whole
product is a Python function. These tests describe the two routes that close
that gap, before either exists.

**What is being pinned, and why each part is a place to get it wrong:**

``GET /api/analysis`` — the review queue.

* ``content_hash``, ``dataset_fingerprint``, ``analysis_as_of``,
  ``window_start``, ``window_end``, ``rejections`` — the provenance a reviewer
  needs to *reproduce* the run and to defend it later. A findings page without
  these is a screenshot; with them it is a citation. The asset that makes this
  worth asserting is that ``content_hash`` and ``analysis_as_of`` are the
  *same values* ``/api/personas`` reports: two views of one dataset must not be
  able to disagree about which dataset they are describing.
* ``findings`` — every finding ``analyze()`` returned, in ``analyze()``'s own
  order, each carrying its subject's display fields and an ``evidence_count``.
  The order is asserted because ``analyze()`` went to the trouble of defining a
  total order (user-major, severity-descending) as presentation policy; a route
  that re-sorted or grouped would silently discard that decision.
* **No evidence payload.** The list is a queue; the dossier is the record.
  Carrying 60 evidence rows in the queue would make the list's contract depend
  on the detail's, so ``evidence_count`` is the only thing that crosses.

``GET /api/analysis/findings/{finding_id}`` — the dossier.

* ``finding`` — the *domain* ``Finding``, evidence included. Not a copy, not a
  renamed projection: the engine's vocabulary is what an auditor reads, and a
  DTO layer here would create a second spelling of every field and a place for
  the two to drift.
* ``subject`` — the ``PersonaSummary`` ``/api/personas`` already returns. The
  forensic timeline's cast (identities, entitlements, coverage, gaps) already
  exists; the dossier reuses it rather than inventing a fourth shape.
* ``related_findings`` — the same person's other findings, as summaries. Carol
  carries two facts about herself and the dossier must not imply she carries
  one.

**What these tests deliberately do not assert.** No field is renamed, so the
assertions read the engine's own spelling (``severity``, ``status``,
``evidence_completeness``, ``rules_triggered``). Nothing is asserted about
where findings are stored, because they are not stored: they are derived from
an immutable dataset, and a persisted copy could only go stale or disagree with
``analyze()``. One test below is an explicit guard on that choice.

**The failure mode these tests exist to prevent** is not "the endpoint 500s".
It is an endpoint that returns a plausible list which is missing a whole class
of finding, or a partial dossier that looks complete. So the assertions are
mostly *bijections*: eight findings, eight dossiers, every dossier reachable
from the list, every exhibit present, no id duplicated anywhere.
"""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import session_scope
from app.models.finding import EvidenceRow, FindingRow
from app.schemas.domain.finding import FORBIDDEN_CONCLUSION_PHRASES

#: The fixture population's finding count, written out so a rule that stops
#: firing shows up as a changed number rather than as a quietly shorter list.
EXPECTED_FINDING_COUNT = 8

#: ``Severity`` is a ``StrEnum`` and therefore orders *alphabetically* by value
#: -- ``CRITICAL, HIGH, INFO, LOW, MEDIUM`` -- which is not the order anyone
#: means. ``analyze()`` ranks worst-first; this is a copy of that ranking, so a
#: route that re-sorts by severity value is caught rather than accommodated.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_FORBIDDEN_UI_LANGUAGE = FORBIDDEN_CONCLUSION_PHRASES


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _analysis(client: TestClient) -> dict:
    response = client.get("/api/analysis")
    assert response.status_code == 200, response.text
    return response.json()


def _findings(client: TestClient) -> list[dict]:
    return _analysis(client)["findings"]


def _by_user(findings: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        grouped.setdefault(finding["user_id"], []).append(finding)
    return grouped


def _persona(client: TestClient, username: str) -> dict:
    body = client.get("/api/personas").json()
    return next(p for p in body["personas"] if p["username"] == username)


def _dossier(client: TestClient, finding_id: str) -> dict:
    response = client.get(f"/api/analysis/findings/{finding_id}")
    assert response.status_code == 200, response.text
    return response.json()


def _expected_order(findings: list[dict]) -> list[str]:
    return [
        finding["id"]
        for finding in sorted(
            findings,
            key=lambda f: (f["user_id"], SEVERITY_RANK[f["severity"]], f["id"]),
        )
    ]


# --------------------------------------------------------------------------- #
# the review queue
# --------------------------------------------------------------------------- #


def test_analysis_returns_every_finding_the_engine_produces(client: TestClient) -> None:
    """The count is asserted, not merely "some findings came back".

    A sweep that silently drops one rule's output is the failure this whole
    module exists to make visible, and it looks exactly like a smaller list.
    """
    findings = _findings(client)

    assert len(findings) == EXPECTED_FINDING_COUNT
    assert len({finding["id"] for finding in findings}) == EXPECTED_FINDING_COUNT, (
        "findings are keyed by id; a duplicate makes one of them unreachable"
    )


def test_analysis_agrees_with_the_oracle_persona_by_persona(
    client: TestClient, oracle: dict
) -> None:
    """The HTTP surface reports what the oracle says, or one of them is wrong.

    The oracle is the written specification and predates the engine, so a
    mismatch here is a mismatch with the requirement rather than with the code.
    """
    grouped = _by_user(_findings(client))

    for expected in oracle["personas"]:
        primary = expected["finding"]
        if primary["type"] == "NO_FINDING":
            continue

        actual = grouped.get(expected["user_id"], [])
        matching = [f for f in actual if f["type"] == primary["type"]]
        assert matching, (
            f"{expected['username']} should carry {primary['type']} over HTTP"
        )

        finding = matching[0]
        for field in ("status", "severity", "recommendation", "evidence_completeness"):
            assert finding[field] == primary[field], (
                f"{expected['username']}.{field}: {finding[field]!r} != {primary[field]!r}"
            )


def test_analysis_carries_the_provenance_needed_to_reproduce_the_run(
    client: TestClient,
) -> None:
    """Findings without their window and hash are an anecdote, not evidence."""
    body = _analysis(client)
    personas = client.get("/api/personas").json()

    assert body["content_hash"] == personas["content_hash"], (
        "two views of one dataset must not disagree about which dataset it is"
    )
    assert body["analysis_as_of"] == personas["analysis_as_of"]
    assert body["window_end"] == body["analysis_as_of"]
    assert body["window_start"] < body["window_end"]
    assert body["dataset_fingerprint"], (
        "a finding has to cite an exact revision of the facts, and the content "
        "hash names the input files rather than the normalized result"
    )
    assert body["rejections"] == 3, (
        "the review surface must state how much input was discarded, or a "
        "reviewer cannot tell a clean window from a partial one"
    )


def test_analysis_keeps_the_engines_ordering(client: TestClient) -> None:
    """User-major, severity-descending, id. Presentation policy, asserted.

    Re-sorting this in the API -- by severity across everyone, say -- would put
    one person's two findings in two places and invite a reviewer to count them
    as two people's problems.
    """
    findings = _findings(client)

    assert [f["id"] for f in findings] == _expected_order(findings)


def test_the_queue_leads_with_the_worst_fact_about_each_person(
    client: TestClient,
) -> None:
    """Carol's critical finding comes before her medium one."""
    carol = _by_user(_findings(client))["u_carol"]

    assert len(carol) == 2, "carol carries two facts about herself"
    assert [f["severity"] for f in carol] == ["CRITICAL", "MEDIUM"]


def test_a_queue_row_carries_its_subject_and_exhibit_count(client: TestClient) -> None:
    """The queue is read per person, so the person travels with the row."""
    findings = _findings(client)
    personas = {p["id"]: p for p in client.get("/api/personas").json()["personas"]}

    for finding in findings:
        subject = finding["subject"]

        assert subject["id"] == finding["user_id"]
        assert subject["username"] == personas[finding["user_id"]]["username"]
        assert subject["name"]
        assert subject["department"]
        assert subject["employment_status"]

        assert finding["evidence_count"] >= 1, (
            "a finding with no exhibit is a conclusion without evidence"
        )


def test_the_queue_does_not_carry_the_evidence_payload(client: TestClient) -> None:
    """The list is a queue. Shipping the record here would make it the record."""
    for finding in _findings(client):
        assert "evidence" not in finding


def test_a_summary_does_not_rename_the_engines_vocabulary(client: TestClient) -> None:
    """The wire format keeps the engine's spelling, so there is one name per fact.

    A DTO layer that mapped ``type`` to ``finding_type`` or ``severity`` to
    ``risk`` would mean the dossier and the queue could disagree about a field
    without anything failing.
    """
    engine_fields = set(importlib.import_module("app.schemas.domain.finding").Finding.model_fields)
    subjects_and_counts = {"subject", "evidence_count"}

    for finding in _findings(client):
        extra = set(finding) - engine_fields - subjects_and_counts
        assert not extra, f"the queue invented fields the engine does not have: {extra}"

        assert isinstance(finding["type"], str), "enums must serialise as strings"
        assert isinstance(finding["rules_triggered"], list)


# --------------------------------------------------------------------------- #
# the dossier
# --------------------------------------------------------------------------- #


def test_a_dossier_carries_the_full_finding_with_its_exhibits(
    client: TestClient,
) -> None:
    bob = next(f for f in _findings(client) if f["subject"]["username"] == "bob.chen")
    dossier = _dossier(client, bob["id"])

    assert dossier["finding"]["id"] == bob["id"]
    assert dossier["finding"]["summary"]
    assert dossier["finding"]["recommendation"] == bob["recommendation"]
    assert dossier["finding"]["rules_triggered"], (
        "an auditor has to be able to name the control that fired"
    )

    evidence = dossier["finding"]["evidence"]
    assert len(evidence) == bob["evidence_count"]
    assert evidence, "a high-privilege low-usage finding rests on counted events"
    for item in evidence:
        assert item["evidence_id"]
        assert item["kind"]
        assert item["source"]
        assert item["description"]


def test_a_dossier_carries_the_subject_the_finding_is_about(
    client: TestClient,
) -> None:
    """The dossier restates the person, using the shape /api/personas already returns."""
    bob = next(f for f in _findings(client) if f["subject"]["username"] == "bob.chen")
    dossier = _dossier(client, bob["id"])
    subject = dossier["subject"]

    assert subject["id"] == bob["user_id"]
    assert subject["username"] == "bob.chen"
    assert subject["identities"], "the identities are half of the ghost-access story"
    assert subject["entitlements"], "the grant is what the finding is about"
    assert subject["activity"]["coverage"] == _persona(client, "bob.chen")["activity"]["coverage"]


def test_a_dossier_lists_the_persons_other_findings(client: TestClient) -> None:
    """Carol has two facts about herself; opening one must not hide the other."""
    carol = _by_user(_findings(client))["u_carol"]
    first, second = carol[0], carol[1]

    dossier = _dossier(client, first["id"])
    related = dossier["related_findings"]

    assert [f["id"] for f in related] == [second["id"]]
    assert first["id"] not in [f["id"] for f in related], (
        "a finding is not related to itself"
    )


def test_every_finding_in_the_queue_has_a_reachable_dossier(client: TestClient) -> None:
    """A bijection between the list and the detail.

    This is the check that catches a summary/detail drift: the queue promising
    five exhibits and the dossier showing three is a disagreement about the
    same finding.
    """
    for finding in _findings(client):
        dossier = _dossier(client, finding["id"])

        assert dossier["finding"]["id"] == finding["id"]
        assert len(dossier["finding"]["evidence"]) == finding["evidence_count"], (
            f"{finding['id']}: queue said {finding['evidence_count']} exhibits"
        )


def test_no_exhibit_is_claimed_by_two_findings(client: TestClient) -> None:
    """Findings are independent records; shared exhibits would blur which is which."""
    seen: list[str] = []
    for finding in _findings(client):
        seen.extend(
            item["evidence_id"] for item in _dossier(client, finding["id"])["finding"]["evidence"]
        )

    assert len(seen) == len(set(seen))
    assert len(seen) == 60, "the fixture's evidence count, written down"


def test_an_unknown_finding_id_is_a_404_not_an_empty_dossier(
    client: TestClient,
) -> None:
    """A missing record must not render as a finding with nothing to show."""
    response = client.get("/api/analysis/findings/f_does_not_exist")

    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# what the dossier must never say
# --------------------------------------------------------------------------- #


def test_no_finding_over_http_uses_language_the_evidence_cannot_support(
    client: TestClient, oracle: dict
) -> None:
    """The forbidden-phrase guard, applied to everything the API returns.

    ``Finding.summary`` is validated at construction, but ``recommendation`` and
    ``Evidence.description`` are not, and a dossier renders all three. Alice's
    case is the one that matters: her evidence genuinely supports "unused", and
    the correct answer is still that nothing should be removed.
    """
    rendered: list[str] = []
    for finding in _findings(client):
        dossier = _dossier(client, finding["id"])["finding"]
        rendered.append(dossier["summary"])
        rendered.append(str(dossier["recommendation"]))
        rendered.extend(item["description"] for item in dossier["evidence"])

    for text in rendered:
        lowered = text.lower()
        for phrase in _FORBIDDEN_UI_LANGUAGE:
            assert phrase not in lowered, f"{phrase!r} appeared in {text!r}"


def test_the_oracles_must_not_say_list_is_honoured_over_http(
    client: TestClient, oracle: dict
) -> None:
    """Each persona's own forbidden words, applied to its own dossier.

    Alice's ``must_not_say`` is the sharpest constraint in the fixture set: her
    evidence genuinely supports "unused" and the answer must still not be
    "remove". Asserting it here means a wording change in the engine or in a
    template is caught at the boundary a reviewer actually reads.
    """
    grouped = _by_user(_findings(client))

    for expected in oracle["personas"]:
        forbidden = expected.get("must_not_say")
        if not forbidden:
            continue

        for finding in grouped.get(expected["user_id"], []):
            dossier = _dossier(client, finding["id"])["finding"]
            text = " ".join(
                [dossier["summary"], str(dossier["recommendation"])]
                + [item["description"] for item in dossier["evidence"]]
            ).lower()

            for word in forbidden:
                assert word.lower() not in text, (
                    f"{expected['username']}'s dossier says {word!r}: {text!r}"
                )


# --------------------------------------------------------------------------- #
# the architecture the surface must not break
# --------------------------------------------------------------------------- #


def test_the_analysis_route_calls_analyze_rather_than_re_deriving_it(
    client: TestClient, monkeypatch
) -> None:
    """``analyze()`` is the source of truth, and the route must go through it.

    An API that reached for the rule modules directly -- or re-implemented a
    threshold -- would be a second opinion about security, and the two would
    eventually disagree with nothing failing.
    """
    module = importlib.import_module("app.api.v1.analysis")

    calls: list[object] = []
    real = module.analyze

    def spy(dataset, settings):
        calls.append(dataset)
        return real(dataset, settings)

    monkeypatch.setattr(module, "analyze", spy)

    assert client.get("/api/analysis").status_code == 200
    assert len(calls) == 1, "the findings route did not obtain its findings from analyze()"

    calls.clear()
    finding_id = _findings(client)[0]["id"]
    assert client.get(f"/api/analysis/findings/{finding_id}").status_code == 200
    assert calls, "the dossier is findings too, and must come from the same sweep"


def test_findings_are_derived_and_never_written_to_the_database(client: TestClient, ingesting) -> None:
    """The engine's output is a pure function of the dataset, not a row.

    Persisting findings would create a second copy that can go stale the moment
    the fixtures change, and a reviewer reading the table would have no way to
    tell which revision of the facts it was computed from. The tables exist from
    Phase 1 and stay empty on purpose.
    """
    factory, _report, _dataset = ingesting

    with session_scope(factory) as session:
        assert session.scalar(select(func.count()).select_from(FindingRow)) == 0
        assert session.scalar(select(func.count()).select_from(EvidenceRow)) == 0


def test_an_empty_analysis_is_still_a_complete_answer(client: TestClient) -> None:
    """The shape holds when there is nothing to report.

    Also the guard against ``/api/analysis`` becoming a 404 for a dataset with
    no findings: "nothing to review" and "no such endpoint" are different
    answers, and a client cannot tell them apart from a status code alone.
    """
    body = _analysis(client)
    assert set(body) >= {
        "content_hash",
        "dataset_fingerprint",
        "analysis_as_of",
        "window_start",
        "window_end",
        "rejections",
        "findings",
    }
    assert isinstance(body["findings"], list)
