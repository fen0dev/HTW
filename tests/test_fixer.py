"""Fix proposals and the pull request interface: proposals only, never applied."""

from __future__ import annotations

from pathlib import Path

import pytest

from htw.agents.fixer import (
    DependencyBumpProposer,
    FileChange,
    FixContext,
    FixProposal,
    parse_version,
    propose_fixes,
    target_version,
)
from htw.core.config import load_config
from htw.core.fingerprint import assign_fingerprints
from htw.core.levels import ControlLevel
from htw.core.scope import ScopeDecision
from htw.core.scoring import assign_priorities
from htw.detect import detect_stack
from htw.errors import ScopeViolation
from htw.integrations.pull_requests import (
    ProposalWriter,
    PullRequestPublisher,
    PullRequestRef,
    render_proposal,
)

from .conftest import scope_yaml, write_tree
from .helpers import dependency_finding, sast_finding

REQUIREMENTS = "# pinned\nflask==3.0.0\nJinja2==2.10  # templating\nrequests[socks]==2.19.1 ; python_version > '3'\n"


def context(root: Path, files: dict[str, str] | None = None) -> FixContext:
    write_tree(root, files or {})
    return FixContext("app", root, detect_stack(root))


def prepared(*findings):
    items = list(findings)
    assign_fingerprints(items)
    assign_priorities(items, "medium")
    return items


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2.10.1", (2, 10, 1)),
        ("v1.2", (1, 2)),
        ("3", (3,)),
        ("2.0.0rc1", None),
        (">=2.0", None),
        ("", None),
    ],
)
def test_parse_version(text: str, expected) -> None:
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    ("current", "fixed", "expected"),
    [
        ("2.10", [("2.10.1",)], "2.10.1"),
        # Two advisories: the target must clear both.
        ("2.10", [("2.10.1",), ("2.11.3",)], "2.11.3"),
        # One advisory fixed on several branches: take the nearest fix above current.
        ("1.2.3", [("1.2.9", "2.0.4")], "1.2.9"),
        ("2.0.1", [("1.2.9", "2.0.4")], "2.0.4"),
        ("2.9.9", [("2.10.0",)], "2.10.0"),
        # Unknowable: no fix, fix not above current, or not a plain version.
        ("2.10", [()], None),
        ("2.10", [("2.10.1",), ()], None),
        ("3.0", [("2.10.1",)], None),
        ("2.10", [("2.11.0rc1",)], None),
        ("2.10.dev0", [("2.11",)], None),
        ("2.10", [], None),
    ],
)
def test_target_version(current, fixed, expected) -> None:
    assert target_version(current, fixed) == expected


def test_dependency_upgrade_proposal_with_a_patch(tmp_path: Path) -> None:
    ctx = context(tmp_path, {"requirements.txt": REQUIREMENTS})
    findings = prepared(
        dependency_finding("GHSA-462w-v97r-4m45", fixed=("2.10.1",)),
        dependency_finding("GHSA-g3rq-g295-4j3m", fixed=("2.11.3",)),
        sast_finding(),
    )

    (proposal,) = propose_fixes(findings, ctx)

    assert proposal.title == "Upgrade jinja2 from 2.10 to 2.11.3"
    assert proposal.kind == "dependency_bump" and proposal.requires_human_review
    assert proposal.public_safe
    assert proposal.priority == "P1"
    assert proposal.fingerprints == tuple(sorted(f.fingerprint for f in findings[:2]))
    assert "2 published advisories" in proposal.summary
    assert proposal.id.startswith("fix-") and len(proposal.id) == 16
    assert proposal.patch == (
        "--- a/requirements.txt\n"
        "+++ b/requirements.txt\n"
        "@@ -1,4 +1,4 @@\n"
        " # pinned\n"
        " flask==3.0.0\n"
        "-Jinja2==2.10  # templating\n"
        "+Jinja2==2.11.3  # templating\n"
        " requests[socks]==2.19.1 ; python_version > '3'\n"
    )
    # A proposal is never applied.
    assert (tmp_path / "requirements.txt").read_text() == REQUIREMENTS


def test_extras_and_markers_survive_the_patch(tmp_path: Path) -> None:
    ctx = context(tmp_path, {"requirements.txt": REQUIREMENTS})
    findings = prepared(dependency_finding(name="requests", version="2.19.1", fixed=("2.20.0",)))

    (proposal,) = propose_fixes(findings, ctx)

    assert "+requests[socks]==2.20.0 ; python_version > '3'\n" in proposal.patch


@pytest.mark.parametrize(
    ("files", "manifest", "why"),
    [
        ({"requirements.txt": "jinja2>=2.10\n"}, "requirements.txt", "range, not an exact pin"),
        (
            {"requirements.txt": "jinja2==2.10 \\\n    --hash=sha256:abc\n"},
            "requirements.txt",
            "hash-pinned",
        ),
        ({"requirements.txt": "jinja2==2.10\njinja2==2.10\n"}, "requirements.txt", "ambiguous"),
        ({"requirements.txt": "jinja2==2.9\n"}, "requirements.txt", "another version is pinned"),
        ({"requirements.txt": "jinja2==2.10"}, "requirements.txt", "no trailing newline"),
        ({"poetry.lock": "jinja2==2.10\n"}, "poetry.lock", "lockfile"),
        ({"package-lock.json": "{}\n"}, "package-lock.json", "lockfile"),
        ({}, "requirements.txt", "file is gone"),
        ({}, "../outside/requirements.txt", "outside the asset"),
    ],
)
def test_no_patch_when_the_edit_would_be_a_guess(tmp_path: Path, files, manifest, why) -> None:
    root = tmp_path / "asset"
    root.mkdir()
    write_tree(tmp_path / "outside", {"requirements.txt": "jinja2==2.10\n"})
    ctx = context(root, files)

    (proposal,) = propose_fixes(prepared(dependency_finding(path=manifest)), ctx)

    assert not proposal.has_patch, why
    assert proposal.title == "Upgrade jinja2 from 2.10 to 2.11.3"
    assert any("No patch was generated" in note for note in proposal.notes)


def test_symlinked_manifest_is_not_patched(tmp_path: Path) -> None:
    root = tmp_path / "asset"
    root.mkdir()
    (tmp_path / "real.txt").write_text("jinja2==2.10\n")
    (root / "requirements.txt").symlink_to(tmp_path / "real.txt")

    (proposal,) = propose_fixes(
        prepared(dependency_finding()), FixContext("app", root, detect_stack(root))
    )

    assert not proposal.has_patch


def test_unknown_target_still_produces_a_proposal(tmp_path: Path) -> None:
    ctx = context(tmp_path, {"requirements.txt": REQUIREMENTS})

    (proposal,) = propose_fixes(prepared(dependency_finding(fixed=())), ctx)

    assert proposal.title == "Upgrade jinja2 2.10"
    assert "could not be derived automatically" in proposal.summary
    assert not proposal.has_patch


def test_update_bots_are_preferred_when_configured(tmp_path: Path) -> None:
    ctx = context(
        tmp_path,
        {"requirements.txt": REQUIREMENTS, ".github/dependabot.yml": "version: 2\nupdates: []\n"},
    )

    (proposal,) = propose_fixes(prepared(dependency_finding()), ctx)

    assert "Dependabot is configured" in proposal.notes[0]


def test_proposals_are_grouped_per_package_and_ordered_by_priority(tmp_path: Path) -> None:
    from htw.core.finding import Severity

    ctx = context(tmp_path, {"requirements.txt": REQUIREMENTS})
    findings = prepared(
        dependency_finding(name="requests", version="2.19.1", fixed=("2.20.0",), severity=Severity.LOW),
        dependency_finding(severity=Severity.CRITICAL),
        dependency_finding(name="lodash", version="4.17.15", fixed=("4.17.21",), ecosystem="npm",
                           path="package-lock.json", severity=Severity.MEDIUM),
    )  # fmt: skip

    proposals = propose_fixes(findings, ctx)

    assert [(p.priority, p.title.split()[1]) for p in proposals] == [
        ("P0", "jinja2"), ("P2", "lodash"), ("P3", "requests"),
    ]  # fmt: skip
    assert DependencyBumpProposer().propose([sast_finding()], ctx) == []


def test_hostile_package_names_are_escaped_in_proposals(tmp_path: Path) -> None:
    ctx = context(tmp_path)
    finding = dependency_finding(
        name="x](https://evil.invalid) <b>", ecosystem="npm", path="package.json"
    )

    (proposal,) = propose_fixes(prepared(finding), ctx)
    body = render_proposal(proposal)

    # The bracket is escaped, so no link is formed, and the tag is inert.
    assert "\\](https://evil.invalid)" in body
    assert body.count("](") == body.count("\\](")
    assert "<b>" not in body


# --- delivery ---------------------------------------------------------------------


def proposal(**overrides) -> FixProposal:
    values = {
        "asset_id": "app",
        "kind": "dependency_bump",
        "title": "Upgrade jinja2 from 2.10 to 2.11.3",
        "summary": "jinja2 2.10 is affected by 1 published advisory.",
        "fingerprints": ("htw1:" + "a" * 32,),
        "priority": "P1",
        "proposer": "dependency-bump",
        "changes": (
            FileChange("requirements.txt", "--- a/requirements.txt\n+++ b/requirements.txt\n"),
        ),
        "public_safe": True,
    }
    values.update(overrides)
    return FixProposal(**values)  # type: ignore[arg-type]


def test_proposal_writer_writes_markdown_and_patch(tmp_path: Path) -> None:
    with_patch, without = proposal(), proposal(title="Upgrade lodash", changes=())

    written = ProposalWriter(tmp_path / "proposals").write([with_patch, without])

    assert [p.name for p in written] == [f"{with_patch.id}.md", f"{without.id}.md"]
    assert (tmp_path / "proposals" / f"{with_patch.id}.patch").read_text() == with_patch.patch
    assert not (tmp_path / "proposals" / f"{without.id}.patch").exists()
    body = written[0].read_text()
    assert "A person must review it before it is merged; HTW never merges." in body
    assert "```diff" in body
    assert ProposalWriter(tmp_path / "none").write([]) == []
    assert not (tmp_path / "none").exists()


class RecordingPublisher(PullRequestPublisher):
    def __init__(self, *, draft: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.draft = draft
        self.opened: list[dict] = []

    def _open_draft_pull_request(self, *, asset, branch, title, body, patch) -> PullRequestRef:
        self.opened.append({"asset": asset.id, "branch": branch, "title": title, "body": body})
        return PullRequestRef("https://forge.invalid/acme/app/pull/1", branch, draft=self.draft)


@pytest.fixture
def asset(tmp_path: Path):
    (tmp_path / "htw.yaml").write_text(scope_yaml([{"id": "app", "path": "."}]), encoding="utf-8")
    return load_config(tmp_path / "htw.yaml").assets[0]


def allowed(asset_id: str = "app") -> ScopeDecision:
    return ScopeDecision(asset_id, ControlLevel.L0)


def test_publisher_opens_a_draft_on_a_new_htw_branch(asset) -> None:
    publisher = RecordingPublisher(enabled=True)

    reference = publisher.publish(proposal(), asset, allowed())

    assert reference.draft
    (opened,) = publisher.opened
    assert opened["branch"].startswith("htw/fix-")
    assert opened["branch"].endswith("upgrade-jinja2-from-2-10-to-2-11-3")
    assert "HTW never merges" in opened["body"]


def test_publisher_is_off_in_report_only_mode(asset) -> None:
    publisher = RecordingPublisher(enabled=False)

    with pytest.raises(ScopeViolation, match="report-only mode"):
        publisher.publish(proposal(), asset, allowed())
    assert publisher.opened == []


def test_publisher_refuses_assets_out_of_scope(asset) -> None:
    publisher = RecordingPublisher(enabled=True)
    refused = ScopeDecision("app", ControlLevel.L0)
    refused.deny("authorization expired")

    for decision, candidate in (
        (refused, proposal()),
        (allowed("another-asset"), proposal()),
        (allowed(), proposal(asset_id="another-asset")),
    ):
        with pytest.raises(ScopeViolation, match="not authorized in scope"):
            publisher.publish(candidate, asset, decision)
    assert publisher.opened == []


def test_publisher_never_discloses_unfixed_weaknesses_publicly(asset) -> None:
    sensitive = proposal(kind="code_change", title="Harden input handling", public_safe=False)

    with pytest.raises(ScopeViolation, match="could disclose an unfixed weakness"):
        RecordingPublisher(enabled=True).publish(sensitive, asset, allowed())

    private = RecordingPublisher(enabled=True, destination_is_private=True)
    assert private.publish(sensitive, asset, allowed()).draft


def test_publisher_requires_a_patch_and_a_draft(asset) -> None:
    with pytest.raises(ScopeViolation, match="has no patch"):
        RecordingPublisher(enabled=True).publish(proposal(changes=()), asset, allowed())
    with pytest.raises(ScopeViolation, match="not a draft"):
        RecordingPublisher(enabled=True, draft=False).publish(proposal(), asset, allowed())


def test_branch_names_are_safe(asset) -> None:
    hostile = proposal(title="Upgrade ../../x; rm -rf ~ && `id` $(whoami)")

    branch = PullRequestPublisher.branch_name(hostile)

    assert branch.startswith("htw/fix-")
    assert branch.endswith("-upgrade-x-rm-rf-id-whoami")
    assert all(c.isascii() and (c.isalnum() or c in "/-") for c in branch)
    assert (
        PullRequestPublisher.branch_name(proposal(title="???")) == f"htw/{proposal(title='???').id}"
    )
