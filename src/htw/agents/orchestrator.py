"""The orchestrator: deterministic control flow for a scan.

It decides nothing by judgement. For each asset it checks scope and authorization,
detects the stack, selects the scanners that apply, runs them, normalizes and
fingerprints the findings, compares them with the previous run, and hands the result
to reporting. Every step that matters is written to the audit log.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from htw.agents import AGENTS
from htw.agents.base import AgentPlan, ScannerAgent
from htw.agents.fixer import FixContext, propose_fixes
from htw.agents.reporting import write_reports
from htw.agents.run import COMPLETE, INCOMPLETE, REFUSED, STOPPED, AssetRun
from htw.agents.triage import triage_findings
from htw.core.audit import AuditLog, initiator
from htw.core.config import Asset, Config
from htw.core.finding import Finding, sanitize_finding
from htw.core.fingerprint import assign_fingerprints
from htw.core.levels import ControlLevel
from htw.core.llm import client_for
from htw.core.paths import is_excluded
from htw.core.runner import ToolRunner
from htw.core.scope import KillSwitch, ScopeDecision, ScopeGuard
from htw.core.scoring import assign_priorities
from htw.core.store import Store
from htw.core.suppressions import SuppressionSet, load_suppressions
from htw.detect import StackProfile, detect_stack
from htw.errors import HtwError, KillSwitchEngaged
from htw.integrations.pull_requests import GitHubCliPublisher, PullRequestPublisher
from htw.scanners.base import STATUS_ERROR, STATUS_MISSING, STATUS_OK, ScanContext, ToolOutcome

MAX_FINDINGS_PER_TOOL = 5000


class Orchestrator:
    def __init__(
        self,
        config: Config,
        *,
        now: Callable[[], datetime] | None = None,
        runner: ToolRunner | None = None,
        agents: Sequence[ScannerAgent] = AGENTS,
        environ: dict[str, str] | None = None,
        publisher: PullRequestPublisher | None = None,
    ):
        self.config = config
        self._now = now or (lambda: datetime.now(UTC))
        self.agents = tuple(agents)
        self.kill_switch = KillSwitch(config.kill_switch_path, environ)
        self.runner = runner or ToolRunner(
            timeout_seconds=config.runner.timeout_seconds,
            max_output_bytes=config.runner.max_output_mb * 1024 * 1024,
            env_passthrough=config.runner.env_passthrough,
            kill_switch=self.kill_switch,
            environ=environ,
        )
        self.audit = AuditLog(config.audit_path)
        self._environ = environ
        self._publisher = publisher

    def select_assets(self, asset_ids: Sequence[str] | None) -> list[Asset]:
        if not asset_ids:
            return list(self.config.assets)
        return [self.config.asset(asset_id) for asset_id in asset_ids]

    def plan(self, asset: Asset) -> tuple[ScopeDecision, StackProfile | None, list[AgentPlan]]:
        """Scope check, stack detection and scanner selection, without running anything."""
        decision = ScopeGuard(self._now()).check(asset, ControlLevel.L0)
        if not decision.allowed:
            return decision, None, []
        profile = detect_stack(asset.path, asset.exclude)
        return decision, profile, self._plans(asset, profile)

    def _plans(self, asset: Asset, profile: StackProfile) -> list[AgentPlan]:
        plans = []
        guard = ScopeGuard(self._now())
        for agent in self.agents:
            level_check = guard.check(asset, agent.level, control=agent.approval_control or None)
            if not level_check.allowed:
                plans.append(
                    AgentPlan(agent.name, agent.title, False, "; ".join(level_check.reasons))
                )
                continue
            plans.append(agent.plan(profile, asset.scanners[agent.name], self.runner))
        return plans

    def scan(self, asset_ids: Sequence[str] | None = None) -> list[AssetRun]:
        """Scan the selected assets (all declared assets by default)."""
        assets = self.select_assets(asset_ids)
        if not self.config.state_dir.exists():
            # Reports describe unfixed weaknesses: readable by the operator only.
            self.config.state_dir.mkdir(parents=True, mode=0o700)
        try:
            self.kill_switch.raise_if_engaged()
        except KillSwitchEngaged as exc:
            self.audit.append("kill_switch", at=self._now(), detail=str(exc))
            raise
        suppressions = load_suppressions(self.config.suppressions_path, self._now().date())
        runs = []
        with Store(self.config.store_path) as store:
            for asset in assets:
                run = self._scan_asset(asset, store, suppressions)
                runs.append(run)
                if run.status == STOPPED:
                    break
        return runs

    def _scan_asset(self, asset: Asset, store: Store, suppressions: SuppressionSet) -> AssetRun:
        started = self._now()
        decision = ScopeGuard(started).check(
            asset, ControlLevel.L0, last_run_at=store.last_run_started(asset.id)
        )
        self.audit.append(
            "scope_decision",
            at=started,
            asset=asset.id,
            level=decision.level.name,
            allowed=decision.allowed,
            reasons=decision.reasons,
            ownership=decision.ownership_evidence,
            authorized_by=asset.authorization.authorized_by,
            authorization_expires=asset.authorization.expires_on.isoformat(),
            config_hash=self.config.config_hash,
        )
        if not decision.allowed:
            return AssetRun(asset=asset, decision=decision, status=REFUSED)

        run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
        run = AssetRun(
            asset=asset,
            decision=decision,
            status=COMPLETE,
            run_id=run_id,
            started_at=started,
            fixes_enabled=self.config.fixes.propose,
            expired_suppressions=list(suppressions.expired),
        )
        store.begin_run(run_id, asset.id, started, self.config.config_hash)
        self.audit.append(
            "run_started",
            at=started,
            run=run_id,
            asset=asset.id,
            path=str(asset.path),
            initiator=initiator(self._environ),
            mode="propose-fixes" if self.config.fixes.propose else "report-only",
            config_hash=self.config.config_hash,
        )

        run.profile = detect_stack(asset.path, asset.exclude)
        run.plans = self._plans(asset, run.profile)
        run.report_dir = self.config.reports_dir / asset.id / run_id
        run.report_dir.mkdir(parents=True, exist_ok=True)

        findings = self._run_tools(run)
        if run.status != STOPPED:
            self._record(run, findings, store, suppressions)

        run.finished_at = self._now()
        if run.status != STOPPED:
            write_reports(run)
        store.finish_run(run_id, run.finished_at, run.status, run.delta.counts())
        self.audit.append(
            "run_finished",
            at=run.finished_at,
            run=run_id,
            asset=asset.id,
            status=run.status,
            delta=run.delta.counts(),
            gaps=run.gaps,
        )
        return run

    def _run_tools(self, run: AssetRun) -> list[Finding]:
        assert run.profile is not None and run.report_dir is not None
        asset = run.asset
        agents = {agent.name: agent for agent in self.agents}
        findings: list[Finding] = []
        for plan in run.plans:
            agent = agents[plan.agent]
            for adapter in plan.missing:
                run.outcomes.append(
                    ToolOutcome(
                        agent=agent.name,
                        tool=adapter.name,
                        status=STATUS_MISSING,
                        message=adapter.missing_message(),
                        install_hint=adapter.install_hint,
                    )
                )
            artifacts: dict[str, Path] = {}
            for adapter in plan.selected:
                if adapter.level > asset.max_level:
                    continue
                ctx = ScanContext(
                    asset=asset,
                    root=asset.path,
                    profile=run.profile,
                    runner=self.runner,
                    settings=asset.scanners[agent.name],
                    config_dir=self.config.base_dir,
                    artifacts_dir=run.report_dir,
                    artifacts=artifacts,
                )
                outcome = ToolOutcome(agent=agent.name, tool=adapter.name, status=STATUS_OK)
                tool_started = self._now()
                try:
                    outcome.version = adapter.version(self.runner, asset.path)
                    outcome.findings = self._normalize(adapter.scan(ctx), asset, outcome)
                except KillSwitchEngaged as exc:
                    outcome.status, outcome.message = STATUS_ERROR, str(exc)
                    run.status = STOPPED
                except HtwError as exc:
                    outcome.status, outcome.message = STATUS_ERROR, str(exc)
                    run.status = INCOMPLETE
                except Exception as exc:
                    # Scanner output is untrusted. A wrapper that trips over it must cost
                    # that one tool's results, not the whole run.
                    outcome.status = STATUS_ERROR
                    outcome.message = (
                        f"{adapter.name}: its output could not be processed "
                        f"({type(exc).__name__}). Please report this as an HTW bug."
                    )
                    run.status = INCOMPLETE
                outcome.duration_seconds = round((self._now() - tool_started).total_seconds(), 3)
                run.outcomes.append(outcome)
                self.audit.append(
                    "tool_executed",
                    at=self._now(),
                    run=run.run_id,
                    asset=asset.id,
                    agent=agent.name,
                    tool=adapter.name,
                    tool_version=outcome.version,
                    level=adapter.level.name,
                    status=outcome.status,
                    findings=len(outcome.findings),
                    detail=outcome.message,
                )
                if run.status == STOPPED:
                    run.notes.append(
                        "The kill switch was engaged during the run; results were discarded."
                    )
                    return []
                findings.extend(outcome.findings)
        return findings

    @staticmethod
    def _normalize(findings: list[Finding], asset: Asset, outcome: ToolOutcome) -> list[Finding]:
        kept = [
            sanitize_finding(finding)
            for finding in findings
            if not (finding.location.path and is_excluded(finding.location.path, asset.exclude))
        ]
        if len(kept) > MAX_FINDINGS_PER_TOOL:
            kept.sort(key=lambda f: (-f.severity.rank, f.location.path or "", f.rule_id))
            outcome.message = (
                f"{len(kept)} findings reported; only the {MAX_FINDINGS_PER_TOOL} most severe "
                "were kept. Narrow the ruleset or add excludes."
            )
            kept = kept[:MAX_FINDINGS_PER_TOOL]
        return kept

    def _record(
        self, run: AssetRun, findings: list[Finding], store: Store, suppressions: SuppressionSet
    ) -> None:
        assert run.profile is not None and run.report_dir is not None
        asset = run.asset
        assign_fingerprints(findings, asset.path)
        assign_priorities(findings, asset.criticality)
        if self.config.triage.enabled:
            llm = client_for(self.config.triage) if self.config.triage.llm else None
            findings, run.triage = triage_findings(findings, environment=asset.environment, llm=llm)
            for note in run.triage:
                if note.action == "error":
                    run.status = INCOMPLETE
                    run.notes.append(note.reason)
        completed = {o.tool for o in run.outcomes if o.status == STATUS_OK}
        run.delta = store.apply_run(run.run_id, asset.id, self._now(), findings, completed)

        on_record = (
            run.delta.new
            + run.delta.reappeared
            + run.delta.unchanged
            + run.delta.unverified
            + run.delta.resolved
        )
        for finding in on_record:
            suppression = suppressions.get(finding.fingerprint)
            if suppression is not None:
                run.suppressed[finding.fingerprint] = suppression

        if self.config.fixes.propose:
            open_findings = run.visible(run.delta.new + run.delta.reappeared + run.delta.unchanged)
            run.proposals = propose_fixes(
                open_findings, FixContext(asset.id, asset.path, run.profile)
            )
            if self.config.fixes.pull_requests:
                self._publish(run)

    def _publish(self, run: AssetRun) -> None:
        publisher = self._publisher or GitHubCliPublisher(
            enabled=True,
            destination_is_private=self.config.fixes.private_destination,
            runner=self.runner,
        )
        for proposal in run.proposals:
            if not proposal.has_patch:
                continue
            try:
                reference = publisher.publish(proposal, run.asset, run.decision)
            except HtwError as exc:
                run.notes.append(f"{proposal.id}: pull request not opened: {exc}")
                continue
            run.pull_requests.append(reference)
            self.audit.append(
                "pull_request_opened",
                at=self._now(),
                run=run.run_id,
                asset=run.asset.id,
                branch=reference.branch,
                url=reference.url,
                draft=reference.draft,
            )
