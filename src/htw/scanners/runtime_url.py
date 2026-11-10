"""The only address a runtime check is allowed to contact."""

from __future__ import annotations

from datetime import UTC, datetime

from htw.core.config import validate_target_url
from htw.errors import ScopeViolation
from htw.scanners.base import ScanContext


def approved_staging_url(ctx: ScanContext) -> str:
    """Return the staging URL when a current DAST approval names exactly that URL.

    The scope guard already refuses the agent without an approval. This is the second
    check, next to the process that would open the connection, so a wrapper cannot
    be pointed at some other host.
    """
    url = str(ctx.settings.options.get("staging_url") or "")
    if not url:
        raise ScopeViolation(
            "refusing to contact a runtime target: DAST runs only against the staging "
            "URL named in a current human approval"
        )
    where = f"asset {ctx.asset.id!r}"
    try:
        url = validate_target_url(url, where)
    except Exception as exc:
        raise ScopeViolation(
            "refusing to contact a runtime target: DAST runs only against an http(s) "
            "staging URL with no credentials"
        ) from exc
    today = datetime.now(UTC).date()
    matched = [
        approval
        for approval in ctx.asset.approvals
        if approval.control == "dast"
        and approval.target == url
        and approval.authorized_on <= today <= approval.expires_on
    ]
    if not matched:
        raise ScopeViolation(
            "refusing to contact a runtime target: DAST runs only against the staging "
            "URL named in a current human approval"
        )
    return url
