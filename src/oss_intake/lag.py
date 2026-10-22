"""Release-lag metrics: fixes that existed upstream but were not shipped by the project."""

from __future__ import annotations

from datetime import datetime, timedelta
from statistics import median

from .models import SEVERITIES, Finding, days_between
from .versions import label_only_match, nearest_fix

DEFAULT_GRACE_DAYS = 14
DEFAULT_UNSHIPPED_DAYS = 90


def flag_label_matches(findings: list[Finding]) -> int:
    """Mark findings whose installed version equals a listed fix apart from a build label."""
    n = 0
    for f in findings:
        match = label_only_match(f.installed, f.fixed_versions)
        if match:
            f.likely_fixed = True
            f.note = (f"Installed {f.installed} equals listed fix {match} apart from a build label; "
                      "likely already fixed. Check the target path and confirm.")
            n += 1
    return n


def flag_no_newer_fix(findings: list[Finding]) -> int:
    """Mark findings whose listed fixes are all at or below the installed version."""
    n = 0
    for f in findings:
        if f.fixed_versions and not f.likely_fixed and nearest_fix(f.installed, f.fixed_versions) is None:
            f.note = (f"No listed fix ({', '.join(f.fixed_versions)}) is newer than installed {f.installed}; "
                      "scanner data may be wrong (often Go pseudo-versions). Check manually.")
            n += 1
    return n


def compute(findings: list[Finding], release_date: datetime | None, as_of: datetime,
            grace_days: int = DEFAULT_GRACE_DAYS, unshipped_days: int = DEFAULT_UNSHIPPED_DAYS,
            scanned_is_latest: bool | None = None) -> dict:
    """Release-lag metrics.

    grace_days: a fix must have been public this many days before the release to count as
    "existed before release" (nobody ships a fix published the day before).
    unshipped_days: a fix public for at least this long, while the scanned release is still the
    project's latest, counts as "unshipped" (forward-looking lag).
    """
    cutoff = release_date - timedelta(days=grace_days) if release_date else None
    for f in findings:
        if f.fix_published and not f.likely_fixed:
            f.days_fix_available = days_between(f.fix_published, as_of)
            if cutoff:
                f.fix_available_at_release = f.fix_published < cutoff
        if f.published and release_date:
            f.published_before_release = f.published < release_date

    with_fix = [f for f in findings if f.has_fix and not f.likely_fixed]
    likely_fixed = [f for f in findings if f.likely_fixed]
    dated = [f for f in with_fix if f.fix_published]
    within_grace = [f for f in dated if release_date and cutoff <= f.fix_published < release_date]
    unshipped = None
    if scanned_is_latest is not None:
        unshipped = [f for f in dated if scanned_is_latest and (f.days_fix_available or 0) >= unshipped_days]
    at_release = [f for f in dated if f.fix_available_at_release]
    days = [f.days_fix_available for f in dated if f.days_fix_available is not None]
    oldest = min(dated, key=lambda f: f.fix_published) if dated else None
    oldest_pub = min((f for f in with_fix if f.published), key=lambda f: f.published, default=None)

    def by_sev(items: list[Finding]) -> dict[str, int]:
        return {s: sum(1 for f in items if f.severity == s) for s in SEVERITIES}

    return {
        "release_date": release_date.isoformat() if release_date else None,
        "grace_days": grace_days,
        "unshipped_days": unshipped_days,
        "scanned_is_latest": scanned_is_latest,
        "likely_fixed_label_match": len(likely_fixed),
        "fix_within_grace": len(within_grace),
        "unshipped": None if unshipped is None else len(unshipped),
        "unshipped_by_severity": None if unshipped is None else by_sev(unshipped),
        "as_of": as_of.isoformat(),
        "total": len(findings),
        "by_severity": by_sev(findings),
        "with_fix": len(with_fix),
        "with_fix_by_severity": by_sev(with_fix),
        "without_fix": len(findings) - len(with_fix),
        "fix_date_known": len(dated),
        "fix_date_unknown": len(with_fix) - len(dated),
        "fix_available_at_release": len(at_release),
        "fix_available_at_release_by_severity": by_sev(at_release),
        "fix_after_release": sum(1 for f in dated if f.fix_available_at_release is False),
        "cve_published_before_release": sum(1 for f in with_fix if f.published_before_release),
        "median_days_fix_available": median(days) if days else None,
        "max_days_fix_available": max(days) if days else None,
        "oldest_available_fix": None if not oldest else {
            "id": oldest.vuln_id, "package": oldest.package, "fix_version": oldest.fix_version_used,
            "fix_published": oldest.fix_published.date().isoformat(), "days": oldest.days_fix_available,
        },
        "oldest_published_with_fix": None if not oldest_pub else {
            "id": oldest_pub.vuln_id, "package": oldest_pub.package,
            "published": oldest_pub.published.date().isoformat(),
            "days": days_between(oldest_pub.published, as_of),
        },
        "kev_with_fix": sum(1 for f in with_fix if f.kev),
        "max_epss_with_fix": max((f.epss for f in with_fix if f.epss is not None), default=None),
        "epss_scored": sum(1 for f in findings if f.epss is not None),
    }
