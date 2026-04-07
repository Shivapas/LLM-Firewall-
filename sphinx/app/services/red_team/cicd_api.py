"""Sprint 24B — Red Team CI/CD API.

REST-oriented helpers for CI/CD integration: trigger a campaign, poll
for completion, and produce a pass/fail verdict based on Critical findings.
Designed for use with GitHub Actions and other CI/CD pipelines.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .runner import (
    Campaign,
    CampaignStatus,
    create_campaign,
    get_campaign,
    run_campaign,
)
from .policy_recommendation import generate_recommendations


class CICDBuildVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PENDING = "pending"
    ERROR = "error"


def compute_build_verdict(
    campaign: Campaign,
    fail_on_critical: bool = True,
    fail_on_high: bool = False,
    max_critical: int = 0,
    max_high: int = 0,
) -> dict:
    """Evaluate campaign results and return a CI/CD-friendly verdict.

    Parameters
    ----------
    campaign : Campaign
        Completed campaign to evaluate.
    fail_on_critical : bool
        Fail the build if any Critical findings exist.
    fail_on_high : bool
        Fail the build if any High findings exist.
    max_critical : int
        Maximum allowed Critical findings before failure (0 = any triggers fail).
    max_high : int
        Maximum allowed High findings before failure.

    Returns
    -------
    dict with keys: verdict, critical_count, high_count, total_findings, details
    """
    if campaign.status == CampaignStatus.PENDING:
        return {
            "verdict": CICDBuildVerdict.PENDING.value,
            "campaign_id": campaign.id,
            "campaign_status": campaign.status.value,
            "message": "Campaign has not been executed yet.",
        }

    if campaign.status == CampaignStatus.RUNNING:
        return {
            "verdict": CICDBuildVerdict.PENDING.value,
            "campaign_id": campaign.id,
            "campaign_status": campaign.status.value,
            "progress": f"{campaign.probes_executed}/{campaign.total_probes}",
            "message": "Campaign is still running.",
        }

    if campaign.status == CampaignStatus.FAILED:
        return {
            "verdict": CICDBuildVerdict.ERROR.value,
            "campaign_id": campaign.id,
            "campaign_status": campaign.status.value,
            "message": f"Campaign execution failed: {campaign.error_message}",
        }

    # Campaign completed — count findings
    detected = [r for r in campaign.results if r.detected]
    critical_count = sum(1 for r in detected if r.severity.value == "critical")
    high_count = sum(1 for r in detected if r.severity.value == "high")
    medium_count = sum(1 for r in detected if r.severity.value == "medium")
    low_count = sum(1 for r in detected if r.severity.value == "low")

    failed = False
    fail_reasons = []

    if fail_on_critical and critical_count > max_critical:
        failed = True
        fail_reasons.append(
            f"{critical_count} Critical findings (max allowed: {max_critical})"
        )
    if fail_on_high and high_count > max_high:
        failed = True
        fail_reasons.append(
            f"{high_count} High findings (max allowed: {max_high})"
        )

    verdict = CICDBuildVerdict.FAIL if failed else CICDBuildVerdict.PASS

    return {
        "verdict": verdict.value,
        "campaign_id": campaign.id,
        "campaign_status": campaign.status.value,
        "total_probes": len(campaign.results),
        "total_findings": len(detected),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "fail_reasons": fail_reasons,
        "detection_rate": round(len(detected) / max(len(campaign.results), 1), 4),
        "message": (
            f"Build FAILED: {'; '.join(fail_reasons)}"
            if failed
            else "Build PASSED: No blocking findings detected."
        ),
    }


async def trigger_cicd_campaign(
    target_url: str,
    name: Optional[str] = None,
    probe_categories: Optional[list[str]] = None,
    concurrency: int = 10,
    timeout_seconds: int = 30,
    created_by: str = "cicd",
    wait: bool = False,
) -> dict:
    """Trigger a red team campaign for CI/CD.

    If ``wait=True``, blocks until the campaign completes and returns the
    verdict. Otherwise returns immediately with the campaign ID for polling.
    """
    campaign_name = name or f"CI/CD Run — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
    campaign = create_campaign(
        name=campaign_name,
        target_url=target_url,
        probe_categories=probe_categories,
        concurrency=concurrency,
        timeout_seconds=timeout_seconds,
        created_by=created_by,
    )

    if wait:
        await run_campaign(campaign)
        generate_recommendations(campaign)
        verdict = compute_build_verdict(campaign)
        return {
            "campaign_id": campaign.id,
            "campaign": campaign.to_dict(),
            "verdict": verdict,
        }

    # Non-blocking — kick off in background
    asyncio.ensure_future(run_campaign(campaign))
    return {
        "campaign_id": campaign.id,
        "status": "started",
        "message": "Campaign started. Poll /api/v1/red-team/cicd/status/{campaign_id} for results.",
    }


def get_cicd_status(campaign_id: str) -> dict:
    """Poll campaign status and verdict for CI/CD integration."""
    campaign = get_campaign(campaign_id)
    if not campaign:
        return {"error": "Campaign not found", "campaign_id": campaign_id}

    result = {
        "campaign_id": campaign.id,
        "status": campaign.status.value,
        "progress": f"{campaign.probes_executed}/{campaign.total_probes}",
    }

    if campaign.status == CampaignStatus.COMPLETED:
        result["verdict"] = compute_build_verdict(campaign)
        result["summary"] = campaign._compute_findings_summary()
    elif campaign.status == CampaignStatus.FAILED:
        result["verdict"] = {
            "verdict": CICDBuildVerdict.ERROR.value,
            "message": campaign.error_message,
        }

    return result
