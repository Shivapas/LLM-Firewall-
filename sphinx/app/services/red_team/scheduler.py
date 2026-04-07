"""Sprint 24B — Continuous Red Team Campaign Scheduling.

Supports daily/weekly recurring red team campaigns with automatic
regression detection: alerts when a new vulnerability is detected
that was not present in the previous campaign run.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from .runner import (
    Campaign,
    CampaignStatus,
    create_campaign,
    get_campaign,
    get_campaign_store,
    run_campaign,
)
from .policy_recommendation import generate_recommendations

logger = logging.getLogger("sphinx.red_team.scheduler")


class ScheduleFrequency(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"


class RegressionAlert:
    """Alert raised when a scheduled campaign detects a new vulnerability."""

    def __init__(
        self,
        schedule_id: str,
        current_campaign_id: str,
        previous_campaign_id: str,
        new_probe_ids: list[str],
        severity: str,
        message: str,
    ):
        self.id = str(uuid.uuid4())
        self.schedule_id = schedule_id
        self.current_campaign_id = current_campaign_id
        self.previous_campaign_id = previous_campaign_id
        self.new_vulnerability_probe_ids = new_probe_ids
        self.severity = severity
        self.message = message
        self.acknowledged = False
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "schedule_id": self.schedule_id,
            "current_campaign_id": self.current_campaign_id,
            "previous_campaign_id": self.previous_campaign_id,
            "new_vulnerability_probe_ids": self.new_vulnerability_probe_ids,
            "severity": self.severity,
            "message": self.message,
            "acknowledged": self.acknowledged,
            "created_at": self.created_at.isoformat(),
        }


class RedTeamSchedule:
    """A recurring red team campaign schedule."""

    def __init__(
        self,
        name: str,
        target_url: str,
        probe_categories: Optional[list[str]] = None,
        concurrency: int = 10,
        timeout_seconds: int = 30,
        frequency: str = "daily",
        created_by: str = "admin",
    ):
        self.id = str(uuid.uuid4())
        self.name = name
        self.target_url = target_url
        self.probe_categories = probe_categories or [
            "injection", "jailbreak", "pii_extraction",
            "tool_call_injection", "memory_poisoning",
            "privilege_escalation", "multi_step_attack",
        ]
        self.concurrency = concurrency
        self.timeout_seconds = timeout_seconds
        self.frequency = ScheduleFrequency(frequency)
        self.is_active = True
        self.created_by = created_by
        self.last_campaign_id: Optional[str] = None
        self.last_run_at: Optional[datetime] = None
        self.next_run_at: Optional[datetime] = self._compute_next_run()
        self.campaign_history: list[str] = []  # ordered campaign IDs
        self.created_at = datetime.now(timezone.utc)

    def _compute_next_run(self, from_time: Optional[datetime] = None) -> datetime:
        base = from_time or datetime.now(timezone.utc)
        if self.frequency == ScheduleFrequency.DAILY:
            return base + timedelta(days=1)
        else:  # weekly
            return base + timedelta(weeks=1)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "target_url": self.target_url,
            "probe_categories": self.probe_categories,
            "concurrency": self.concurrency,
            "timeout_seconds": self.timeout_seconds,
            "frequency": self.frequency.value,
            "is_active": self.is_active,
            "last_campaign_id": self.last_campaign_id,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "campaign_history": self.campaign_history,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

_schedules: dict[str, RedTeamSchedule] = {}
_alerts: dict[str, RegressionAlert] = {}
_scheduler_task: Optional[asyncio.Task] = None


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------


def create_schedule(
    name: str,
    target_url: str,
    probe_categories: Optional[list[str]] = None,
    concurrency: int = 10,
    timeout_seconds: int = 30,
    frequency: str = "daily",
    created_by: str = "admin",
) -> RedTeamSchedule:
    schedule = RedTeamSchedule(
        name=name,
        target_url=target_url,
        probe_categories=probe_categories,
        concurrency=concurrency,
        timeout_seconds=timeout_seconds,
        frequency=frequency,
        created_by=created_by,
    )
    _schedules[schedule.id] = schedule
    return schedule


def get_schedule(schedule_id: str) -> Optional[RedTeamSchedule]:
    return _schedules.get(schedule_id)


def list_schedules() -> list[dict]:
    return [s.to_dict() for s in sorted(
        _schedules.values(), key=lambda x: x.created_at, reverse=True
    )]


def update_schedule(schedule_id: str, **kwargs) -> Optional[RedTeamSchedule]:
    schedule = _schedules.get(schedule_id)
    if not schedule:
        return None
    for key, value in kwargs.items():
        if hasattr(schedule, key):
            if key == "frequency":
                value = ScheduleFrequency(value)
            setattr(schedule, key, value)
    if "frequency" in kwargs:
        schedule.next_run_at = schedule._compute_next_run()
    return schedule


def delete_schedule(schedule_id: str) -> bool:
    if schedule_id in _schedules:
        _schedules[schedule_id].is_active = False
        del _schedules[schedule_id]
        return True
    return False


# ---------------------------------------------------------------------------
# Regression detection
# ---------------------------------------------------------------------------


def detect_regression(
    schedule: RedTeamSchedule,
    current_campaign: Campaign,
    previous_campaign: Optional[Campaign],
) -> Optional[RegressionAlert]:
    """Compare current campaign results against previous run.

    A regression is any probe that detected a vulnerability in the current
    campaign but did NOT detect one in the previous campaign.
    """
    if not previous_campaign:
        return None

    current_detected = {r.probe_id for r in current_campaign.results if r.detected}
    previous_detected = {r.probe_id for r in previous_campaign.results if r.detected}

    new_vulns = current_detected - previous_detected
    if not new_vulns:
        return None

    # Determine highest severity among new vulnerabilities
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_severity = "info"
    for r in current_campaign.results:
        if r.probe_id in new_vulns and r.detected:
            if severity_rank.get(r.severity.value, 0) > severity_rank.get(max_severity, 0):
                max_severity = r.severity.value

    alert = RegressionAlert(
        schedule_id=schedule.id,
        current_campaign_id=current_campaign.id,
        previous_campaign_id=previous_campaign.id,
        new_probe_ids=sorted(new_vulns),
        severity=max_severity,
        message=(
            f"Regression detected: {len(new_vulns)} new vulnerabilities found "
            f"in schedule '{schedule.name}' that were not present in the "
            f"previous campaign run. Highest severity: {max_severity}."
        ),
    )
    _alerts[alert.id] = alert
    logger.warning(
        "Regression alert %s: %d new vulns in schedule %s",
        alert.id, len(new_vulns), schedule.id,
    )
    return alert


# ---------------------------------------------------------------------------
# Alert management
# ---------------------------------------------------------------------------


def list_alerts(schedule_id: Optional[str] = None) -> list[dict]:
    alerts = _alerts.values()
    if schedule_id:
        alerts = [a for a in alerts if a.schedule_id == schedule_id]
    return [a.to_dict() for a in sorted(alerts, key=lambda x: x.created_at, reverse=True)]


def acknowledge_alert(alert_id: str) -> bool:
    alert = _alerts.get(alert_id)
    if not alert:
        return False
    alert.acknowledged = True
    return True


# ---------------------------------------------------------------------------
# Scheduled campaign execution
# ---------------------------------------------------------------------------


async def execute_scheduled_campaign(schedule: RedTeamSchedule) -> Campaign:
    """Create and run a campaign for a schedule, then check for regressions."""
    campaign = create_campaign(
        name=f"{schedule.name} — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
        target_url=schedule.target_url,
        probe_categories=schedule.probe_categories,
        concurrency=schedule.concurrency,
        timeout_seconds=schedule.timeout_seconds,
        created_by=f"scheduler:{schedule.id}",
    )

    # Run the campaign
    await run_campaign(campaign)

    # Generate policy recommendations
    generate_recommendations(campaign)

    # Get previous campaign for regression check
    previous_campaign = None
    if schedule.last_campaign_id:
        previous_campaign = get_campaign(schedule.last_campaign_id)

    # Check for regression
    if previous_campaign:
        detect_regression(schedule, campaign, previous_campaign)

    # Update schedule state
    schedule.last_campaign_id = campaign.id
    schedule.last_run_at = datetime.now(timezone.utc)
    schedule.next_run_at = schedule._compute_next_run()
    schedule.campaign_history.append(campaign.id)

    logger.info(
        "Scheduled campaign completed: schedule=%s campaign=%s status=%s",
        schedule.id, campaign.id, campaign.status.value,
    )
    return campaign


# ---------------------------------------------------------------------------
# Background scheduler loop
# ---------------------------------------------------------------------------


async def _scheduler_loop():
    """Background loop that checks for due schedules and executes them."""
    logger.info("Red team scheduler started")
    while True:
        try:
            now = datetime.now(timezone.utc)
            for schedule in list(_schedules.values()):
                if not schedule.is_active:
                    continue
                if schedule.next_run_at and now >= schedule.next_run_at:
                    logger.info("Executing scheduled campaign: %s", schedule.name)
                    try:
                        await execute_scheduled_campaign(schedule)
                    except Exception:
                        logger.exception(
                            "Failed to execute scheduled campaign: %s", schedule.id
                        )
        except asyncio.CancelledError:
            logger.info("Red team scheduler stopped")
            return
        except Exception:
            logger.exception("Error in scheduler loop")

        await asyncio.sleep(60)  # Check every 60 seconds


def start_scheduler() -> asyncio.Task:
    """Start the background scheduler loop."""
    global _scheduler_task
    if _scheduler_task and not _scheduler_task.done():
        return _scheduler_task
    _scheduler_task = asyncio.ensure_future(_scheduler_loop())
    return _scheduler_task


def stop_scheduler():
    """Stop the background scheduler loop."""
    global _scheduler_task
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()
        _scheduler_task = None
