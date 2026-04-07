"""Approval notification integrations — Slack bot + email.

Sends approval request notifications to configured channels so human approvers
can review and act on pending HITL requests.
"""

import json
import logging
from dataclasses import dataclass
from typing import Optional, Protocol

import httpx

logger = logging.getLogger("sphinx.hitl.notification")


class ApprovalNotifiable(Protocol):
    """Minimal interface for an approval request used by notifications."""
    id: str
    agent_id: str
    tenant_id: str
    action_description: str
    risk_context: dict
    risk_level: str
    risk_score: float
    matched_patterns: list[str]
    notification_channels: list[str]


@dataclass
class SlackConfig:
    """Slack integration configuration."""
    webhook_url: str
    channel: str = "#sphinx-approvals"
    bot_name: str = "Sphinx HITL Bot"
    approve_callback_url: str = ""
    reject_callback_url: str = ""


@dataclass
class EmailConfig:
    """Email integration configuration."""
    smtp_host: str = "localhost"
    smtp_port: int = 587
    from_address: str = "sphinx-hitl@example.com"
    to_addresses: list[str] | None = None
    use_tls: bool = True

    def __post_init__(self):
        if self.to_addresses is None:
            self.to_addresses = []


class SlackNotifier:
    """Send approval notifications via Slack webhook."""

    def __init__(self, config: SlackConfig):
        self.config = config

    async def send(self, request: ApprovalNotifiable) -> bool:
        """Send a Slack message with approval request details and action buttons."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":rotating_light: HITL Approval Required — {request.risk_level.upper()}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent ID:*\n`{request.agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Tenant:*\n`{request.tenant_id}`"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{request.risk_level}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{request.risk_score:.2f}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Action Description:*\n{request.action_description}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Matched Patterns:*\n{', '.join(request.matched_patterns) if request.matched_patterns else 'N/A'}",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": f"approve_{request.id}",
                        "value": request.id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "style": "danger",
                        "action_id": f"reject_{request.id}",
                        "value": request.id,
                    },
                ],
            },
        ]

        payload = {
            "channel": self.config.channel,
            "username": self.config.bot_name,
            "blocks": blocks,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.config.webhook_url, json=payload)
                if resp.status_code == 200:
                    logger.info("Slack notification sent for approval %s", request.id)
                    return True
                else:
                    logger.warning(
                        "Slack notification failed for approval %s: %d %s",
                        request.id, resp.status_code, resp.text,
                    )
                    return False
        except Exception:
            logger.exception("Failed to send Slack notification for approval %s", request.id)
            return False


class EmailNotifier:
    """Send approval notifications via email (SMTP)."""

    def __init__(self, config: EmailConfig):
        self.config = config

    async def send(self, request: ApprovalNotifiable) -> bool:
        """Send email notification with approval request details."""
        if not self.config.to_addresses:
            logger.warning("No email recipients configured; skipping email for approval %s", request.id)
            return False

        subject = f"[Sphinx HITL] Approval Required — {request.risk_level.upper()} — Agent {request.agent_id}"
        body = (
            f"HITL Approval Request\n"
            f"=====================\n\n"
            f"Approval ID: {request.id}\n"
            f"Agent ID:    {request.agent_id}\n"
            f"Tenant:      {request.tenant_id}\n"
            f"Risk Level:  {request.risk_level}\n"
            f"Risk Score:  {request.risk_score:.4f}\n\n"
            f"Action Description:\n{request.action_description}\n\n"
            f"Matched Patterns: {', '.join(request.matched_patterns) if request.matched_patterns else 'N/A'}\n\n"
            f"Risk Context:\n{json.dumps(request.risk_context, indent=2)}\n\n"
            f"Please approve or reject via the Sphinx Admin API:\n"
            f"  POST /approvals/{request.id}/approve\n"
            f"  POST /approvals/{request.id}/reject\n"
        )

        try:
            # Use asyncio-compatible email sending via smtplib in thread
            import asyncio
            import smtplib
            from email.mime.text import MIMEText

            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.config.from_address
            msg["To"] = ", ".join(self.config.to_addresses)

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._send_smtp, msg)
            logger.info("Email notification sent for approval %s", request.id)
            return True
        except Exception:
            logger.exception("Failed to send email notification for approval %s", request.id)
            return False

    def _send_smtp(self, msg) -> None:
        """Synchronous SMTP send (run in executor)."""
        import smtplib

        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
            if self.config.use_tls:
                server.starttls()
            server.send_message(msg)


class NotificationService:
    """Orchestrates sending approval notifications across configured channels."""

    def __init__(
        self,
        slack_notifier: Optional[SlackNotifier] = None,
        email_notifier: Optional[EmailNotifier] = None,
    ):
        self._slack = slack_notifier
        self._email = email_notifier

    async def send_approval_notification(self, request: ApprovalNotifiable) -> dict[str, bool]:
        """Send notifications to all configured channels. Returns per-channel success."""
        results: dict[str, bool] = {}
        channels = request.notification_channels

        if "slack" in channels and self._slack:
            results["slack"] = await self._slack.send(request)
        if "email" in channels and self._email:
            results["email"] = await self._email.send(request)

        if not results:
            logger.warning(
                "No notification channels configured/active for approval %s",
                request.id,
            )
        return results


# ── Singleton ─────────────────────────────────────────────────────────

_notification_service: Optional[NotificationService] = None


def get_notification_service(
    slack_config: Optional[SlackConfig] = None,
    email_config: Optional[EmailConfig] = None,
) -> NotificationService:
    global _notification_service
    if _notification_service is None:
        slack = SlackNotifier(slack_config) if slack_config else None
        email = EmailNotifier(email_config) if email_config else None
        _notification_service = NotificationService(
            slack_notifier=slack,
            email_notifier=email,
        )
    return _notification_service
