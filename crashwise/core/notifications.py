# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Universal Notification Router — dispatches vulnerability alerts via
webhooks (Slack/Discord) and secure email (SMTP with optional PGP).

Designed to be **standalone** — no external SaaS dependencies.  All
integrations use standard protocols (HTTP POST, SMTP) so CrashWise
remains fully self-hosted.

Usage::

    from crashwise.core.notifications import NotificationRouter

    router = NotificationRouter()
    await router.send(
        title="Critical UAF in libpng",
        body="...",
        severity="critical",
        cvss_score=9.1,
    )
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)


# ── Configuration dataclass ──────────────────────────────────────────────────


@dataclass(frozen=True)
class NotificationConfig:
    """Runtime notification settings."""

    webhook_url: str | None = None
    webhook_format: str = "slack"  # "slack" | "discord" | "generic"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "crashwise@localhost"
    smtp_to: list[str] | None = None
    pgp_public_key: str | None = None
    enabled: bool = False
    min_cvss_threshold: float = 7.0

    @classmethod
    def from_settings(cls) -> "NotificationConfig":
        """Build config from environment / settings."""
        settings = get_settings()
        return cls(
            webhook_url=getattr(settings, "webhook_url", None),
            webhook_format=getattr(settings, "webhook_format", "slack"),
            smtp_host=getattr(settings, "smtp_host", None),
            smtp_port=getattr(settings, "smtp_port", 587),
            smtp_user=getattr(settings, "smtp_user", None),
            smtp_password=getattr(settings, "smtp_password", None),
            smtp_from=getattr(settings, "smtp_from", "crashwise@localhost"),
            smtp_to=getattr(settings, "smtp_to", None),
            pgp_public_key=getattr(settings, "pgp_public_key", None),
            enabled=getattr(settings, "notifications_enabled", False),
            min_cvss_threshold=getattr(settings, "min_cvss_threshold", 7.0),
        )


# ── Router ───────────────────────────────────────────────────────────────────


class NotificationRouter:
    """Dispatch alerts to configured channels."""

    def __init__(self, config: NotificationConfig | None = None) -> None:
        self.config = config or NotificationConfig.from_settings()

    async def send(
        self,
        *,
        title: str,
        body: str,
        severity: str,
        cvss_score: float,
        cvss_vector: str = "",
        target: str = "",
        crash_id: str = "",
    ) -> dict[str, bool]:
        """Send notification to all configured channels.

        Returns
        -------
        dict mapping channel name → success bool.
        """
        if not self.config.enabled:
            log.debug("notifications.disabled")
            return {}

        if cvss_score < self.config.min_cvss_threshold:
            log.debug(
                "notifications.below_threshold",
                cvss=cvss_score,
                threshold=self.config.min_cvss_threshold,
            )
            return {}

        results: dict[str, bool] = {}

        # Webhook.
        if self.config.webhook_url:
            results["webhook"] = await self._send_webhook(
                title=title,
                body=body,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                target=target,
                crash_id=crash_id,
            )

        # Email.
        if self.config.smtp_host and self.config.smtp_to:
            results["email"] = await self._send_email(
                title=title,
                body=body,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                target=target,
                crash_id=crash_id,
            )

        log.info("notifications.sent", channels=list(results.keys()), results=results)
        return results

    # ── Webhook ──────────────────────────────────────────────────────────

    async def _send_webhook(
        self,
        *,
        title: str,
        body: str,
        severity: str,
        cvss_score: float,
        cvss_vector: str,
        target: str,
        crash_id: str,
    ) -> bool:
        """POST a JSON payload to the webhook URL."""
        if not self.config.webhook_url:
            return False

        fmt = self.config.webhook_format.lower()
        if fmt == "slack":
            payload = _build_slack_payload(title, severity, cvss_score, target, crash_id)
        elif fmt == "discord":
            payload = _build_discord_payload(title, severity, cvss_score, target, crash_id)
        else:
            payload = {
                "title": title,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "target": target,
                "crash_id": crash_id,
                "body_preview": body[:500],
            }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    self.config.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                log.info("notifications.webhook.ok", status=resp.status_code)
                return True
        except Exception as exc:
            log.warning("notifications.webhook.failed", error=str(exc))
            return False

    # ── Email ──────────────────────────────────────────────────────────────

    async def _send_email(
        self,
        *,
        title: str,
        body: str,
        severity: str,
        cvss_score: float,
        cvss_vector: str,
        target: str,
        crash_id: str,
    ) -> bool:
        """Send SMTP email with optional PGP encryption."""
        if not self.config.smtp_host or not self.config.smtp_to:
            return False

        subject = f"[CrashWise] {severity.upper()}: {title} (CVSS {cvss_score})"
        text_body = (
            f"CrashWise Alert\n"
            f"{'=' * 60}\n\n"
            f"Title:      {title}\n"
            f"Target:     {target}\n"
            f"Severity:   {severity}\n"
            f"CVSS:       {cvss_score} ({cvss_vector})\n"
            f"Crash ID:   {crash_id}\n\n"
            f"{'=' * 60}\n\n"
            f"{body}\n"
        )

        # Optional PGP encryption.
        if self.config.pgp_public_key:
            try:
                text_body = _pgp_encrypt(text_body, self.config.pgp_public_key)
                subject = f"[CrashWise] [PGP] {subject}"
            except Exception as exc:
                log.warning("notifications.pgp_encrypt_failed", error=str(exc))

        # Build MIME message.
        try:
            import aiosmtplib
            from email.message import EmailMessage

            msg = EmailMessage()
            msg["From"] = self.config.smtp_from
            msg["To"] = ", ".join(self.config.smtp_to)
            msg["Subject"] = subject
            msg.set_content(text_body)

            await aiosmtplib.send(
                msg,
                hostname=self.config.smtp_host,
                port=self.config.smtp_port,
                username=self.config.smtp_user,
                password=self.config.smtp_password,
                use_tls=self.config.smtp_port == 465,
                start_tls=self.config.smtp_port == 587,
            )
            log.info("notifications.email.ok", to=self.config.smtp_to)
            return True
        except ImportError:
            log.warning("notifications.email.missing_deps", hint="pip install aiosmtplib")
            return False
        except Exception as exc:
            log.warning("notifications.email.failed", error=str(exc))
            return False


# ── Payload builders ─────────────────────────────────────────────────────────


def _build_slack_payload(
    title: str,
    severity: str,
    cvss_score: float,
    target: str,
    crash_id: str,
) -> dict[str, Any]:
    color = "#dc2626" if cvss_score >= 9 else "#ea580c" if cvss_score >= 7 else "#ca8a04"
    return {
        "attachments": [
            {
                "color": color,
                "title": f"CrashWise Alert: {title}",
                "fields": [
                    {"title": "Target", "value": target, "short": True},
                    {"title": "Severity", "value": severity.upper(), "short": True},
                    {"title": "CVSS", "value": str(cvss_score), "short": True},
                    {"title": "Crash ID", "value": crash_id, "short": True},
                ],
                "footer": "CrashWise",
                "ts": int(__import__("time").time()),
            }
        ]
    }


def _build_discord_payload(
    title: str,
    severity: str,
    cvss_score: float,
    target: str,
    crash_id: str,
) -> dict[str, Any]:
    color = 0xDC2626 if cvss_score >= 9 else 0xEA580C if cvss_score >= 7 else 0xCA8A04
    return {
        "embeds": [
            {
                "title": f"CrashWise Alert: {title}",
                "color": color,
                "fields": [
                    {"name": "Target", "value": target, "inline": True},
                    {"name": "Severity", "value": severity.upper(), "inline": True},
                    {"name": "CVSS", "value": str(cvss_score), "inline": True},
                    {"name": "Crash ID", "value": crash_id, "inline": True},
                ],
                "footer": {"text": "CrashWise"},
                "timestamp": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
            }
        ]
    }


# ── PGP helper ───────────────────────────────────────────────────────────────


def _pgp_encrypt(plaintext: str, public_key_armor: str) -> str:
    """Encrypt *plaintext* with the provided PGP public key.

    Uses ``python-gnupg`` if available; otherwise raises ImportError.
    """
    try:
        import gnupg
    except ImportError as exc:
        raise ImportError("python-gnupg is required for PGP encryption") from exc

    gpg = gnupg.GPG()
    import_result = gpg.import_keys(public_key_armor)
    if not import_result.fingerprints:
        raise ValueError("Failed to import PGP public key")

    encrypted = gpg.encrypt(
        plaintext,
        import_result.fingerprints[0],
        always_trust=True,
    )
    if not encrypted.ok:
        raise RuntimeError(f"PGP encryption failed: {encrypted.stderr}")
    return str(encrypted)


__all__ = ["NotificationRouter", "NotificationConfig"]
