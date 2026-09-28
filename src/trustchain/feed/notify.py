"""Slack Webhook · 메일 알림.

설정(환경변수 / Kubernetes Secret)
- TRUSTCHAIN_SLACK_WEBHOOK : https://hooks.slack.com/services/...
- TRUSTCHAIN_SMTP_HOST, TRUSTCHAIN_SMTP_PORT(587), TRUSTCHAIN_SMTP_USER, TRUSTCHAIN_SMTP_PASSWORD,
  TRUSTCHAIN_MAIL_FROM, TRUSTCHAIN_MAIL_TO(쉼표 구분, 서비스 담당자 미지정 시 기본 수신자)
"""

from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from trustchain.core.http import CachedClient, HttpError
from trustchain.core.logging import get_logger

log = get_logger("trustchain.notify")
SLACK_PREFIX = "https://hooks.slack.com/"


@dataclass
class AlertMessage:
    service: str
    vuln_id: str
    severity: str
    component: str
    version: str | None
    summary: str
    fixed: list[str]
    recipients: list[str]

    def text(self) -> str:
        fix = f"{self.fixed[0]} 이상으로 업그레이드" if self.fixed else "패치 없음 - 완화 조치 검토"
        return (f"[TrustChain] {self.severity} {self.vuln_id} - 서비스 '{self.service}' 영향\n"
                f"구성요소: {self.component} {self.version or ''}\n요약: {self.summary[:300]}\n조치: {fix}")


class Notifier(Protocol):
    def send(self, msg: AlertMessage) -> bool: ...


class SlackNotifier:
    def __init__(self, webhook: str, http: CachedClient | None = None):
        # SSRF 방지 : Slack 웹훅 도메인만 허용
        if not webhook.startswith(SLACK_PREFIX):
            raise ValueError("Slack webhook URL 은 https://hooks.slack.com/ 으로 시작해야 합니다")
        self.webhook = webhook
        self.http = http or CachedClient()

    def send(self, msg: AlertMessage) -> bool:
        color = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825"}.get(msg.severity, "#607d8b")
        payload = {"text": msg.text(), "attachments": [{"color": color, "text": msg.summary[:500]}]}
        try:
            return self.http.post(self.webhook, payload) < 300
        except HttpError as e:
            log.warning("Slack 알림 실패: %s", e)
            return False


class MailNotifier:
    def __init__(self, host: str, port: int, user: str | None, password: str | None, sender: str,
                 default_to: list[str]):
        self.host, self.port, self.user, self.password = host, port, user, password
        self.sender, self.default_to = sender, default_to

    def send(self, msg: AlertMessage) -> bool:
        to = msg.recipients or self.default_to
        if not to:
            return False
        em = EmailMessage()
        em["Subject"] = f"[TrustChain] {msg.severity} {msg.vuln_id} - {msg.service}"
        em["From"] = self.sender
        em["To"] = ", ".join(to)
        em.set_content(msg.text())
        try:
            with smtplib.SMTP(self.host, self.port, timeout=10) as s:
                s.starttls(context=ssl.create_default_context())
                if self.user and self.password:
                    s.login(self.user, self.password)
                s.send_message(em)
            return True
        except (OSError, smtplib.SMTPException) as e:
            log.warning("메일 알림 실패: %s", e.__class__.__name__)
            return False


class MultiNotifier:
    def __init__(self, notifiers: list[Notifier]):
        self.notifiers = notifiers

    def send(self, msg: AlertMessage) -> bool:
        results = [n.send(msg) for n in self.notifiers]
        return any(results) if results else False


class MemoryNotifier:
    """테스트·시연용 : 전송 대신 목록에 기록."""

    def __init__(self) -> None:
        self.sent: list[AlertMessage] = []

    def send(self, msg: AlertMessage) -> bool:
        self.sent.append(msg)
        return True


def notifier_from_env() -> MultiNotifier:
    ns: list[Notifier] = []
    hook = os.environ.get("TRUSTCHAIN_SLACK_WEBHOOK")
    if hook:
        ns.append(SlackNotifier(hook))
    host = os.environ.get("TRUSTCHAIN_SMTP_HOST")
    if host:
        ns.append(MailNotifier(
            host, int(os.environ.get("TRUSTCHAIN_SMTP_PORT", "587")), os.environ.get("TRUSTCHAIN_SMTP_USER"),
            os.environ.get("TRUSTCHAIN_SMTP_PASSWORD"), os.environ.get("TRUSTCHAIN_MAIL_FROM", "trustchain@localhost"),
            [x.strip() for x in os.environ.get("TRUSTCHAIN_MAIL_TO", "").split(",") if x.strip()],
        ))
    return MultiNotifier(ns)
