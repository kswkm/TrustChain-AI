"""로그의 토큰·비밀정보·개인정보 마스킹.

로그 핸들러에 MaskingFilter 를 붙이면 메시지와 인자 모두에서 민감정보가 제거된다.
"""

from __future__ import annotations

import logging
import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # GitHub 토큰 (ghp_, gho_, ghs_, github_pat_)
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "[GITHUB_TOKEN]"),
    # 플랫폼 API 토큰
    (re.compile(r"\btc_[A-Za-z0-9_\-]{16,}\b"), "[TRUSTCHAIN_TOKEN]"),
    # AWS Access Key
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[AWS_KEY]"),
    # Slack
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[SLACK_TOKEN]"),
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "https://hooks.slack.com/services/[MASKED]"),
    # LLM API 키
    (re.compile(r"\bsk-(ant-)?[A-Za-z0-9_\-]{16,}\b"), "[API_KEY]"),
    # Authorization 헤더 / Bearer
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/]+=*"), r"\1[MASKED]"),
    # key=value 형태 비밀정보
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b(\s*[:=]\s*)(['\"]?)[^\s'\",]+"),
        r"\1\2\3[MASKED]",
    ),
    # 개인정보 : 이메일, 주민등록번호, 휴대전화
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b\d{6}-[1-4]\d{6}\b"), "[RRN]"),
    (re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b"), "[PHONE]"),
]


def mask(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


class MaskingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # 포맷 오류가 있어도 로그를 잃지 않는다
            msg = str(record.msg)
        record.msg = mask(msg)
        record.args = None
        return True


def get_logger(name: str = "trustchain") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        h.addFilter(MaskingFilter())
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
