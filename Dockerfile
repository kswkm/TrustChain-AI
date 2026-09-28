# TrustChain AI 플랫폼 이미지 (수집 API · 피드 모니터 · AI 어시스턴트 · 대시보드 공용)
# 플랫폼 자체 이미지에도 SBOM·서명·출처 증명을 적용한다 (.github/workflows/ci.yml → trustchain-ci.yml)
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS build
# 다국어 임베딩·리랭커(sentence-transformers)까지 포함하려면: --build-arg EXTRAS=server,dashboard,ai
ARG EXTRAS=server,dashboard
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir ".[${EXTRAS}]"

FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin trustchain
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TRUSTCHAIN_CACHE=/tmp/trustchain-cache HOME=/tmp
USER 10001
EXPOSE 8000 8501
CMD ["trustchain", "server", "--host", "0.0.0.0", "--port", "8000"]
