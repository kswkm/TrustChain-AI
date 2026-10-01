# TrustChain AI 플랫폼 이미지 (수집 API · 피드 모니터 · AI 어시스턴트 · 대시보드 공용)
# 플랫폼 자체 이미지에도 SBOM·서명·출처 증명을 적용한다 (.github/workflows/ci.yml → trustchain-ci.yml)
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS build
WORKDIR /build
# 의존성은 해시 고정본(requirements.lock : server·dashboard·ai, PyTorch CPU 전용)으로만 설치한다 (개발기획서 2-6 공급망)
# 재생성 : pip-compile --generate-hashes --allow-unsafe --strip-extras --extra server --extra dashboard --extra ai
#          --extra-index-url https://download.pytorch.org/whl/cpu --no-emit-index-url -o requirements.lock pyproject.toml
COPY requirements.lock ./
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --require-hashes \
      --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.lock
COPY pyproject.toml README.md ./
COPY src ./src
# 프로젝트 자체는 로컬 소스이므로 의존성 해석 없이(--no-deps) 설치
RUN /opt/venv/bin/pip install --no-cache-dir --no-deps --no-build-isolation .

FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin trustchain
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TRUSTCHAIN_CACHE=/tmp/trustchain-cache HOME=/tmp
USER 10001
EXPOSE 8000 8501
CMD ["trustchain", "server", "--host", "0.0.0.0", "--port", "8000"]
