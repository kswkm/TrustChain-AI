# 시연 서비스 이미지 : 베이스 이미지 digest 고정, 비root 실행, 모델·AI-BOM 동봉
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS build
WORKDIR /build
COPY requirements.lock ./
# 해시 고정본으로만 설치 (재생성 : pip-compile --generate-hashes --allow-unsafe -o requirements.lock requirements.txt)
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock

FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /srv
COPY --from=build /opt/venv /opt/venv
COPY app ./app
COPY model/mnist.keras ./model/mnist.keras
COPY aibom.cdx.json ./aibom.cdx.json
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp KERAS_HOME=/tmp/.keras
USER 10001
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
