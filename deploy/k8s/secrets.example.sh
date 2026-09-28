#!/usr/bin/env sh
# trustchain-secrets 생성 예시. 값은 파일/비밀 저장소에서 읽고, 셸 히스토리·저장소에 남기지 않는다.
# 사용: PGPASS_FILE=./pg.pass DASH_TOKEN_FILE=./dash.token sh deploy/k8s/secrets.example.sh
set -eu
PG_PASS="$(cat "${PGPASS_FILE:?}")"
kubectl -n trustchain create secret generic trustchain-secrets \
  --from-literal=postgres-password="$PG_PASS" \
  --from-literal=database-url="postgresql+psycopg://trustchain:${PG_PASS}@postgres.trustchain.svc:5432/trustchain" \
  --from-file=dashboard-token="${DASH_TOKEN_FILE:?}" \
  ${LLM_KEY_FILE:+--from-file=llm-api-key="$LLM_KEY_FILE"} \
  ${SLACK_WEBHOOK_FILE:+--from-file=slack-webhook="$SLACK_WEBHOOK_FILE"} \
  --dry-run=client -o yaml | kubectl apply -f -
