#!/usr/bin/env bash
# kind(Kubernetes in Docker) 임시 클러스터에 deploy/k8s 를 그대로 적용하고 실제 배포·차단을 확인한다.
#   - Calico(NetworkPolicy 집행) + Kyverno(F9 Admission Control) 설치
#   - Verify Gate 를 통과한 서명 이미지(digest)를 Deployment 로 배포 → 준비 완료까지 확인
#   - 서명 없는 이미지·digest 없는 이미지는 Admission 에서 거부되는지 확인
#   - 시연 서비스 NetworkPolicy : 수신 8080 허용, 송신 전부 차단 확인
#   - (PLATFORM_IMAGE 지정 시) trustchain 네임스페이스 플랫폼 배포, API→DB 왕복, 대시보드→DB 직접 접속 차단
# 비용 없는 검증용 클러스터 (GitHub Actions 러너 또는 개발자 PC 의 Docker). 클러스터는 끝나면 삭제한다.
#
# 사용: IMAGE=ghcr.io/kswkm/mnist-api DIGEST=sha256:... UNSIGNED=ghcr.io/kswkm/mnist-api@sha256:... \
#       [PLATFORM_IMAGE=ghcr.io/kswkm/trustchain-platform@sha256:...] deploy/kind/verify.sh
set -euo pipefail

: "${IMAGE:?서명된 이미지 (ghcr.io/owner/name)}" "${DIGEST:?sha256:...}" "${UNSIGNED:?서명 없는 이미지@digest}"
CLUSTER="${CLUSTER:-trustchain-verify}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
CALICO_URL="https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml"
CALICO_SHA256="be59408bf990e96276f631d2f9285c2a0f9802194c0ad1cecdb6d9c52623a1c8"
KYVERNO_URL="https://github.com/kyverno/kyverno/releases/download/v1.19.1/install.yaml"
KYVERNO_SHA256="d3322cb346d3d42dd0f41e230b0d1d7bc5619960e1c36fdac4d9151d724b88e6"
CURL_IMAGE="docker.io/curlimages/curl@sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40" # 8.17.0
FAILED=0
RESULTS=()

cleanup() {
  [ "${KEEP_CLUSTER:-0}" = "1" ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

record() { # record <통과 여부 0/1> <항목> <근거>
  if [ "$1" = "0" ]; then RESULTS+=("| ✅ | $2 | $3 |"); else RESULTS+=("| ❌ | $2 | $3 |"); FAILED=1; fi
  echo "[$([ "$1" = "0" ] && echo PASS || echo FAIL)] $2 — $3"
}

fetch() { # fetch <url> <sha256> <파일> : 고정 해시가 다르면 중단
  curl -fsSL "$1" -o "$3"
  echo "$2  $3" | sha256sum -c - >/dev/null
}

echo "== kind 클러스터 (기본 CNI 끄고 Calico 사용)"
cat >"$WORK/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
kind create cluster --name "$CLUSTER" --config "$WORK/kind.yaml" --wait 0s
fetch "$CALICO_URL" "$CALICO_SHA256" "$WORK/calico.yaml"
kubectl apply -f "$WORK/calico.yaml" >/dev/null
kubectl wait --for=condition=Ready nodes --all --timeout=300s
kubectl -n kube-system rollout status ds/calico-node --timeout=300s

echo "== Kyverno 설치"
fetch "$KYVERNO_URL" "$KYVERNO_SHA256" "$WORK/kyverno.yaml"
kubectl create -f "$WORK/kyverno.yaml" >/dev/null
kubectl -n kyverno wait --for=condition=Available deploy --all --timeout=300s

echo "== 네임스페이스·정책 적용"
kubectl apply -f "$ROOT/deploy/k8s/base/namespaces.yaml"
kubectl apply -f "$ROOT/deploy/k8s/kyverno/verify-images.yaml" -f "$ROOT/deploy/k8s/kyverno/workload-hardening.yaml"
# 정책이 Admission 웹훅으로 등록될 때까지 대기 (등록 전 요청은 정책 없이 통과하므로 검증이 무의미해짐)
kubectl wait --for=jsonpath='{.status.conditionStatus.ready}'=true --timeout=300s \
  imagevalidatingpolicy/trustchain-verify-images validatingpolicy/trustchain-workload-hardening

deploy_manifest() { # deploy_manifest <이미지 참조> <Deployment 이름>
  sed -e "s#ghcr.io/kswkm/mnist-api@sha256:0\{64\}#$1#" -e "s#name: mnist-api, namespace: app }#name: $2, namespace: app }#" \
    "$ROOT/deploy/k8s/base/mnist-api.yaml"
}

deployment_only() { # 여러 문서 YAML 에서 Deployment 문서만 출력
  python3 -c 'import re, sys; d = re.split(r"^---$", sys.stdin.read(), flags=re.M); print(next(x for x in d if re.search(r"^kind: Deployment$", x, re.M)).strip())'
}

echo "== 1) Verify Gate 통과 digest 배포 (Kyverno 가 서명·SLSA 출처 증명·SBOM 증명을 다시 검증)"
deploy_manifest "$IMAGE@$DIGEST" mnist-api >"$WORK/app.yaml"
if out="$(kubectl apply -f "$WORK/app.yaml" 2>&1)" && kubectl -n app rollout status deploy/mnist-api --timeout=600s; then
  record 0 "서명 이미지 배포 허용·준비 완료" "\`$IMAGE@${DIGEST:0:19}…\` replicas 2/2 Ready"
else
  record 1 "서명 이미지 배포 허용·준비 완료" "$(echo "$out" | tail -1 | cut -c1-200)"
  kubectl -n app describe deploy/mnist-api | tail -20 || true
fi

echo "== 2) 서명 없는 이미지를 kubectl 로 직접 배포 (Verify Gate 우회, 시나리오 7)"
deploy_manifest "$UNSIGNED" bypass-test | deployment_only >"$WORK/bypass.yaml"
if out="$(kubectl create --dry-run=server -f "$WORK/bypass.yaml" 2>&1)"; then
  record 1 "서명 없는 이미지 거부" "허용됨: $out"
elif [[ "$out" == *trustchain-verify-images* ]]; then
  record 0 "서명 없는 이미지 거부" "$(echo "$out" | grep -o 'CI 워크플로우의 cosign 서명이 없습니다' | head -1) (trustchain-verify-images)"
else
  record 1 "서명 없는 이미지 거부" "다른 원인으로 실패: $(echo "$out" | tail -1 | cut -c1-200)"
fi

echo "== 3) digest 없는 태그 이미지"
sed -e "s#$IMAGE@$DIGEST#docker.io/library/nginx:1.27#" -e 's#name: mnist-api, namespace: app }#name: tag-test, namespace: app }#' \
  "$WORK/app.yaml" | deployment_only >"$WORK/tag.yaml"
if out="$(kubectl create --dry-run=server -f "$WORK/tag.yaml" 2>&1)"; then
  record 1 "digest 없는 이미지 거부" "허용됨: $out"
elif [[ "$out" == *trustchain-workload-hardening* ]]; then
  record 0 "digest 없는 이미지 거부" "trustchain-workload-hardening"
else
  record 1 "digest 없는 이미지 거부" "다른 원인으로 실패: $(echo "$out" | tail -1 | cut -c1-200)"
fi

echo "== 4) NetworkPolicy (Calico 가 집행)"
kubectl create namespace nettest >/dev/null
kubectl -n nettest run probe --image="$CURL_IMAGE" --restart=Never --command -- sleep 3600 >/dev/null
kubectl -n nettest wait --for=condition=Ready pod/probe --timeout=180s >/dev/null
if code="$(kubectl -n nettest exec probe -- curl -s -o /dev/null -w '%{http_code}' -m 10 http://mnist-api.app.svc/healthz)" && [ "$code" = "200" ]; then
  record 0 "다른 네임스페이스 → 시연 서비스 8080 허용" "HTTP $code"
else
  record 1 "다른 네임스페이스 → 시연 서비스 8080 허용" "HTTP ${code:-연결 실패}"
fi
# 대조군 : 정책이 없는 Pod 는 외부로 나갈 수 있어야 차단 결과가 의미 있다
if kubectl -n nettest exec probe -- curl -s -o /dev/null -m 10 https://1.1.1.1 >/dev/null 2>&1; then ctrl=0; else ctrl=1; fi
egress_py="import socket; socket.create_connection(('1.1.1.1', 443), timeout=5)"
if kubectl -n app exec deploy/mnist-api -- python -c "$egress_py" >/dev/null 2>&1; then
  record 1 "시연 서비스 → 외부 송신 차단" "연결됨 (차단 실패)"
elif [ "$ctrl" = "0" ]; then
  record 0 "시연 서비스 → 외부 송신 차단" "1.1.1.1:443 연결 실패 (대조군 nettest Pod 는 같은 주소 연결 성공)"
else
  record 1 "시연 서비스 → 외부 송신 차단" "대조군도 외부 연결 실패 — 판정 불가"
fi

if [ -n "${PLATFORM_IMAGE:-}" ]; then
  echo "== 5) trustchain 네임스페이스 : PostgreSQL(pgvector)·수집 API·대시보드·피드 CronJob"
  pg_pass="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
  kubectl -n trustchain create secret generic trustchain-secrets \
    --from-literal=postgres-password="$pg_pass" \
    --from-literal=database-url="postgresql+psycopg://trustchain:${pg_pass}@postgres.trustchain.svc:5432/trustchain" \
    --from-literal=dashboard-token="pending" >/dev/null
  sed "s#ghcr.io/kswkm/trustchain-platform@sha256:0\{64\}#$PLATFORM_IMAGE#" "$ROOT/deploy/k8s/base/trustchain.yaml" >"$WORK/platform.yaml"
  kubectl apply -f "$WORK/platform.yaml" -f "$ROOT/deploy/k8s/base/networkpolicy.yaml" >/dev/null
  if kubectl -n trustchain rollout status statefulset/postgres --timeout=300s &&
    kubectl -n trustchain rollout status deploy/trustchain-api --timeout=600s &&
    kubectl -n trustchain rollout status deploy/trustchain-dashboard --timeout=300s; then
    record 0 "플랫폼 배포 (PSA restricted·워크로드 정책 통과)" "postgres·trustchain-api·trustchain-dashboard Ready"
  else
    record 1 "플랫폼 배포 (PSA restricted·워크로드 정책 통과)" "준비 실패"
    kubectl -n trustchain get pods,events 2>&1 | tail -20 || true
  fi
  # 관리자 토큰으로 수집 API → PostgreSQL 왕복 확인 (대시보드 Pod 에서 호출 : NetworkPolicy 가 허용하는 경로)
  token="$(kubectl -n trustchain exec deploy/trustchain-api -- trustchain token --name kind-verify --role admin 2>/dev/null | tail -1 | tr -d '\r')"
  probe_py='import json, os, sys, urllib.request as u
r = u.Request("http://trustchain-api.trustchain.svc:8000/api/v1/services", headers={"Authorization": "Bearer " + sys.argv[1]})
print(u.urlopen(r, timeout=10).status)'
  if code="$(kubectl -n trustchain exec deploy/trustchain-dashboard -- python -c "$probe_py" "$token" 2>&1 | tail -1)" && [ "$code" = "200" ]; then
    record 0 "대시보드 → 수집 API → DB 조회" "토큰 인증 후 /api/v1/services HTTP 200"
  else
    record 1 "대시보드 → 수집 API → DB 조회" "$(echo "$code" | cut -c1-200)"
  fi
  if kubectl -n trustchain exec deploy/trustchain-dashboard -- python -c \
    "import socket; socket.create_connection(('postgres.trustchain.svc', 5432), timeout=5)" >/dev/null 2>&1; then
    record 1 "대시보드 → DB 직접 접속 차단" "연결됨 (차단 실패)"
  else
    record 0 "대시보드 → DB 직접 접속 차단" "postgres:5432 연결 실패 (DB 는 API 에서만 접근)"
  fi
fi

{
  echo "### kind 클러스터 실제 배포·차단 결과"
  echo
  echo "kind $(kind version | awk '{print $2}') · Kubernetes $(kubectl version -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])') · Calico v3.28.2 · Kyverno v1.19.1"
  echo
  echo "| 결과 | 항목 | 근거 |"
  echo "|---|---|---|"
  printf '%s\n' "${RESULTS[@]}"
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
exit "$FAILED"
