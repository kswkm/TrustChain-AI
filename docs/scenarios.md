# 공급망 공격 시연 시나리오 (개발기획서 3-5)

```bash
python scenarios/run_all.py --offline      # 기록된 PyPI 메타데이터 픽스처 사용 (CI)
python scenarios/run_all.py                # 실제 PyPI·OSV 조회
```

| # | 공격 | 재현 방법 | 차단 단계 | 로컬 재현 |
|---|---|---|---|---|
| 1 | AI 가 제안한 존재하지 않는 패키지 추가 | `requirements.txt` 에 `fastapi-auth-shield==1.2.0`, 코드에서 import | 개발 (F2) `TC-PKG-001` | ✅ |
| 2 | 유명 패키지와 비슷한 위장 패키지 | `reqeusts==2.31.0` (자리바꿈, 최근 등록, 저장소 없음) | 개발 (F3) `TC-PKG-002` | ✅ |
| 3 | SQL 삽입·하드코딩 비밀정보 커밋 | 문자열 결합 쿼리 + `DB_PASSWORD = "..."` | 개발 (F1) `TC-SQL-001`, `TC-SECRET-001` | ✅ |
| 4 | 악성 pickle 모델로 교체 | AI-BOM 생성 후 `__reduce__` → `os.system` 모델로 교체 | 빌드 (F5) `TC-MODEL-001` + AI-BOM 해시 불일치 | ✅ |
| 5 | 취약 OS 패키지 베이스 이미지 | Trivy 결과(`--vuln-image` 로 실제 스캔, 없으면 샘플 리포트) | 빌드 (F5) CRITICAL 게이트 · 지원 종료 OS(TC-IMG-006) | ✅ (실제 Trivy 실측) |
| 6 | 개발자 PC 에서 빌드한 서명 없는 이미지를 직접 push | 아래 절차 | 배포 (F8) Verify Gate | ✅ (GHCR 실측) |
| 7 | 검증을 우회해 kubectl 로 직접 배포 | 아래 절차 | 배포 (F9) Kyverno | ✅ (kind 실측) |

시나리오 2 를 실제 PyPI 로 실행하면 `reqeusts` 가 등록되어 있지 않아 환각(존재하지 않는 패키지) 규칙으로 차단될 수 있습니다.
어느 쪽이든 개발 단계에서 차단됩니다.

## 시나리오 6 : 서명 없는 이미지

```bash
# 개발자 PC 에서 CI 를 거치지 않고 직접 빌드·푸시
docker build -t ghcr.io/<owner>/mnist-api:hotfix demo/mnist-api
docker push ghcr.io/<owner>/mnist-api:hotfix
DIGEST=$(docker buildx imagetools inspect ghcr.io/<owner>/mnist-api:hotfix --format '{{json .Manifest.Digest}}' | tr -d '"')

python scenarios/run_all.py --image ghcr.io/<owner>/mnist-api@$DIGEST --repo github.com/<owner>/trustchain-ai
# 기대 결과: cosign 서명 FAIL (no matching signatures), SLSA 출처 증명 FAIL → Verify Gate 실패, 배포 차단
```

## 시나리오 7 : kubectl 직접 배포

실측 환경 : kind v0.33.0 (Kubernetes v1.37) + Kyverno v1.19.1, 정책은 CEL 기반 `ImageValidatingPolicy`·`ValidatingPolicy` (`policies.kyverno.io/v1`). 결과는 [evaluation.md](evaluation.md) 5절.

```bash
# 로컬 kind 클러스터로 재현 (실측에 사용한 절차)
kind create cluster --name trustchain-s7
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.19.1/install.yaml
kubectl -n kyverno wait --for=condition=Available deploy --all --timeout=300s
kubectl apply -f deploy/k8s/base/namespaces.yaml -f deploy/k8s/kyverno/verify-images.yaml -f deploy/k8s/kyverno/workload-hardening.yaml
python scenarios/run_all.py --offline --cluster --image ghcr.io/<owner>/mnist-api@$DIGEST
kind delete cluster --name trustchain-s7
```

```bash
# k3s + Kyverno 설치
curl -sfL https://get.k3s.io -o k3s-install.sh   # 설치 스크립트는 내용 확인 후 실행
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl apply -k deploy/k8s

python scenarios/run_all.py --cluster --image ghcr.io/<owner>/mnist-api@$DIGEST
# 기대 결과: admission webhook "ivpol.validate.kyverno.svc-fail-finegrained-trustchain-verify-images" denied the request:
#           Policy trustchain-verify-images failed: CI 워크플로우의 cosign 서명이 없습니다
```
