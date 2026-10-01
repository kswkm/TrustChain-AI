"""F12. 웹 대시보드 (Streamlit) : 서비스별 신뢰 점수 · SBOM 조회 · 차단 이력 · 알림 · 자연어 질의응답.

실행 : TRUSTCHAIN_API=http://localhost:8000 TRUSTCHAIN_TOKEN=<reader 토큰> streamlit run src/trustchain/dashboard/app.py
대시보드는 수집 API 만 호출하며(DB 직접 접근 없음) reader 권한 토큰만 사용한다.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pandas as pd
import streamlit as st

API = os.environ.get("TRUSTCHAIN_API", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("TRUSTCHAIN_TOKEN", "")
SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}

st.set_page_config(page_title="TrustChain AI", page_icon="🛡️", layout="wide")


def api(method: str, path: str, **kw: Any) -> Any:
    try:
        r = httpx.request(method, API + path, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60, **kw)
    except httpx.HTTPError:
        st.error("수집 API 에 연결할 수 없습니다.")
        st.stop()
    if r.status_code == 401:
        st.error("인증 실패: TRUSTCHAIN_TOKEN 을 확인하세요.")
        st.stop()
    if r.status_code >= 400:
        st.error(f"요청 실패 (HTTP {r.status_code})")
        st.stop()
    return r.json()


@st.cache_data(ttl=30)
def services() -> list[dict[str, Any]]:
    return api("GET", "/api/v1/services")


def score_color(s: int) -> str:
    return "green" if s >= 80 else "orange" if s >= 50 else "red"


st.title("🛡️ TrustChain AI")
st.caption("코드 한 줄부터 배포된 서비스까지, 신뢰할 수 있는 구성요소만 통과시킨다")
if not TOKEN:
    st.warning("TRUSTCHAIN_TOKEN 환경변수(reader 권한)가 필요합니다.")
    st.stop()

tab_overview, tab_sbom, tab_events, tab_alerts, tab_ask = st.tabs(
    ["서비스 신뢰 점수", "SBOM 조회", "차단 이력", "취약점 알림", "AI 보안 어시스턴트"])

svcs = services()
names = [s["name"] for s in svcs]

with tab_overview:
    if not svcs:
        st.info("아직 수집된 서비스가 없습니다. CI 에서 `trustchain upload` 로 리포트를 전송하세요.")
    cols = st.columns(min(len(svcs), 4) or 1)
    for i, s in enumerate(svcs):
        with cols[i % len(cols)]:
            st.metric(s["name"], f"{s['trust_score']} / 100",
                      delta="게이트 통과" if s["last_gate_passed"] else ("게이트 실패" if s["last_gate_passed"] is False else "-"),
                      delta_color="normal" if s["last_gate_passed"] else "inverse")
            st.markdown(f":{score_color(s['trust_score'])}[{'█' * (s['trust_score'] // 10)}]")
            st.caption(f"구성요소 {s['components']}개 · 미해결 알림 {s['open_alerts']}건")
            with st.expander("감점 내역"):
                st.json(s.get("score_detail", {}))
    if svcs:
        sel = st.selectbox("최근 스캔 결과 보기", names, key="fsvc")
        findings = api("GET", f"/api/v1/services/{sel}/findings")
        if findings:
            df = pd.DataFrame([{"심각도": SEV_ICON.get(f["severity"], "") + " " + f["severity"], "룰": f["rule_id"],
                                "제목": f["title"], "위치": f"{f.get('file') or ''}:{f.get('line') or ''}",
                                "분류": f.get("category"), "KISA": f.get("kisa") or ""} for f in findings])
            st.dataframe(df, width="stretch", hide_index=True)
        else:
            st.success("발견된 문제가 없습니다.")

with tab_sbom:
    if names:
        c1, c2 = st.columns([1, 2])
        sel = c1.selectbox("서비스", names, key="ssvc")
        q = c2.text_input("구성요소 검색", max_chars=100)
        comps = api("GET", f"/api/v1/services/{sel}/components", params={"q": q} if q else None)
        df = pd.DataFrame(comps)
        if not df.empty:
            models = df[df["type"] == "machine-learning-model"]
            st.caption(f"구성요소 {len(df)}개 (AI 모델 {len(models)}개)")
            st.dataframe(df, width="stretch", hide_index=True)
        else:
            st.info("SBOM 이 없습니다.")

with tab_events:
    only_blocked = st.toggle("차단된 이벤트만", value=True)
    ev = api("GET", "/api/v1/events", params={"blocked_only": str(only_blocked).lower(), "limit": 200})
    if ev:
        df = pd.DataFrame(ev)
        df["결과"] = df["passed"].map({True: "✅ 통과", False: "⛔ 차단"})
        st.dataframe(df[["created_at", "service", "stage", "결과", "image", "reason"]], width="stretch",
                     hide_index=True)
        st.bar_chart(df.groupby("stage").size())
    else:
        st.info("이력이 없습니다.")

with tab_alerts:
    al = api("GET", "/api/v1/alerts", params={"limit": 200})
    if al:
        df = pd.DataFrame(al)
        df["심각도"] = df["severity"].map(lambda s: SEV_ICON.get(s, "") + " " + s)
        st.dataframe(df[["matched_at", "notified_at", "service", "심각도", "vuln_id", "component", "version", "fixed"]],
                     width="stretch", hide_index=True)
    else:
        st.success("미해결 취약점 알림이 없습니다.")

with tab_ask:
    st.caption("취약점 권고문·CWE·KISA 시큐어코딩 가이드를 검색해 근거와 함께 답합니다. 근거가 없으면 모른다고 답합니다.")
    svc = st.selectbox("서비스 맥락 (선택)", ["(없음)"] + names, key="asvc")
    if "history" not in st.session_state:
        st.session_state.history = []
    for role, content in st.session_state.history:
        st.chat_message(role).markdown(content)
    question = st.chat_input("예: 우리 서비스에서 가장 먼저 고쳐야 할 취약점은? / pickle 모델을 안전하게 로드하려면?")
    if question:
        st.chat_message("user").markdown(question)
        body: dict[str, Any] = {"question": question[:2000]}
        if svc != "(없음)":
            body["service"] = svc
        res = api("POST", "/api/v1/assistant/ask", json=body)
        text = res["answer"]
        if res.get("priorities"):
            text += "\n\n**위험 우선순위**\n" + "\n".join(
                f"{p['rank']}. `{p['id']}` {p.get('package') or ''} — 점수 {p['score']} ({', '.join(p['reasons'])})"
                for p in res["priorities"][:5])
        if res["citations"]:
            text += "\n\n**근거 문서**\n" + "\n".join(
                f"[{c['n']}] {c['title']}" + (f" — {c['url']}" if c.get("url") else "") for c in res["citations"])
        if not res["grounded"]:
            text += "\n\n⚠️ 근거가 확인되지 않은 답변입니다."
        st.chat_message("assistant").markdown(text)
        st.session_state.history += [("user", question), ("assistant", text)]
