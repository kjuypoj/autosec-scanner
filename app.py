# app.py
import streamlit as st
import asyncio
import json
import os

# 우리가 만든 scanner.py에서 핵심 함수들만 수입(Import)해 옵니다!
from scanner import run_scan, generate_human_report

st.set_page_config(page_title="AutoSec Scanner", page_icon="🛡️", layout="wide")

st.title("🛡️ AutoSec Vulnerability Scanner")
st.markdown("**AI 기반 웹/인프라 자동화 취약점 진단 도구**")

# --- 1. 사이드바 (옵션 설정) ---
with st.sidebar:
    st.header("⚙️ 스캔 옵션")
    target_url = st.text_input("타겟 URL 입력", placeholder="http://127.0.0.1:8000")
    
    st.divider()
    
    st.subheader("고급 설정")
    safe_mode = st.checkbox("안전 모드 (파괴적 페이로드 금지)", value=False)
    verify_ssl = st.checkbox("SSL 인증서 검증", value=True)
    port_range = st.text_input("포트 스캔 범위", value="1-100")
    
    st.divider()
    
    st.subheader("🤖 AI 리포트 설정")
    openai_key = st.text_input("OpenAI API Key (선택)", type="password", help="키를 입력하면 AI가 요약 리포트를 작성해 줍니다.")

# --- 2. 메인 화면 (스캔 실행) ---
if st.button("🚀 스캔 시작", type="primary", use_container_width=True):
    if not target_url:
        st.error("타겟 URL을 입력해주세요!")
    else:
        # 포트 범위 파싱
        try:
            pmin, pmax = map(int, port_range.split("-"))
        except:
            pmin, pmax = 1, 1024

        st.info(f"[{target_url}] 스캔을 시작합니다. 잠시만 기다려주세요...")
        
        # 로딩 스피너 빙글빙글
        with st.spinner("해커 모드 가동 중... 보안 취약점을 탐색하고 있습니다 🕵️‍♂️"):
            try:
                # 비동기 스캐너 실행! (scanner.py의 run_scan 호출)
                report = asyncio.run(run_scan(
                    target=target_url,
                    safe_mode=safe_mode,
                    verify_ssl=verify_ssl,
                    port_range=(pmin, pmax)
                ))
                
                st.success("🎉 스캔 완료!")
                
                # --- 3. 결과 탭 나누기 ---
                tab1, tab2, tab3 = st.tabs(["📊 요약 리포트 (Human/AI)", "🔍 상세 취약점 내역", "💻 Raw JSON"])
                
                with tab1:
                    st.subheader("진단 결과 요약")
                    # AI 키가 있으면 API에 넘겨주고, 없으면 None으로 넘깁니다.
                    final_key = openai_key if openai_key else None
                    human_report = generate_human_report(report, openai_api_key=final_key)
                    # 텍스트 박스로 예쁘게 출력
                    st.text_area("Final Report", human_report, height=400, label_visibility="collapsed")
                
                with tab2:
                    st.subheader("탐지된 핵심 취약점")
                    res = report.get("results", {})
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if res.get("m5_xss"):
                            st.error(f"🚨 **XSS 취약점 발견!** ({len(res['m5_xss'])}건)")
                            st.write(res["m5_xss"])
                        if res.get("m6_sqli"):
                            st.error(f"🚨 **SQLi 취약점 발견!** ({len(res['m6_sqli'])}건)")
                            st.write(res["m6_sqli"])
                    with col2:
                        if res.get("m2_ports"):
                            vuln_ports = [p for p in res["m2_ports"] if p.get("cve")]
                            if vuln_ports:
                                st.error(f"🚨 **위험 포트 발견!** ({len(vuln_ports)}건)")
                                st.write(vuln_ports)
                        if res.get("m10_fuzz"):
                            st.warning(f"⚠️ **숨겨진 파일 노출!** ({len(res['m10_fuzz'])}건)")
                            st.write(res["m10_fuzz"])
                
                with tab3:
                    st.subheader("전체 로우 데이터")
                    st.json(report)

            except Exception as e:
                st.error(f"스캔 중 오류가 발생했습니다: {e}")