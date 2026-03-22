# frontend/app.py
"""
Streamlit 前端展示界面
风格：警务情报作战室 —— 深色系 + 红橙黄绿风险热力图
"""
import streamlit as st
import asyncio
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Streamlit Cloud Secrets → 环境变量（云端部署必需）
try:
    for key in ["GEMINI_API_KEY"]:
        if key not in os.environ and key in st.secrets:
            os.environ[key] = st.secrets[key]
except Exception:
    pass

st.set_page_config(
    page_title="涉诈网站智能研判系统",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;600;700&family=Share+Tech+Mono&display=swap');
  html, body, [class*="css"] { font-family: 'Noto Sans SC', sans-serif; }
  .risk-card-RED    { background:linear-gradient(135deg,#2d0a0a,#1a0505); border-left:4px solid #f44336; }
  .risk-card-ORANGE { background:linear-gradient(135deg,#2d1a0a,#1a0d05); border-left:4px solid #ff9800; }
  .risk-card-YELLOW { background:linear-gradient(135deg,#2d2a0a,#1a1805); border-left:4px solid #ffeb3b; }
  .risk-card-GREEN  { background:linear-gradient(135deg,#0a2d0a,#051a05); border-left:4px solid #4caf50; }
  .risk-card { padding:20px 24px; border-radius:8px; margin:16px 0; }
  .risk-score-big { font-size:64px; font-weight:700; font-family:'Share Tech Mono',monospace; line-height:1; }
  .feat-bar-bg { background:#1e2d3d; border-radius:3px; height:8px; margin-top:3px; }
  .intel-item { display:flex; justify-content:space-between; padding:8px 12px; border-bottom:1px solid #1e2d3d; font-size:13px; }
  .intel-key { color:#546e7a; font-family:'Share Tech Mono',monospace; }
  .intel-val { color:#eceff1; text-align:right; max-width:60%; word-break:break-all; }
  .kw-tag-high   { background:#3d0000;color:#ef9a9a;border:1px solid #b71c1c;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;display:inline-block; }
  .kw-tag-medium { background:#3d2000;color:#ffcc80;border:1px solid #e65100;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;display:inline-block; }
  .kw-tag-low    { background:#3d3d00;color:#fff176;border:1px solid #f9a825;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;display:inline-block; }
  .step-item { display:flex; align-items:flex-start; margin:10px 0; padding:8px 12px; background:#0a1628; border-radius:4px; font-size:14px; color:#b0bec5; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="background:linear-gradient(135deg,#0d1b2a,#1a2744);border:1px solid #1e3a5f;border-radius:8px;padding:20px 30px;margin-bottom:24px;">
  <div style="font-size:22px;font-weight:700;color:#4fc3f7;letter-spacing:2px;">🔍 涉诈网站智能研判与决策支持系统</div>
  <div style="font-size:12px;color:#546e7a;margin-top:4px;font-family:'Share Tech Mono',monospace;">OSINT-BASED FRAUD WEBSITE INTELLIGENT ASSESSMENT SYSTEM v1.0 | 仅限授权人员使用</div>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### ⚙️ 分析参数配置")
    priority = st.selectbox("任务优先级", ["normal", "urgent"], index=0)
    analyst_id = st.text_input("分析员工号", placeholder="如：P20240001")
    extra_kw_input = st.text_area("补充风险关键词（每行一个）", placeholder="如：\n安全账户\n资金核验", height=100)
    extra_keywords = [k.strip() for k in extra_kw_input.splitlines() if k.strip()]
    st.markdown("---")
    st.markdown("### 📋 风险等级说明")
    st.markdown("🔴 **RED ≥ 80** — 高危，立即处置\n\n🟠 **ORANGE 60~79** — 中高风险，重点监控\n\n🟡 **YELLOW 40~59** — 疑似风险，继续侦查\n\n🟢 **GREEN < 40** — 暂无风险，存档备查")
    st.markdown("---")
    st.markdown("### 🧪 快速测试")
    demo_urls = {"模拟高危投资诈骗": "quick-profit.xyz", "模拟境外赌博平台": "bet-win-now.top", "模拟正常政府网站": "www.beijing.gov.cn"}
    for label, demo_url in demo_urls.items():
        if st.button(label, use_container_width=True):
            st.session_state["target_url"] = demo_url

col_input, col_btn = st.columns([4, 1])
with col_input:
    url_input = st.text_input("", value=st.session_state.get("target_url", ""), placeholder="输入目标网址，如：suspicious-invest.com", label_visibility="collapsed")
with col_btn:
    analyze_btn = st.button("▶ 开始研判", use_container_width=True)

def risk_color(level):
    return {"RED":"#f44336","ORANGE":"#ff9800","YELLOW":"#ffeb3b","GREEN":"#4caf50"}.get(level,"#90a4ae")
def risk_emoji(level):
    return {"RED":"🔴","ORANGE":"🟠","YELLOW":"🟡","GREEN":"🟢"}.get(level,"⚪")

def render_bar(name, value, contrib):
    pct = int(value * 100)
    color = "#f44336" if value>0.7 else ("#ff9800" if value>0.4 else ("#ffeb3b" if value>0.2 else "#4caf50"))
    st.markdown(f"""<div style="margin:6px 0"><div style="display:flex;justify-content:space-between"><span style="font-size:12px;color:#78909c;font-family:'Share Tech Mono',monospace">{name}</span><span style="font-size:11px;color:#90a4ae">{pct}%  贡献:{contrib:.2f}分</span></div><div class="feat-bar-bg"><div style="background:{color};height:8px;border-radius:3px;width:{pct}%"></div></div></div>""", unsafe_allow_html=True)

if analyze_btn and url_input.strip():
    with st.spinner("🔄 正在执行多维度情报采集与研判分析..."):
        try:
            from backend.modules.pipeline import AnalysisPipeline
            from backend.models.schemas import AnalysisRequest
            request = AnalysisRequest(url=url_input.strip(), priority=priority, analyst_id=analyst_id or None, extra_keywords=extra_keywords)
            pipeline = AnalysisPipeline()
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(pipeline.run(request))
            loop.close()
        except Exception as e:
            st.error(f"分析失败：{e}")
            st.stop()

    if not result.success:
        st.error(f"❌ 分析异常：{result.error}")
        st.stop()

    report = result.report
    if report is None:
        st.error("❌ 报告数据为空")
        st.stop()
    wras = report.wras
    intel = report.raw_intel
    feat = report.features

    st.markdown(f"""<div class="risk-card risk-card-{wras.risk_level.value}">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;">
        <div>
          <div style="font-size:13px;color:#90a4ae;letter-spacing:1px;">综合风险评分</div>
          <div class="risk-score-big" style="color:{risk_color(wras.risk_level.value)}">{wras.final_score:.1f}</div>
          <div style="font-size:14px;color:#90a4ae;margin-top:8px">{risk_emoji(wras.risk_level.value)} {report.disposal.level} | 置信度 {wras.confidence_coeff:.0%} | {report.report_id}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:12px;color:#546e7a">原始分 × 置信度</div>
          <div style="font-family:'Share Tech Mono',monospace;color:#90a4ae;font-size:18px">{wras.raw_score:.1f} × {wras.confidence_coeff:.3f}</div>
          <div style="font-size:11px;color:#37474f;margin-top:8px">分析耗时: {result.elapsed_s:.1f}s</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    FEAT_LABELS = {
        "domain_age_days":"域名注册时长","icp_missing":"ICP备案缺失","whois_privacy_protected":"WHOIS信息隐藏",
        "ssl_self_signed":"SSL证书异常","ip_overseas":"服务器境外","ip_cdn_abuse":"CDN规避行为",
        "keyword_risk_score":"风险话术密度","phishing_visual_sim":"钓鱼仿冒相似度","resource_load_anomaly":"页面资源异常率",
        "public_sentiment_neg":"负面舆情强度","complaint_count_norm":"投诉量归一化","blacklist_hit":"黑名单命中",
    }

    gemini = getattr(report, "gemini", None)
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 风险热力图", "🔍 原始情报", "⚖️ 处置预案", "🤖 AI 智能分析", "📄 完整报告"])

    with tab1:
        ca, cb = st.columns(2)
        fd = feat.model_dump()
        items = [(k,v) for k,v in fd.items() if isinstance(v,(int,float))]
        half = len(items)//2
        with ca:
            st.markdown("**域名 · 网络维度**")
            for k,v in items[:half]:
                render_bar(FEAT_LABELS.get(k,k), v, wras.feature_contrib.get(k,0.0))
        with cb:
            st.markdown("**内容 · 舆情维度**")
            for k,v in items[half:]:
                render_bar(FEAT_LABELS.get(k,k), v, wras.feature_contrib.get(k,0.0))
        st.markdown("---")
        st.markdown("**各维度得分汇总**")
        cols = st.columns(len(wras.score_breakdown))
        for col, (dim, score) in zip(cols, wras.score_breakdown.items()):
            with col:
                c = "#f44336" if score>20 else ("#ff9800" if score>12 else ("#ffeb3b" if score>6 else "#4caf50"))
                st.markdown(f"""<div style="text-align:center;padding:12px;background:#0d1b2a;border-radius:6px;border:1px solid #1e3a5f"><div style="font-size:24px;font-weight:700;color:{c};font-family:'Share Tech Mono',monospace">{score:.1f}</div><div style="font-size:11px;color:#546e7a;margin-top:4px">{dim}</div></div>""", unsafe_allow_html=True)
        if any(feat.keyword_hits.values()):
            st.markdown("---\n**⚠️ 命中风险关键词**")
            for level, words in feat.keyword_hits.items():
                if words:
                    st.markdown(" ".join(f'<span class="kw-tag-{level}">{w}</span>' for w in words), unsafe_allow_html=True)
        if feat.sentiment_detail:
            st.markdown(f"**舆情：** {feat.sentiment_detail}")

    with tab2:
        cl, cr = st.columns(2)
        with cl:
            st.markdown("**📋 域名 / 注册信息**")
            for k,v in [("目标域名",intel.domain),("域名注册天数",f"{intel.domain_age_days or '未知'} 天"),("注册商",intel.registrar or "未知"),("WHOIS隐私","⚠️ 是" if intel.whois_privacy else "否"),("ICP备案",intel.icp_record or "⚠️ 无备案"),("SSL证书","有效" if intel.ssl_valid else "⚠️ 无效"),("SSL签发者",intel.ssl_issuer or "—"),("自签名","⚠️ 是" if intel.ssl_self_signed else "否"),("证书有效期",f"{intel.ssl_expiry_days or '—'} 天")]:
                st.markdown(f'<div class="intel-item"><span class="intel-key">{k}</span><span class="intel-val">{v}</span></div>', unsafe_allow_html=True)
        with cr:
            st.markdown("**🌐 服务器 / 网络信息**")
            for k,v in [("服务器IP",intel.server_ip or "—"),("所在国家",intel.server_country or "未知"),("ISP运营商",intel.server_isp or "—"),("CDN使用","⚠️ 是" if intel.is_cdn else "否"),("跳转链路",f"{len(intel.redirect_chain)} 跳"),("黑名单命中","⚠️ 是" if intel.blacklist_hit else "否"),("投诉量",f"{intel.complaint_count} 条")]:
                st.markdown(f'<div class="intel-item"><span class="intel-key">{k}</span><span class="intel-val">{v}</span></div>', unsafe_allow_html=True)
            if intel.search_snippets:
                st.markdown("**舆情摘要**")
                for s in intel.search_snippets:
                    st.markdown(f"> {s}")

    with tab3:
        rc = risk_color(wras.risk_level.value)
        st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:20px;margin:16px 0"><div style="font-size:18px;font-weight:700;color:{rc}">{risk_emoji(wras.risk_level.value)} {report.disposal.level}</div><div style="color:#b0bec5;margin-top:8px;font-size:14px">{report.disposal.action}</div></div>""", unsafe_allow_html=True)
        st.markdown("**📌 处置步骤**")
        for i, step in enumerate(report.disposal.steps, 1):
            st.markdown(f'<div class="step-item"><span style="color:{rc};font-weight:700;margin-right:12px">{i}</span><span>{step}</span></div>', unsafe_allow_html=True)
        st.markdown("---\n**🔬 XAI 研判依据（主要风险因子）**")
        XAI = {"keyword_risk_score":"页面含有高风险诈骗话术","icp_missing":"网站无ICP备案","domain_age_days":"域名注册时间极短","ip_overseas":"服务器位于境外","public_sentiment_neg":"网络存在大量负面投诉","blacklist_hit":"命中已知涉诈黑名单","ssl_self_signed":"使用自签名SSL证书","whois_privacy_protected":"WHOIS注册信息被隐藏","complaint_count_norm":"投诉平台有受害人记录"}
        for fn, contrib in sorted(wras.feature_contrib.items(), key=lambda x: x[1], reverse=True)[:5]:
            if contrib > 0:
                st.markdown(f"- **{XAI.get(fn, fn)}** （贡献 {contrib:.2f} 分）")

    with tab4:
        if gemini:
            # ── Gemini 来源标识 ──
            st.markdown(f"""<div style="background:#0a1628;border:1px solid #1b5e20;border-radius:6px;padding:10px 16px;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between">
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:18px">✦</span>
                <span style="color:#81c784;font-weight:600;font-size:13px">Powered by Google Gemini</span>
                <span style="color:#546e7a;font-size:12px;font-family:'Share Tech Mono',monospace;background:#0d2818;padding:2px 8px;border-radius:3px">{gemini.model_name}</span>
              </div>
              <span style="color:#546e7a;font-size:11px;font-family:'Share Tech Mono',monospace">AI 分析耗时 {gemini.ai_elapsed_s:.1f}s</span>
            </div>""", unsafe_allow_html=True)
            # ── AI 内容语义分析 ──
            st.markdown("### 🧠 AI 内容语义分析")
            ai_score = gemini.content_risk_score
            ai_color = "#f44336" if ai_score>0.7 else ("#ff9800" if ai_score>0.4 else ("#ffeb3b" if ai_score>0.2 else "#4caf50"))
            st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:16px;margin:8px 0">
              <div style="display:flex;align-items:center;gap:16px">
                <div style="font-size:36px;font-weight:700;color:{ai_color};font-family:'Share Tech Mono',monospace">{ai_score:.0%}</div>
                <div><div style="font-size:13px;color:#546e7a">AI 欺诈风险评分</div>
                <div style="color:#b0bec5;font-size:13px;margin-top:4px">{gemini.content_reasoning}</div></div>
              </div></div>""", unsafe_allow_html=True)

            if gemini.fraud_types:
                st.markdown("**检测到的欺诈类型：**")
                st.markdown(" ".join(f'<span class="kw-tag-high">{ft}</span>' for ft in gemini.fraud_types), unsafe_allow_html=True)

            if gemini.key_evidence:
                st.markdown("**关键证据：**")
                for ev in gemini.key_evidence:
                    st.markdown(f"- {ev}")

            # ── AI 视觉分析 ──
            if gemini.visual_risk_score > 0 or gemini.visual_features:
                st.markdown("---\n### 👁️ AI 视觉分析")
                vis_color = "#f44336" if gemini.visual_risk_score>0.7 else ("#ff9800" if gemini.visual_risk_score>0.4 else "#4caf50")
                phishing_tag = '  <span style="color:#f44336;font-weight:700">⚠️ 钓鱼网站</span>' if gemini.is_phishing else ""
                impersonate_tag = f'  仿冒目标：<span style="color:#ff9800;font-weight:700">{gemini.impersonates}</span>' if gemini.impersonates else ""
                st.markdown(f"""<div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:8px;padding:16px;margin:8px 0">
                  <div style="font-size:24px;font-weight:700;color:{vis_color};font-family:'Share Tech Mono',monospace">{gemini.visual_risk_score:.0%}</div>
                  <div style="font-size:13px;color:#546e7a">AI 视觉风险评分{phishing_tag}{impersonate_tag}</div>
                  <div style="color:#b0bec5;font-size:13px;margin-top:8px">{gemini.visual_description}</div>
                </div>""", unsafe_allow_html=True)
                if gemini.visual_features:
                    st.markdown("**可疑视觉特征：**")
                    for vf in gemini.visual_features:
                        st.markdown(f"- {vf}")

            # ── AI 侦查报告 ──
            if gemini.ai_report:
                st.markdown("---\n### 📝 AI 侦查报告")
                st.markdown(gemini.ai_report)
        else:
            st.info("⚠️ Gemini AI 未配置或分析未执行。请在 .env 中配置 GEMINI_API_KEY 以启用 AI 智能分析。")

    with tab5:
        report_dict = {"report_id":report.report_id,"analyzed_at":report.analyzed_at.isoformat(),"url":report.url,"wras_score":wras.final_score,"risk_level":wras.risk_level.value,"disposal_action":report.disposal.action,"feature_vector":{k:v for k,v in feat.model_dump().items() if isinstance(v,(int,float))},"feature_contributions":wras.feature_contrib,"score_breakdown":wras.score_breakdown}
        if gemini:
            report_dict["gemini_analysis"] = {"content_risk_score":gemini.content_risk_score,"fraud_types":gemini.fraud_types,"visual_risk_score":gemini.visual_risk_score,"is_phishing":gemini.is_phishing}
        st.json(report_dict)
        st.download_button(label="⬇ 下载 JSON 报告", data=json.dumps(report_dict, ensure_ascii=False, indent=2), file_name=f"{report.report_id}.json", mime="application/json")

elif analyze_btn:
    st.warning("⚠️ 请输入目标网址")
