# 涉诈网站智能研判与决策支持系统

> 基于开源情报（OSINT）的涉诈网站自动化研判与决策支持系统
> 技术顾问：Leslie (A1RER) | 业务逻辑：警校合作方

---

## 系统架构

```
URL输入
  ↓
[模块一] OSINT 采集层
  ├── 域名/WHOIS/DNS (DomainIntelCollector)
  ├── SSL 证书分析  (SSLIntelCollector)
  ├── 服务器地理    (GeoIPCollector)
  ├── 页面内容      (PageContentCollector / Playwright)
  └── 外部舆情      (SentimentCollector)
  ↓
[模块二] 特征工程层
  ├── 静态维度：域名年龄、ICP备案、WHOIS隐私、SSL异常
  ├── 网络维度：境外服务器、CDN规避
  ├── 内容维度：关键词NLP、pHash钓鱼检测、资源异常率
  └── 舆情维度：负面情感极性、投诉量、黑名单
  ↓
[模块三] WRAS 评分引擎
  公式：Risk_Score = Σ(W_i × F_i) × C_trust
  ├── W_i：业务专家权重（警校方提供）
  ├── F_i：特征向量（0~1 归一化）
  └── C_trust：置信度系数（时效性 × 多源验证）
  ↓
[模块四] 决策支持层
  ├── 风险分级（RED/ORANGE/YELLOW/GREEN）
  ├── 警务处置预案匹配
  └── XAI 可解释性热力图
  ↓
FastAPI 后端 + Streamlit 前端
```

---

## 目录结构

```
fraud_intel_system/
├── config/
│   └── settings.py          # 系统参数、权重、关键词库
├── backend/
│   ├── main.py              # FastAPI 服务
│   ├── models/
│   │   └── schemas.py       # Pydantic 数据模型
│   └── modules/
│       ├── osint_collector.py   # 情报采集
│       ├── feature_engineer.py  # 特征工程
│       ├── wras_engine.py       # 评分引擎
│       └── pipeline.py          # 流水线协调
├── frontend/
│   └── app.py               # Streamlit 界面
└── requirements.txt
```

---

## 快速启动

```bash
# 安装依赖
pip install -r requirements.txt
playwright install chromium   # 安装浏览器内核

# 启动后端 API
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# 启动前端界面
streamlit run frontend/app.py
```

---

## WRAS 权重说明

权重由警校业务方根据实战经验提供，当前配置如下：

| 特征维度 | 权重 | 说明 |
|---------|------|------|
| 风险话术密度 | 0.15 | 冒充公检法等高危话术 |
| 负面舆情强度 | 0.14 | 受害者投诉、媒体曝光 |
| ICP备案缺失 | 0.10 | 无备案网站违规运营 |
| 域名注册时长 | 0.08 | 新域名是典型诈骗特征 |
| 境外服务器 | 0.07 | 规避国内监管 |
| 钓鱼视觉相似度 | 0.12 | 仿冒官方页面 |
| ...其余维度 | ... | 详见 config/settings.py |

---

## 扩展方向

1. **模型升级**：接入 MacBERT / RoBERTa 中文分类模型替换规则NLP
2. **数据源扩展**：对接 12321.cn 举报平台API、反诈App数据
3. **知识图谱**：构建涉诈团伙关联图谱（域名/IP/手机号关联分析）
4. **反制溯源**：结合Maltego进行深度溯源链分析
5. **联动封堵**：对接运营商/IDC下架接口实现自动化处置
