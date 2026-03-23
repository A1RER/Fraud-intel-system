# 涉诈网站智能研判与决策支持系统

> 基于开源情报（OSINT）的涉诈网站自动化研判与决策支持系统，面向公安反诈业务场景，实现对可疑网站的快速情报采集、多维特征评估与风险分级处置。

---

## 目录

- [系统概述](#系统概述)
- [技术架构](#技术架构)
- [核心模块说明](#核心模块说明)
- [WRAS 评分体系](#wras-评分体系)
- [目录结构](#目录结构)
- [快速启动](#快速启动)
- [环境变量配置](#环境变量配置)
- [API 接口文档](#api-接口文档)
- [云端部署](#云端部署)
- [扩展方向](#扩展方向)

---

## 系统概述

本系统通过对目标网址进行全自动 OSINT 情报采集，结合加权风险评分算法（WRAS）与大模型 AI 分析，输出结构化的风险研判报告，辅助一线反诈民警快速决策。

**核心能力：**

- 自动采集域名注册、SSL 证书、服务器地理位置、页面内容、搜索引擎舆情等多维情报
- 基于业务专家权重的 WRAS 评分引擎，输出 0~100 分的量化风险值
- 双 AI 引擎（Gemini / DeepSeek）深度语义分析与视觉仿冒检测
- 四级风险分层（RED / ORANGE / YELLOW / GREEN）+ 对应警务处置预案
- XAI 可解释性热力图，呈现各维度风险贡献

---

## 技术架构

```
URL 输入
  ↓
[模块一] OSINT 情报采集层（并行异步）
  ├── DomainIntelCollector   — WHOIS / 域名年龄 / ICP 备案（工信部官方 API）
  ├── SSLIntelCollector      — SSL 证书有效性 / 签发机构 / 自签名检测
  ├── GeoIPCollector         — 服务器 IP 地理归属 / ISP / CDN 识别
  ├── PageContentCollector   — Playwright 全页采集（降级 httpx + BeautifulSoup）
  └── SentimentCollector     — Bing 搜索引擎舆情采集 / 负面关键词统计
  ↓
[模块二] 特征工程层
  ├── 域名维度：注册时长归一化、ICP 缺失、WHOIS 隐私、SSL 异常
  ├── 网络维度：境外服务器、CDN 规避行为
  ├── 内容维度：高危话术 NLP 检测、pHash 钓鱼视觉相似度、资源异常率
  └── 舆情维度：负面情感极性、投诉量归一化、黑名单命中
  ↓
[模块三] WRAS 风险评分引擎
  公式：Final_Score = Σ(W_i × F_i × 100) × C_trust
  ├── W_i：业务专家权重（12 维，总和 = 1.0）
  ├── F_i：特征向量（0~1 归一化）
  └── C_trust：置信度系数（时效衰减 × 多源验证加成）
  ↓
[模块四] AI 智能分析层
  ├── 内容语义分析 — 欺诈类型识别、关键话术提取
  ├── 视觉分析     — 截图仿冒检测（Gemini Vision）
  └── 侦查报告生成 — 结构化专业研判报告
  ↓
[模块五] 决策支持层
  ├── 四级风险分层（RED ≥ 80 / ORANGE 60~79 / YELLOW 40~59 / GREEN < 40）
  ├── 对应警务处置预案（立即下架 / 监控跟进 / 深度侦查 / 存档）
  └── XAI 可解释热力图（各特征风险贡献可视化）
  ↓
FastAPI REST API  +  Streamlit 可视化前端
```

---

## 核心模块说明

### 模块一：OSINT 情报采集（`osint_collector.py`）

所有采集器通过 `asyncio.gather()` 并行执行，总采集时间取决于最慢的单项。

| 采集器 | 数据来源 | 关键字段 |
|--------|---------|---------|
| DomainIntelCollector | python-whois / 工信部 ICP API | 域名年龄、注册商、WHOIS 隐私、备案号 |
| SSLIntelCollector | 直连 443 端口 TLS 握手 | 证书有效性、签发机构、过期天数、自签名 |
| GeoIPCollector | ip-api.com | 服务器国家、ISP、CDN 标识 |
| PageContentCollector | Playwright（降级 httpx） | 页面文本、截图、重定向链、资源异常率 |
| SentimentCollector | Bing 搜索引擎 | 搜索摘要、负面结果计数 |

**ICP 查询说明：** 优先调用工信部官方接口 `hlwicpfwc.miit.gov.cn`，连通性有保障，查询结果权威可信。

### 模块二：特征工程（`feature_engineer.py`）

将原始情报归一化为 12 维特征向量，值域 `[0, 1]`，越高代表风险越大。

- **域名年龄**：注册 ≤ 30 天 → 0.95，≤ 90 天 → 0.75，≤ 365 天 → 0.4，> 3 年 → 0.05
- **关键词 NLP**：高危词（冒充公检法/安全账户等）权重 1.0，中危 0.5，低危 0.2
- **pHash 视觉相似度**：与已知官方页面哈希库比对，检测仿冒
- **AI 融合策略**：取 `max(规则评分, AI评分)`，最小化漏报

### 模块三：WRAS 评分引擎（`wras_engine.py`）

```
Raw_Score  = Σ(W_i × F_i × 100)          # 加权原始分
C_trust    = 时效系数 × 多源加成            # 置信度（0.5~1.0）
Final_Score = Raw_Score × C_trust          # 最终分（上限 100）
```

特殊规则：原始分 ≥ 85 时跳过置信度折扣（极高风险不打折）。

置信度衰减参数：情报超过 72 小时后开始衰减，半衰期 72 小时，最低系数 0.5。

### 模块四：AI 分析层（`gemini_analyzer.py`）

| 分析器 | 功能 | 支持引擎 |
|--------|------|---------|
| GeminiContentAnalyzer | 页面文本语义分析，识别欺诈类型 | Gemini / DeepSeek |
| GeminiVisionAnalyzer | 截图视觉分析，检测仿冒目标 | Gemini（仅） |
| GeminiReportGenerator | 生成结构化专业侦查报告 | Gemini / DeepSeek |

**引擎切换策略：** 默认 Gemini 优先，遇到限流或失败自动切换 DeepSeek；用户可在前端手动指定引擎。

---

## WRAS 评分体系

权重由反诈业务专家根据实战经验标定，当前配置：

| 特征维度 | 权重 | 业务含义 |
|---------|------|---------|
| 风险话术密度 | 0.15 | 冒充公检法、安全账户、刷单返利等高危话术 |
| 负面舆情强度 | 0.14 | 受害者投诉、媒体曝光、论坛举报 |
| 钓鱼视觉相似度 | 0.12 | 仿冒银行、支付平台官方页面 |
| ICP 备案缺失 | 0.10 | 无备案经营属违规，诈骗站点普遍特征 |
| 投诉量归一化 | 0.09 | 搜索引擎负面结果数量 |
| 域名注册时长 | 0.08 | 新域名（< 30 天）是强烈诈骗信号 |
| 境外服务器 | 0.07 | 东南亚、欧洲等高风险地区 |
| SSL 自签名 | 0.06 | 证书异常，正规站点极少使用 |
| 资源加载异常 | 0.05 | 页面大量 404，结构可疑 |
| WHOIS 信息隐藏 | 0.05 | 注册者身份刻意隐匿 |
| 黑名单命中 | 0.05 | 命中已知涉诈域名库 |
| CDN 规避行为 | 0.04 | 利用 CDN 隐藏真实 IP，规避溯源 |

风险分级阈值：

| 等级 | 分值 | 含义 | 处置 |
|------|------|------|------|
| 🔴 RED | ≥ 80 | 高危 | 立即下架，移交网安立案 |
| 🟠 ORANGE | 60~79 | 中高风险 | 列入重点监控，协查跟进 |
| 🟡 YELLOW | 40~59 | 疑似风险 | 扩大侦查，补充情报 |
| 🟢 GREEN | < 40 | 暂无风险 | 存档备查 |

---

## 目录结构

```
.
├── backend/
│   ├── main.py                   # FastAPI 服务入口 + Redis 任务队列
│   ├── models/
│   │   └── schemas.py            # Pydantic 数据模型 + URL 格式校验
│   └── modules/
│       ├── osint_collector.py    # OSINT 情报采集（五大采集器）
│       ├── feature_engineer.py   # 特征工程与归一化
│       ├── wras_engine.py        # WRAS 风险评分引擎
│       ├── gemini_analyzer.py    # AI 分析（Gemini / DeepSeek）
│       └── pipeline.py           # 流水线协调器
├── config/
│   └── settings.py               # 全局配置：权重、阈值、关键词库
├── frontend/
│   └── app.py                    # Streamlit 可视化前端
├── requirements.txt
└── .env.example                  # 环境变量示例（不含真实 Key）
```

---

## 快速启动

**环境要求：Python 3.11+，Redis**

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填入 API Key

# 3. 启动 Redis（Windows）
redis-server

# 4. 启动前端
streamlit run frontend/app.py

# 5. （可选）单独启动 FastAPI 后端
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

> **完整页面采集能力（推荐）：**
> ```bash
> pip install playwright
> playwright install chromium
> ```
> 未安装时自动降级为 httpx 采集，截图与 JS 特征不可用，其余功能正常。

---

## 环境变量配置

复制 `.env.example` 为 `.env` 并填入以下配置：

| 变量 | 必填 | 说明 |
|------|------|------|
| `GEMINI_API_KEY` | 二选一 | Google Gemini API Key |
| `DEEPSEEK_API_KEY` | 二选一 | DeepSeek API Key |
| `REDIS_URL` | 否 | Redis 连接地址，默认 `redis://localhost:6379/0` |
| `CORS_ORIGINS` | 否 | 允许的前端来源，默认 `http://localhost:8501`，多个用逗号分隔 |

---

## API 接口文档

服务启动后访问 `http://localhost:8000/api/docs` 查看完整 Swagger 文档。

### 主要接口

**同步分析**
```
POST /api/analyze
```
```json
{
  "url": "suspicious-site.com",
  "priority": "normal",
  "analyst_id": "P20240001",
  "extra_keywords": ["安全账户", "资金核验"],
  "ai_engine": "auto"
}
```

**异步分析（适合批量）**
```
POST /api/analyze/async   → 返回 task_id
GET  /api/task/{task_id}  → 查询结果（Redis 存储，24h 过期）
```

**批量分析**
```
POST /api/batch
["url1.com", "url2.com", ...]   # 最多 10 个
```

**健康检查**
```
GET /api/health  → 返回服务状态 + Redis 连接状态
```

---

## 云端部署（Streamlit Cloud）

1. Fork 本仓库
2. 前往 [share.streamlit.io](https://share.streamlit.io) 用 GitHub 账号登录
3. 选择仓库，Main file path 填 `frontend/app.py`
4. 在 Secrets 中配置 `GEMINI_API_KEY` / `DEEPSEEK_API_KEY`
5. 点击 Deploy

---

## 扩展方向

1. **模型升级**：接入 MacBERT / RoBERTa 中文分类模型替换规则 NLP，提升话术识别准确率
2. **数据源扩展**：对接 12321 举报平台 API、国家反诈中心数据
3. **知识图谱**：构建涉诈团伙关联图谱（域名 / IP / 手机号关联分析）
4. **反制溯源**：结合 Maltego 进行深度溯源链分析
5. **联动封堵**：对接运营商 / IDC 下架接口，实现一键自动化处置

---

## License

[Apache 2.0](LICENSE)
