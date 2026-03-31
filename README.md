# 慧眼 — 招聘诈骗识别与预警系统

> 基于开源情报（OSINT）和 AI 的招聘诈骗智能识别系统，面向大学生求职场景，实现对可疑招聘信息的多维度分析、风险分级、证据链生成和反诈宣教。

**在线体验：[https://fraud-analyzer-scy.tech](https://fraud-analyzer-scy.tech)**

---

## 系统概述

当前很多大学生在求职过程中，在小红书、微信群、私聊等"非公开场景"中被看似真实的招聘信息诱导，如"高薪内推""付费培训包入职"等。这类诈骗往往没有明确的网站，传统反诈手段难以及时识别。

**慧眼**从更底层去分析——招聘行为本身有没有诈骗特征。

**核心能力：**

- **四种输入方式**：招聘信息文本 / 聊天记录 / 公司名称 / 网站链接
- **三层分析引擎**：规则关键词匹配 + 正则模式识别 + AI 语义深度分析
- **企业信息核验**：名称模式分析 + 行业风险匹配 + AI 辅助研判
- **四大诈骗类型识别**：付费培训诈骗 / 虚假内推诈骗 / 高薪诱导诈骗 / 信息盗取诈骗
- **证据链生成**：自动标注来源（话术分析/模式匹配/企业核验/AI分析）和证据强度
- **涉诈信息情报库**：分析记录自动沉淀，高风险企业累计追踪，支持关联查询
- **数据看板**：诈骗类型分布、7天趋势、风险等级分布、高频涉诈企业 TOP 10
- **反诈宣教**：高发预警（基于系统实时数据）、典型案例详解、求职防诈五字诀
- **网站链接分析**：自动 OSINT 采集（域名/SSL/服务器/舆情）+ WRAS 评分 + AI 视觉分析

---

## 技术架构

```
用户输入（招聘信息 / 聊天记录 / 公司名称 / 网站链接）
  ↓
┌──────────────────────────────────────────────────┐
│ 开源情报采集层（OSINT）                            │
│  ├── 企业信息核验（名称模式 + 行业风险）            │
│  ├── 招聘话术分析（50+ 关键词 + 5 种正则模式）      │
│  └── 网络舆情 / OSINT 采集（URL 分析时）            │
└──────────────────────────────────────────────────┘
  ↓
┌──────────────────────────────────────────────────┐
│ 智能分析与研判层（核心）                            │
│  ① 规则识别（关键词 / 行为特征 / 正则模式）         │
│  ② AI 语义分析（Gemini / DeepSeek 双引擎）         │
│  ③ 多源数据融合（话术 45% + 企业 20% + AI 35%）    │
└──────────────────────────────────────────────────┘
  ↓
┌──────────────────────────────────────────────────┐
│ 风险判定层                                        │
│  ├── 诈骗类型识别（付费培训 / 内推 / 高薪 / 信息盗取）│
│  ├── 风险等级评估（HIGH / MEDIUM / LOW / SAFE）     │
│  └── 证据链生成（来源标注 + 强度评级）              │
└──────────────────────────────────────────────────┘
  ↓
┌──────────────────────────────────────────────────┐
│ 结果输出层                                        │
│  风险提示 + AI 决策建议 + 防范提示                  │
└──────────────────────────────────────────────────┘
  ↓
┌─────────────────────┐  ┌─────────────────────────┐
│ 涉诈信息情报库       │  │ 反诈宣教模块             │
│ 数据沉淀 / 关联查询  │  │ 高频预警 / 案例展示      │
│ 统计分析 / 可视化    │  │ 点对点防范提醒           │
└─────────────────────┘  └─────────────────────────┘
```

---

## 目录结构

```
.
├── backend/
│   ├── main.py                      # FastAPI 服务入口 + 所有 API 路由
│   ├── models/
│   │   └── schemas.py               # 数据模型（含招聘诈骗新模型）
│   └── modules/
│       ├── recruitment_analyzer.py   # 招聘话术分析（关键词 + 正则 + AI）
│       ├── company_checker.py        # 企业信息核验（名称模式 + AI）
│       ├── fraud_classifier.py       # 多源融合诈骗分类器
│       ├── evidence_builder.py       # 结构化证据链生成器
│       ├── intel_db.py               # SQLite 情报数据库
│       ├── osint_collector.py        # OSINT 情报采集（URL 分析）
│       ├── feature_engineer.py       # 特征工程
│       ├── wras_engine.py            # WRAS 风险评分引擎
│       ├── gemini_analyzer.py        # AI 分析（Gemini / DeepSeek）
│       └── pipeline.py               # URL 分析流水线
├── config/
│   └── settings.py                   # 全局配置
├── web/                              # React 前端
│   ├── src/
│   │   ├── App.tsx                   # 路由入口（React Router）
│   │   ├── constants.ts              # 共享配置
│   │   ├── types.ts                  # TypeScript 类型定义
│   │   ├── components/
│   │   │   └── common.tsx            # 通用组件
│   │   └── pages/
│   │       ├── AnalyzePage.tsx        # 风险识别页（/）
│   │       ├── DatabasePage.tsx       # 情报库页（/database）
│   │       ├── StatsPage.tsx          # 数据看板页（/stats）
│   │       └── EducationPage.tsx      # 反诈宣教页（/education）
│   ├── vite.config.ts
│   └── package.json
├── data/                             # SQLite 数据库（自动创建，已 gitignore）
├── requirements.txt
└── .env.example
```

---

## 快速启动

**环境要求：Python 3.11+，Node.js 18+**

```bash
# 1. 克隆项目
git clone <repo-url>
cd Fraud_intel_system

# 2. 安装 Python 依赖
pip install -r requirements.txt

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env，填入至少一个 AI API Key（可选，不填则 AI 分析不可用，规则引擎仍正常工作）

# 4. 启动后端（在项目根目录）
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# 5. 新开终端，启动前端
cd web
npm install
npm run dev
```

然后浏览器访问 **http://localhost:5173**

> **Redis**（可选）：如需异步任务功能，启动 `redis-server`。不启动也能正常使用，仅异步批量分析不可用。

> **Playwright**（可选，URL 分析用）：
> ```bash
> pip install playwright
> playwright install chromium
> ```

---

## 前端页面

| 路由 | 页面 | 功能 |
|------|------|------|
| `/` | 风险识别 | 四种输入方式，实时分析，风险评分 + 诈骗类型 + 证据链 + 防范建议 |
| `/database` | 情报库 | 分析记录查询、高风险企业列表、按风险等级/关键词筛选 |
| `/stats` | 数据看板 | 诈骗类型分布、7天趋势、风险等级分布、TOP 10 高频企业 |
| `/education` | 反诈宣教 | 求职防诈五字诀、高发预警、典型案例、举报渠道 |

---

## API 接口

服务启动后访问 `http://localhost:8000/api/docs`（本地）或 [https://fraud-analyzer-scy.tech/api/docs](https://fraud-analyzer-scy.tech/api/docs)（线上）查看完整 Swagger 文档。

### 核心接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/fraud-analyze` | 慧眼招聘诈骗分析（支持四种输入类型） |
| POST | `/api/analyze` | URL OSINT 分析（原有功能） |
| POST | `/api/ai-analyze` | 按需 AI 深度分析 |
| GET | `/api/intel/records` | 查询分析记录 |
| GET | `/api/intel/companies` | 查询高风险企业 |
| GET | `/api/intel/stats` | 情报库统计概览 |
| GET | `/api/health` | 健康检查 |

---

## 环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| `GEMINI_API_KEY` | 二选一 | Google Gemini API Key |
| `DEEPSEEK_API_KEY` | 二选一 | DeepSeek API Key |
| `REDIS_URL` | 否 | Redis 地址，默认 `redis://localhost:6379/0` |
| `CORS_ORIGINS` | 否 | 允许的前端来源，默认包含 localhost |

> 不配置任何 API Key 时，AI 分析功能不可用，但规则引擎（关键词 + 正则 + 企业核验）仍正常工作。

---

## License

[Apache 2.0](LICENSE)
