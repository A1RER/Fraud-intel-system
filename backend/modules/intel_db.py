# backend/modules/intel_db.py
"""
涉诈信息情报库 —— SQLite 持久化
存储分析记录、高风险企业、诈骗模式，支持关联查询和统计
"""
import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger

# 数据库文件放在项目根目录 data/ 下
_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
_DB_PATH = os.path.join(_DB_DIR, "intel.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(_DB_DIR, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """创建数据库表（幂等）"""
    conn = _get_conn()
    conn.executescript("""
    -- 分析记录表
    CREATE TABLE IF NOT EXISTS analysis_records (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id     TEXT    UNIQUE NOT NULL,
        input_type    TEXT    NOT NULL,           -- recruitment / chat / company / url
        content       TEXT    NOT NULL,           -- 用户输入内容（脱敏摘要）
        company_name  TEXT,
        url           TEXT,
        risk_level    TEXT    NOT NULL,           -- HIGH / MEDIUM / LOW / SAFE
        risk_score    REAL    NOT NULL,
        fraud_types   TEXT    NOT NULL DEFAULT '[]',  -- JSON array
        confidence    REAL    DEFAULT 0,
        summary       TEXT    DEFAULT '',
        evidence      TEXT    NOT NULL DEFAULT '[]',  -- JSON array
        keyword_hits  TEXT    NOT NULL DEFAULT '[]',  -- JSON array
        suggestions   TEXT    NOT NULL DEFAULT '[]',  -- JSON array
        ai_analysis   TEXT,
        created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    -- 高风险企业表（从分析记录中沉淀）
    CREATE TABLE IF NOT EXISTS risky_companies (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        company_name  TEXT    NOT NULL,
        risk_level    TEXT    NOT NULL,
        risk_score    REAL    NOT NULL,
        fraud_types   TEXT    NOT NULL DEFAULT '[]',
        hit_count     INTEGER NOT NULL DEFAULT 1,  -- 被识别次数
        evidence      TEXT    NOT NULL DEFAULT '[]',
        first_seen    TEXT    NOT NULL DEFAULT (datetime('now')),
        last_seen     TEXT    NOT NULL DEFAULT (datetime('now')),
        UNIQUE(company_name)
    );

    -- 诈骗模式统计表
    CREATE TABLE IF NOT EXISTS fraud_patterns (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        fraud_type    TEXT    UNIQUE NOT NULL,
        total_count   INTEGER NOT NULL DEFAULT 0,
        high_count    INTEGER NOT NULL DEFAULT 0,
        recent_keywords TEXT  NOT NULL DEFAULT '[]',  -- 最近常见关键词
        last_updated  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    -- 索引
    CREATE INDEX IF NOT EXISTS idx_records_risk    ON analysis_records(risk_level);
    CREATE INDEX IF NOT EXISTS idx_records_company ON analysis_records(company_name);
    CREATE INDEX IF NOT EXISTS idx_records_created ON analysis_records(created_at);
    CREATE INDEX IF NOT EXISTS idx_companies_risk  ON risky_companies(risk_level);
    CREATE INDEX IF NOT EXISTS idx_companies_hits  ON risky_companies(hit_count DESC);
    """)
    conn.commit()
    conn.close()
    logger.info(f"[IntelDB] 数据库初始化完成: {_DB_PATH}")


# ── 写入操作 ─────────────────────────────────────────────────────

def save_record(
    report_id: str,
    input_type: str,
    content: str,
    risk_level: str,
    risk_score: float,
    fraud_types: List[str],
    confidence: float = 0.0,
    summary: str = "",
    evidence: List[str] = None,
    keyword_hits: List[str] = None,
    suggestions: List[str] = None,
    ai_analysis: Optional[str] = None,
    company_name: Optional[str] = None,
    url: Optional[str] = None,
):
    """保存分析记录 + 自动更新企业库和模式统计"""
    conn = _get_conn()
    try:
        # 内容摘要（截取前 500 字，避免存过大文本）
        content_summary = content[:500] if content else ""

        conn.execute("""
            INSERT OR IGNORE INTO analysis_records
            (report_id, input_type, content, company_name, url,
             risk_level, risk_score, fraud_types, confidence,
             summary, evidence, keyword_hits, suggestions, ai_analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_id, input_type, content_summary, company_name, url,
            risk_level, risk_score,
            json.dumps(fraud_types, ensure_ascii=False),
            confidence, summary,
            json.dumps(evidence or [], ensure_ascii=False),
            json.dumps(keyword_hits or [], ensure_ascii=False),
            json.dumps(suggestions or [], ensure_ascii=False),
            ai_analysis,
        ))

        # 中高风险 + 有公司名 → 更新企业库
        if company_name and risk_level in ("HIGH", "MEDIUM"):
            _upsert_company(conn, company_name, risk_level, risk_score,
                            fraud_types, evidence or [])

        # 更新诈骗模式统计
        for ft in fraud_types:
            _upsert_pattern(conn, ft, risk_level, keyword_hits or [])

        conn.commit()
    except Exception as e:
        logger.error(f"[IntelDB] 保存记录失败: {e}")
    finally:
        conn.close()


def _upsert_company(conn, name: str, risk_level: str, risk_score: float,
                    fraud_types: List[str], evidence: List[str]):
    """更新或插入高风险企业"""
    existing = conn.execute(
        "SELECT id, hit_count, risk_level, risk_score, fraud_types, evidence FROM risky_companies WHERE company_name = ?",
        (name,)
    ).fetchone()

    if existing:
        # 合并
        old_types = json.loads(existing["fraud_types"])
        merged_types = list(dict.fromkeys(old_types + fraud_types))
        old_evidence = json.loads(existing["evidence"])
        merged_evidence = list(dict.fromkeys(old_evidence + evidence))[-20:]  # 保留最近 20 条
        new_score = max(existing["risk_score"], risk_score)

        conn.execute("""
            UPDATE risky_companies
            SET risk_level = ?, risk_score = ?, fraud_types = ?,
                hit_count = hit_count + 1, evidence = ?, last_seen = datetime('now')
            WHERE id = ?
        """, (
            risk_level if risk_score >= existing["risk_score"] else existing["risk_level"],
            new_score,
            json.dumps(merged_types, ensure_ascii=False),
            json.dumps(merged_evidence, ensure_ascii=False),
            existing["id"],
        ))
    else:
        conn.execute("""
            INSERT INTO risky_companies
            (company_name, risk_level, risk_score, fraud_types, evidence)
            VALUES (?, ?, ?, ?, ?)
        """, (
            name, risk_level, risk_score,
            json.dumps(fraud_types, ensure_ascii=False),
            json.dumps(evidence, ensure_ascii=False),
        ))


def _upsert_pattern(conn, fraud_type: str, risk_level: str, keyword_hits: List[str]):
    """更新诈骗模式统计"""
    existing = conn.execute(
        "SELECT id, recent_keywords FROM fraud_patterns WHERE fraud_type = ?",
        (fraud_type,)
    ).fetchone()

    if existing:
        old_kws = json.loads(existing["recent_keywords"])
        merged_kws = list(dict.fromkeys(keyword_hits + old_kws))[:30]
        conn.execute("""
            UPDATE fraud_patterns
            SET total_count = total_count + 1,
                high_count = high_count + ?,
                recent_keywords = ?,
                last_updated = datetime('now')
            WHERE id = ?
        """, (
            1 if risk_level == "HIGH" else 0,
            json.dumps(merged_kws, ensure_ascii=False),
            existing["id"],
        ))
    else:
        conn.execute("""
            INSERT INTO fraud_patterns (fraud_type, total_count, high_count, recent_keywords)
            VALUES (?, 1, ?, ?)
        """, (
            fraud_type,
            1 if risk_level == "HIGH" else 0,
            json.dumps(keyword_hits, ensure_ascii=False),
        ))


# ── 查询操作 ─────────────────────────────────────────────────────

def get_records(
    risk_level: Optional[str] = None,
    fraud_type: Optional[str] = None,
    company_name: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict:
    """分页查询分析记录"""
    conn = _get_conn()
    where, params = [], []

    if risk_level:
        where.append("risk_level = ?")
        params.append(risk_level)
    if fraud_type:
        where.append("fraud_types LIKE ?")
        params.append(f"%{fraud_type}%")
    if company_name:
        where.append("company_name LIKE ?")
        params.append(f"%{company_name}%")

    clause = f"WHERE {' AND '.join(where)}" if where else ""

    total = conn.execute(
        f"SELECT COUNT(*) as c FROM analysis_records {clause}", params
    ).fetchone()["c"]

    rows = conn.execute(
        f"SELECT * FROM analysis_records {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    conn.close()

    return {
        "total": total,
        "records": [_row_to_dict(r) for r in rows],
    }


def get_companies(
    risk_level: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict:
    """查询高风险企业"""
    conn = _get_conn()
    where, params = [], []

    if risk_level:
        where.append("risk_level = ?")
        params.append(risk_level)
    if keyword:
        where.append("company_name LIKE ?")
        params.append(f"%{keyword}%")

    clause = f"WHERE {' AND '.join(where)}" if where else ""

    total = conn.execute(
        f"SELECT COUNT(*) as c FROM risky_companies {clause}", params
    ).fetchone()["c"]

    rows = conn.execute(
        f"SELECT * FROM risky_companies {clause} ORDER BY hit_count DESC, last_seen DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    conn.close()

    return {
        "total": total,
        "companies": [_row_to_dict(r) for r in rows],
    }


def get_record_detail(report_id: str) -> Optional[Dict]:
    """获取单条分析记录详情"""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM analysis_records WHERE report_id = ?", (report_id,)
    ).fetchone()
    conn.close()
    return _row_to_dict(row) if row else None


def get_company_detail(company_name: str) -> Optional[Dict]:
    """获取企业详情 + 关联分析记录"""
    conn = _get_conn()
    company = conn.execute(
        "SELECT * FROM risky_companies WHERE company_name = ?", (company_name,)
    ).fetchone()
    if not company:
        conn.close()
        return None

    related = conn.execute(
        "SELECT report_id, input_type, risk_level, risk_score, summary, created_at "
        "FROM analysis_records WHERE company_name = ? ORDER BY created_at DESC LIMIT 20",
        (company_name,)
    ).fetchall()
    conn.close()

    result = _row_to_dict(company)
    result["related_records"] = [dict(r) for r in related]
    return result


# ── 统计接口 ─────────────────────────────────────────────────────

def get_stats() -> Dict:
    """获取情报库统计概览"""
    conn = _get_conn()

    total_records = conn.execute("SELECT COUNT(*) as c FROM analysis_records").fetchone()["c"]
    total_companies = conn.execute("SELECT COUNT(*) as c FROM risky_companies").fetchone()["c"]

    # 按风险等级统计
    level_stats = {}
    for row in conn.execute(
        "SELECT risk_level, COUNT(*) as c FROM analysis_records GROUP BY risk_level"
    ):
        level_stats[row["risk_level"]] = row["c"]

    # 诈骗类型统计
    pattern_rows = conn.execute(
        "SELECT fraud_type, total_count, high_count FROM fraud_patterns ORDER BY total_count DESC"
    ).fetchall()
    patterns = [dict(r) for r in pattern_rows]

    # 最近 7 天趋势
    trend = []
    for row in conn.execute("""
        SELECT DATE(created_at) as date, COUNT(*) as count,
               SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_count
        FROM analysis_records
        WHERE created_at >= datetime('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    """):
        trend.append(dict(row))

    # 高频企业 TOP 10
    top_companies = []
    for row in conn.execute(
        "SELECT company_name, hit_count, risk_level, risk_score "
        "FROM risky_companies ORDER BY hit_count DESC LIMIT 10"
    ):
        top_companies.append(dict(row))

    conn.close()
    return {
        "total_records": total_records,
        "total_companies": total_companies,
        "level_stats": level_stats,
        "fraud_patterns": patterns,
        "trend_7d": trend,
        "top_companies": top_companies,
    }


def _row_to_dict(row) -> dict:
    """sqlite3.Row → dict，自动解析 JSON 字段"""
    d = dict(row)
    for key in ("fraud_types", "evidence", "keyword_hits",
                "suggestions", "recent_keywords"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d
