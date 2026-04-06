# backend/modules/osint_collector.py
"""
模块一：自动化情报采集
采集链路：DNS/WHOIS -> SSL -> 服务器地理 -> 页面内容 -> 外部舆情
所有采集器均有严格超时，防止单个慢查询拖垮整条链路。
"""
import asyncio
import base64
import hashlib
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import httpx
from loguru import logger

from backend.models.schemas import RawIntelligence
from config.settings import BLACKLIST_DOMAINS

# 低配服务器（1vCPU/2GB）下禁用 Playwright，用 httpx 轻量采集
# 如需启用，设置环境变量 USE_PLAYWRIGHT=1
_USE_PLAYWRIGHT = os.getenv("USE_PLAYWRIGHT", "").strip() in ("1", "true", "yes")
PLAYWRIGHT_AVAILABLE = False
if _USE_PLAYWRIGHT:
    try:
        from playwright.async_api import async_playwright
        PLAYWRIGHT_AVAILABLE = True
    except ImportError:
        logger.warning("Playwright 未安装，将使用 httpx 采集")


def _normalize_url(url: str) -> str:
    """确保 URL 有协议前缀"""
    if "://" not in url:
        url = f"https://{url}"
    return url


def _extract_domain(url: str) -> str:
    parsed = urlparse(_normalize_url(url))
    return parsed.netloc.lower().replace("www.", "")


def _calc_domain_age(creation_date) -> Optional[int]:
    if not creation_date:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - creation_date
        return max(delta.days, 0)
    return None


class DomainIntelCollector:
    """域名 / WHOIS / DNS 信息采集"""

    @staticmethod
    async def collect(domain: str) -> dict:
        result = {
            "domain_age_days": None,
            "registrar": None,
            "whois_privacy": False,
            "icp_record": None,
            "server_ip": None,
        }

        # WHOIS + DNS 并行
        async def _whois():
            try:
                import whois
                w = await asyncio.wait_for(
                    asyncio.to_thread(whois.whois, domain), timeout=6
                )
                result["domain_age_days"] = _calc_domain_age(w.creation_date)
                result["registrar"] = str(w.registrar) if w.registrar else None
                name = str(w.name or "").lower()
                if any(kw in name for kw in ["privacy", "protected", "proxy", "redacted"]):
                    result["whois_privacy"] = True
            except asyncio.TimeoutError:
                logger.warning(f"WHOIS 查询超时 [{domain}]")
            except Exception as e:
                logger.warning(f"WHOIS 查询失败 [{domain}]: {e}")

        async def _dns():
            try:
                result["server_ip"] = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyname, domain), timeout=4
                )
            except asyncio.TimeoutError:
                logger.warning(f"DNS 查询超时 [{domain}]")
            except Exception:
                pass

        async def _icp():
            result["icp_record"] = await DomainIntelCollector._query_icp(domain)

        await asyncio.gather(_whois(), _dns(), _icp(), return_exceptions=True)
        return result

    @staticmethod
    async def _query_icp(domain: str) -> Optional[str]:
        try:
            return await asyncio.wait_for(
                DomainIntelCollector._query_icp_miit(domain), timeout=6
            )
        except asyncio.TimeoutError:
            logger.warning(f"[ICP] {domain} 查询超时")
            return None
        except Exception as e:
            logger.warning(f"[ICP] {domain} 查询失败: {e}")
            return None

    @staticmethod
    async def _query_icp_miit(domain: str) -> Optional[str]:
        base_url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Origin": "https://beian.miit.gov.cn",
            "Referer": "https://beian.miit.gov.cn/",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        async with httpx.AsyncClient(headers=headers, timeout=5) as client:
            token_resp = await client.post(
                f"{base_url}/auth",
                data={"authKey": "dGVzdA==", "timeStamp": ""},
            )
            if token_resp.status_code != 200:
                return None
            token = token_resp.json().get("params", {}).get("bussiness")
            if not token:
                return None

            query_resp = await client.post(
                f"{base_url}/icpAbbreviateInfo/queryByCondition",
                headers={"token": token, "Content-Type": "application/json"},
                json={"pageNum": 1, "pageSize": 1, "unitName": domain},
            )
            if query_resp.status_code != 200:
                return None
            items = query_resp.json().get("params", {}).get("list", [])
            if not items:
                return None
            icp_no = items[0].get("serviceLicence") or items[0].get("natureName")
            return icp_no if icp_no else None


class SSLIntelCollector:
    """SSL 证书信息采集"""

    @staticmethod
    async def collect(domain: str, port: int = 443) -> dict:
        result = {
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_self_signed": False,
            "ssl_expiry_days": None,
        }
        try:
            ctx = ssl.create_default_context()
            conn = asyncio.open_connection(domain, port, ssl=ctx)
            _, writer = await asyncio.wait_for(conn, timeout=6)
            cert = writer.get_extra_info("ssl_object").getpeercert()
            writer.close()
            await writer.wait_closed()
            result["ssl_valid"] = True
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            result["ssl_issuer"] = issuer_dict.get("organizationName", "Unknown")
            if issuer_dict.get("commonName") == subject_dict.get("commonName"):
                result["ssl_self_signed"] = True
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                result["ssl_expiry_days"] = (expiry - datetime.now(timezone.utc)).days
        except ssl.SSLCertVerificationError:
            result["ssl_self_signed"] = True
        except Exception as e:
            logger.warning(f"SSL 采集失败 [{domain}]: {e}")
        return result


class GeoIPCollector:
    """服务器 IP 地理信息采集"""

    _cache: dict = {}          # {ip: (result, timestamp)}
    _TTL = 24 * 3600           # 同一 IP 缓存 24 小时

    @classmethod
    async def collect(cls, ip: str) -> dict:
        result = {"server_country": None, "server_isp": None, "is_cdn": False}
        if not ip:
            return result

        import time
        cached = cls._cache.get(ip)
        if cached and time.time() - cached[1] < cls._TTL:
            logger.debug(f"[GeoIP] 命中缓存 [{ip}]")
            return cached[0]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,country,countryCode,isp,org"}
                )
                data = resp.json()
                if data.get("status") == "success":
                    result["server_country"] = data.get("country")
                    result["server_isp"] = data.get("isp")
                    org = (data.get("org") or "").lower()
                    cdn_keywords = ["cloudflare", "fastly", "akamai", "cdn", "cloudfront"]
                    if any(k in org for k in cdn_keywords):
                        result["is_cdn"] = True
            cls._cache[ip] = (result, time.time())
        except Exception as e:
            logger.warning(f"GeoIP 查询失败 [{ip}]: {e}")
        return result


class PageContentCollector:
    """页面内容采集（默认 httpx 轻量模式）"""

    USER_AGENTS = {
        "pc": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    @classmethod
    async def collect(cls, url: str) -> dict:
        if PLAYWRIGHT_AVAILABLE:
            return await cls._collect_playwright(url)
        return await cls._collect_httpx(url)

    @classmethod
    async def _collect_playwright(cls, url: str) -> dict:
        result = cls._empty_result()
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                ctx = await browser.new_context(
                    user_agent=cls.USER_AGENTS["pc"],
                    viewport={"width": 1280, "height": 800}
                )
                page = await ctx.new_page()
                redirect_chain = []
                page.on("response", lambda r: redirect_chain.append(r.url)
                        if r.status in (301, 302, 307, 308) else None)
                await page.goto(url, wait_until="domcontentloaded", timeout=12000)
                result["redirect_chain"] = redirect_chain[:5]
                html = await page.content()
                result["page_html"] = html[:50000]
                result["page_title"] = await page.title()
                result["page_text"] = await page.inner_text("body")
                await browser.close()
        except Exception as e:
            logger.error(f"Playwright 采集失败 [{url}]: {e}")
        return result

    @classmethod
    async def _collect_httpx(cls, url: str) -> dict:
        result = cls._empty_result()
        try:
            from bs4 import BeautifulSoup
            headers = {"User-Agent": cls.USER_AGENTS["pc"]}
            async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=10) as client:
                resp = await client.get(url)
                html = resp.text
                result["page_html"] = html[:50000]
                result["redirect_chain"] = [str(r.url) for r in resp.history[:5]]
                soup = BeautifulSoup(html, "html.parser")
                result["page_title"] = soup.title.string if soup.title else ""
                result["page_text"] = soup.get_text(separator=" ", strip=True)[:10000]
        except Exception as e:
            logger.error(f"httpx 采集失败 [{url}]: {e}")
        return result

    @staticmethod
    def _empty_result() -> dict:
        return {
            "page_title": None, "page_text": None, "page_html": None,
            "screenshot_b64": None, "resource_errors": 0,
            "total_resources": 0, "redirect_chain": [],
        }


class SentimentCollector:
    """外部舆情采集 —— 通过 Bing 搜索获取真实互联网舆情"""

    _NEG_KEYWORDS = ["诈骗", "骗局", "投诉", "跑路", "无法提现", "骗子", "举报", "曝光"]
    _cache: dict = {}          # {domain: (snippets, neg_count, timestamp)}
    _TTL = 6 * 3600            # 同一域名缓存 6 小时

    @classmethod
    async def collect(cls, domain: str) -> dict:
        result = {
            "search_snippets": [],
            "social_mentions": [],
            "complaint_count": 0,
            "blacklist_hit": False,
        }
        if domain in BLACKLIST_DOMAINS:
            result["blacklist_hit"] = True
            result["complaint_count"] = 999

        import time
        cached = cls._cache.get(domain)
        if cached and time.time() - cached[2] < cls._TTL:
            logger.debug(f"[舆情] 命中缓存 [{domain}]")
            result["search_snippets"] = cached[0]
            result["complaint_count"] = max(result["complaint_count"], cached[1])
            return result

        snippets, neg_count = await cls._bing_search(domain)
        cls._cache[domain] = (snippets, neg_count, time.time())
        result["search_snippets"] = snippets
        result["complaint_count"] = max(result["complaint_count"], neg_count)
        return result

    @classmethod
    async def _bing_search(cls, domain: str) -> tuple:
        all_snippets: List[str] = []
        neg_count = 0

        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return all_snippets, neg_count

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }

        # 两个查询并发发出，不再串行等待
        queries = [
            domain,
            f"{domain} 诈骗 OR 投诉 OR 骗局 OR 跑路",
        ]

        async def _search_one(client: httpx.AsyncClient, query: str):
            nonlocal neg_count
            try:
                resp = await client.get(
                    "https://www.bing.com/search",
                    params={"q": query, "count": "10"},
                )
                if resp.status_code != 200:
                    return
                soup = BeautifulSoup(resp.text, "html.parser")
                for item in soup.select("li.b_algo"):
                    caption = item.select_one("div.b_caption p, p")
                    if not caption:
                        continue
                    text = caption.get_text(strip=True)
                    if not text or len(text) < 10:
                        continue
                    if text not in all_snippets:
                        all_snippets.append(text)
                    if any(kw in text for kw in cls._NEG_KEYWORDS):
                        neg_count += 1
            except Exception as e:
                logger.warning(f"Bing 搜索失败 [query={query}]: {e}")

        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=6) as client:
            await asyncio.gather(*[_search_one(client, q) for q in queries])

        logger.info(f"[舆情] {domain} 采集到 {len(all_snippets)} 条摘要，负面 {neg_count} 条")
        return all_snippets, neg_count


class OSINTCollector:
    """情报采集协调器 —— 所有子采集器全部并行"""

    @classmethod
    async def collect(cls, url: str) -> RawIntelligence:
        url = _normalize_url(url)
        domain = _extract_domain(url)
        logger.info(f"[OSINT] 开始采集: {url} | domain={domain}")

        # 第一轮：四路并行
        results = await asyncio.gather(
            DomainIntelCollector.collect(domain),
            SSLIntelCollector.collect(domain),
            PageContentCollector.collect(url),
            SentimentCollector.collect(domain),
            return_exceptions=True
        )

        def safe(r, default):
            if isinstance(r, Exception):
                logger.warning(f"[OSINT] 采集器异常: {r}")
                return default
            return r if isinstance(r, dict) else default

        domain_r    = safe(results[0], {})
        ssl_r       = safe(results[1], {})
        page_r      = safe(results[2], PageContentCollector._empty_result())
        sentiment_r = safe(results[3], {})

        # 第二轮：GeoIP（依赖 IP 结果）
        server_ip = domain_r.get("server_ip")
        geo_r = await GeoIPCollector.collect(server_ip) if server_ip else {}

        intel = RawIntelligence(
            url=url, domain=domain,
            domain_age_days=domain_r.get("domain_age_days"),
            registrar=domain_r.get("registrar"),
            whois_privacy=domain_r.get("whois_privacy", False),
            icp_record=domain_r.get("icp_record"),
            ssl_valid=ssl_r.get("ssl_valid", False),
            ssl_issuer=ssl_r.get("ssl_issuer"),
            ssl_self_signed=ssl_r.get("ssl_self_signed", False),
            ssl_expiry_days=ssl_r.get("ssl_expiry_days"),
            server_ip=server_ip,
            server_country=geo_r.get("server_country"),
            server_isp=geo_r.get("server_isp"),
            is_cdn=geo_r.get("is_cdn", False),
            page_title=page_r.get("page_title"),
            page_text=page_r.get("page_text"),
            page_html=page_r.get("page_html"),
            screenshot_b64=page_r.get("screenshot_b64"),
            resource_errors=page_r.get("resource_errors", 0),
            total_resources=page_r.get("total_resources", 0),
            redirect_chain=page_r.get("redirect_chain", []),
            search_snippets=sentiment_r.get("search_snippets", []),
            social_mentions=sentiment_r.get("social_mentions", []),
            complaint_count=sentiment_r.get("complaint_count", 0),
            blacklist_hit=sentiment_r.get("blacklist_hit", False),
        )
        logger.success(f"[OSINT] 采集完成: {domain}")
        return intel
