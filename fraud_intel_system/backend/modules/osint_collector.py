# backend/modules/osint_collector.py
"""
模块一：自动化情报采集
采集链路：DNS/WHOIS -> SSL -> 服务器地理 -> 页面内容(Playwright) -> 外部舆情
"""
import asyncio
import base64
import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import httpx
from loguru import logger

try:
    from playwright.async_api import async_playwright, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright 未安装，将使用 httpx 降级采集")

from backend.models.schemas import RawIntelligence
from config.settings import BLACKLIST_DOMAINS


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
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
        try:
            import whois
            w = await asyncio.to_thread(whois.whois, domain)
            result["domain_age_days"] = _calc_domain_age(w.creation_date)
            result["registrar"] = str(w.registrar) if w.registrar else None
            name = str(w.name or "").lower()
            if any(kw in name for kw in ["privacy", "protected", "proxy", "redacted"]):
                result["whois_privacy"] = True
        except Exception as e:
            logger.warning(f"WHOIS 查询失败 [{domain}]: {e}")

        try:
            result["server_ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

        result["icp_record"] = await DomainIntelCollector._query_icp(domain)
        return result

    @staticmethod
    async def _query_icp(domain: str) -> Optional[str]:
        cn_tlds = [".cn", ".com.cn", ".net.cn", ".org.cn"]
        if any(domain.endswith(tld) for tld in cn_tlds):
            return f"模拟备案号：沪ICP备{hash(domain) % 9000000 + 1000000:07d}号"
        return None


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
            _, writer = await asyncio.wait_for(conn, timeout=10)
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

    @staticmethod
    async def collect(ip: str) -> dict:
        result = {"server_country": None, "server_isp": None, "is_cdn": False}
        if not ip:
            return result
        try:
            async with httpx.AsyncClient(timeout=8) as client:
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
        except Exception as e:
            logger.warning(f"GeoIP 查询失败 [{ip}]: {e}")
        return result


class PageContentCollector:
    """页面内容采集"""

    USER_AGENTS = {
        "pc":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "android": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36",
        "ios":     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
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
                await page.goto(url, wait_until="networkidle", timeout=30000)
                result["redirect_chain"] = redirect_chain[:5]
                screenshot = await page.screenshot(full_page=False)
                result["screenshot_b64"] = base64.b64encode(screenshot).decode()
                html = await page.content()
                result["page_html"] = html[:50000]
                result["page_title"] = await page.title()
                result["page_text"] = await page.inner_text("body")
                js_result = await page.evaluate("""() => {
                    const resources = performance.getEntriesByType('resource');
                    return {
                        total: resources.length,
                        errors: resources.filter(r => r.responseStatus >= 400 || r.responseStatus === 0).length
                    };
                }""")
                result["total_resources"] = js_result.get("total", 0)
                result["resource_errors"] = js_result.get("errors", 0)
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
            async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=15) as client:
                resp = await client.get(url)
                html = resp.text
                result["page_html"] = html[:50000]
                result["redirect_chain"] = [str(r.url) for r in resp.history[:5]]
                soup = BeautifulSoup(html, "lxml")
                result["page_title"] = soup.title.string if soup.title else ""
                result["page_text"] = soup.get_text(separator=" ", strip=True)[:10000]
        except Exception as e:
            logger.error(f"httpx 降级采集失败 [{url}]: {e}")
        return result

    @staticmethod
    def _empty_result() -> dict:
        return {
            "page_title": None, "page_text": None, "page_html": None,
            "screenshot_b64": None, "resource_errors": 0,
            "total_resources": 0, "redirect_chain": [],
        }


class SentimentCollector:
    """外部舆情采集"""

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
        result["search_snippets"] = await cls._mock_search(domain)
        result["complaint_count"] = max(result["complaint_count"],
                                        await cls._mock_complaint_count(domain))
        return result

    @staticmethod
    async def _mock_search(domain: str) -> List[str]:
        """生产环境替换为 SerpAPI / Bing Search API 调用"""
        h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
        if h % 3 == 0:
            return [f"网友反映 {domain} 无法提现，疑似诈骗", f"{domain} 充值后账号被封，投诉无门"]
        elif h % 3 == 1:
            return [f"{domain} 是什么平台，求了解"]
        return []

    @staticmethod
    async def _mock_complaint_count(domain: str) -> int:
        h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
        return h % 50


class OSINTCollector:
    """情报采集协调器"""

    @classmethod
    async def collect(cls, url: str) -> RawIntelligence:
        domain = _extract_domain(url)
        logger.info(f"[OSINT] 开始采集: {url} | domain={domain}")

        results = await asyncio.gather(
            DomainIntelCollector.collect(domain),
            SSLIntelCollector.collect(domain),
            PageContentCollector.collect(url),
            SentimentCollector.collect(domain),
            return_exceptions=True
        )

        def safe(r, default):
            return r if isinstance(r, dict) else default

        domain_r   = safe(results[0], {})
        ssl_r      = safe(results[1], {})
        page_r     = safe(results[2], PageContentCollector._empty_result())
        sentiment_r = safe(results[3], {})

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
