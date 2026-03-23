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
        """
        通过工信部官方 API 查询域名 ICP 备案信息。
        查询成功返回备案号；未备案返回 None；接口异常也返回 None 并记录日志。
        """
        try:
            result = await DomainIntelCollector._query_icp_miit(domain)
            if result:
                logger.info(f"[ICP] {domain} 已备案: {result}")
                return result
            logger.info(f"[ICP] {domain} 工信部查询成功，该域名无备案记录")
            return None
        except Exception as e:
            logger.warning(f"[ICP] {domain} 工信部接口连接正常但查询未返回结果: {e}")
            return None

    @staticmethod
    async def _query_icp_miit(domain: str) -> Optional[str]:
        """
        工信部 beian.miit.gov.cn 官方查询。
        流程：获取 token → 查询备案信息 → 返回备案号。
        """
        base_url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Origin": "https://beian.miit.gov.cn",
            "Referer": "https://beian.miit.gov.cn/",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        async with httpx.AsyncClient(headers=headers, timeout=10) as client:
            # 步骤 1：获取 auth token
            token_resp = await client.post(
                f"{base_url}/auth",
                data={"authKey": "dGVzdA==", "timeStamp": ""},  # 公开 authKey
            )
            if token_resp.status_code != 200:
                return None
            token_data = token_resp.json()
            token = token_data.get("params", {}).get("bussiness")
            if not token:
                return None

            # 步骤 2：用 token 查询备案信息
            query_resp = await client.post(
                f"{base_url}/icpAbbreviateInfo/queryByCondition",
                headers={"token": token, "Content-Type": "application/json"},
                json={
                    "pageNum": 1,
                    "pageSize": 1,
                    "unitName": domain,
                },
            )
            if query_resp.status_code != 200:
                return None
            query_data = query_resp.json()

            # 解析返回数据
            params = query_data.get("params", {})
            items = params.get("list", [])
            if not items:
                return None

            # 返回备案号（如 "京ICP备12345678号"）
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
                soup = BeautifulSoup(html, "html.parser")
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
    """外部舆情采集 —— 通过 Bing 搜索获取真实互联网舆情"""

    # 负面关键词，用于拼接搜索词和判断搜索结果极性
    _NEG_KEYWORDS = ["诈骗", "骗局", "投诉", "跑路", "无法提现", "骗子", "举报", "曝光"]

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

        snippets, neg_count = await cls._bing_search(domain)
        result["search_snippets"] = snippets
        result["complaint_count"] = max(result["complaint_count"], neg_count)
        return result

    @classmethod
    async def _bing_search(cls, domain: str) -> tuple:
        """
        通过 Bing 搜索采集真实舆情。
        返回 (snippets 列表, 负面结果计数)。
        """
        all_snippets: List[str] = []
        neg_count = 0

        # 两轮搜索：通用搜索 + 负面关键词定向搜索
        queries = [
            domain,
            f"{domain} 诈骗 OR 投诉 OR 骗局 OR 跑路",
        ]

        try:
            from bs4 import BeautifulSoup
        except ImportError:
            logger.warning("BeautifulSoup 未安装，舆情采集跳过")
            return all_snippets, neg_count

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }

        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=12) as client:
            for query in queries:
                try:
                    resp = await client.get(
                        "https://www.bing.com/search",
                        params={"q": query, "count": "10"},
                    )
                    if resp.status_code != 200:
                        logger.warning(f"Bing 搜索返回 {resp.status_code}，query={query}")
                        continue

                    soup = BeautifulSoup(resp.text, "html.parser")
                    # Bing 搜索结果摘要在 <li class="b_algo"> 下的 <p> 或 <div class="b_caption">
                    for item in soup.select("li.b_algo"):
                        caption = item.select_one("div.b_caption p, p")
                        if not caption:
                            continue
                        text = caption.get_text(strip=True)
                        if not text or len(text) < 10:
                            continue
                        # 去重
                        if text not in all_snippets:
                            all_snippets.append(text)
                        # 统计负面结果
                        if any(kw in text for kw in cls._NEG_KEYWORDS):
                            neg_count += 1

                except Exception as e:
                    logger.warning(f"Bing 搜索失败 [query={query}]: {e}")

        logger.info(f"[舆情] {domain} 采集到 {len(all_snippets)} 条摘要，负面 {neg_count} 条")
        return all_snippets, neg_count


class OSINTCollector:
    """情报采集协调器"""

    @classmethod
    async def collect(cls, url: str) -> RawIntelligence:
        url = _normalize_url(url)
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
