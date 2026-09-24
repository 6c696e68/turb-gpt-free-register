# -*- coding: utf-8 -*-
"""
curl_cffi Session niêm lắp
thống nhấtquản lý Cookie、requestđầu và TLS chỉ vân
"""
import logging
import hashlib
import random
import re
import threading
import time
import uuid
from urllib.parse import urlparse
from curl_cffi.requests import Session

from config import (
    USER_AGENT, SEC_CH_UA, SEC_CH_UA_PLATFORM, SEC_CH_UA_MOBILE,
    SEC_CH_UA_FULL_VERSION_LIST, SEC_CH_UA_PLATFORM_VERSION, SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS, SEC_CH_UA_MODEL, SEND_HIGH_ENTROPY_CLIENT_HINTS,
    ACCEPT_LANGUAGE, IMPERSONATE, OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION,
    REQUEST_TIMEOUT, pick_proxy, pick_browser_profile, validate_browser_profile,
    BROWSER_PROFILE_POOL, build_browser_environment,
)


logger = logging.getLogger(__name__)
_GEO_CACHE: dict[str, dict] = {}
_GEO_CACHE_LOCK = threading.Lock()
_CF_COOKIE_NAMES = ("cf_clearance", "__cf_bm", "__cfseq", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m")
_COUNTRY_NAME_TO_CODE = {
    "JAPAN": "JP", "CHINA": "CN", "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US",
    "UNITED KINGDOM": "GB", "GREAT BRITAIN": "GB", "VIETNAM": "VN", "VIET NAM": "VN",
    "THAILAND": "TH", "SINGAPORE": "SG", "HONG KONG": "HK", "TAIWAN": "TW",
    "SOUTH KOREA": "KR", "REPUBLIC OF KOREA": "KR", "INDONESIA": "ID", "MALAYSIA": "MY",
    "PHILIPPINES": "PH", "INDIA": "IN", "AUSTRALIA": "AU", "CANADA": "CA",
    "GERMANY": "DE", "FRANCE": "FR", "NETHERLANDS": "NL", "BRAZIL": "BR",
}


def close_browser_session(session) -> None:
    """Close a BrowserSession while retaining compatibility with test doubles."""
    if session is None:
        return
    close = getattr(type(session), "close", None)
    if callable(close):
        close(session)
        return
    raw_session = getattr(session, "session", None)
    if raw_session is not None:
        raw_session.close()


def _seed_uuid(seed: str, salt: str) -> str:
    text = f"{salt}:{seed}".strip()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, text))


def _seed_int(seed: str, salt: str, *, bits: int = 63) -> int:
    digest = hashlib.sha256(f"{salt}:{seed}".encode("utf-8")).digest()
    nbytes = max(1, (bits + 7) // 8)
    value = int.from_bytes(digest[:nbytes], "big")
    mask = (1 << bits) - 1
    return value & mask


def _seeded_browser_profile(seed: str, geo: dict | None = None) -> dict:
    if not seed:
        return pick_browser_profile(geo)
    pool = list(BROWSER_PROFILE_POOL or [])
    if not pool:
        return pick_browser_profile(geo)
    idx = _seed_int(seed, "browser_profile_index", bits=32) % len(pool)
    return build_browser_environment(geo, base_profile=pool[idx])


class BrowserSession:
    """
mô-đun mô phỏng Chrome trình duyệt HTTP phiênquản lý bộ 。
dùng curl_cffi impersonate công có thể vòng qua Cloudflare TLS chỉ vân detect。
"""

    def __init__(
        self,
        proxy: str = None,
        *,
        detect_exit_geo: bool = True,
        device_id: str | None = None,
        auth_session_logging_id: str | None = None,
        oai_session_id: str | None = None,
        sentinel_sid: str | None = None,
        browser_profile: dict | None = None,
        fingerprint_seed: str | None = None,
    ):
        """
Khởi tạophiên。

Args:
proxy: proxyđịa chỉ， nếu \"socks5h://user:pass@host:port\"。
không truyền thì từ config.PROXY_POOL ngẫu nhiênrút một 。
tường minhtruyền \"\" bảng hiện cấm dùng proxy。
detect_exit_geo: là không dò đo egress IP và tự độngchọn chọn ngôn lời / khivùng profile。
góitruy vấn v.v.ngắn requestcó thể đóng，tránhmức ngoài mạngchờ。
"""
        # proxy=None  → 从池里随机抽（默认行为），并按代理池上游配置决定是否链式
        # proxy=""    → 禁用代理（直连）
        # proxy="..." → 使用指定代理，不套用代理池上游
        self._proxy_pool_relay = None
        if proxy is None:
            self.proxy = pick_proxy()
            self.proxy_target = self.proxy
            if self.proxy:
                from core.proxy_chain import open_proxy_pool_proxy
                transport_proxy, self._proxy_pool_relay = open_proxy_pool_proxy(self.proxy)
            else:
                transport_proxy = ""
        else:
            self.proxy = proxy
            self.proxy_target = proxy
            transport_proxy = proxy

        self.fingerprint_seed = str(fingerprint_seed or "").strip()

        # 生成/复用设备ID（oai-did），整个任务周期复用。
        if device_id:
            self.device_id = str(device_id)
        elif self.fingerprint_seed:
            self.device_id = _seed_uuid(self.fingerprint_seed, "device_id")
        else:
            self.device_id = str(uuid.uuid4())

        # 生成 auth_session_logging_id
        if auth_session_logging_id:
            self.auth_session_logging_id = str(auth_session_logging_id)
        elif self.fingerprint_seed:
            self.auth_session_logging_id = _seed_uuid(self.fingerprint_seed, "auth_session_logging_id")
        else:
            self.auth_session_logging_id = str(uuid.uuid4())

        # Auth Web 在同一份 document 内复用该 ID；真正发生页面导航时再轮换。
        self.document_navigation_id = str(uuid.uuid4())

        # ChatGPT 前端会话 ID：CES / Statsig / API 链路内保持稳定。
        if oai_session_id:
            self.oai_session_id = str(oai_session_id)
        elif self.fingerprint_seed:
            self.oai_session_id = _seed_uuid(self.fingerprint_seed, "oai_session_id")
        else:
            self.oai_session_id = str(uuid.uuid4())

        # Datadog/RUM 关联 ID：每个 BrowserSession 独立生成，禁止跨账号复用。
        # 同一账号的运行时环境尽量保持固定，避免同账号多次操作指纹漂移。
        if self.fingerprint_seed:
            self.datadog_trace_id = str(_seed_int(self.fingerprint_seed, "datadog_trace_id"))
            self.datadog_parent_id = str(_seed_int(self.fingerprint_seed, "datadog_parent_id"))
        else:
            self.datadog_trace_id = str(random.getrandbits(63))
            self.datadog_parent_id = str(random.getrandbits(63))
        self.datadog_origin = "rum"
        # 先使用配置默认值，加载真实 ChatGPT 登录页后从 data-build/data-seq
        # 动态同步，避免滚动发布期间继续发送过期的前端版本头。
        self.client_build_number = str(OAI_CLIENT_BUILD_NUMBER)
        self.client_version = str(OAI_CLIENT_VERSION)

        # Sentinel SDK 内部 sid：真实 SDK 会单独生成一个 UUID，和 oai-did 不是同一个值。
        # Python 初始 p 与 Node Runner 最终 token 都复用这个 sid，保持同一 SDK 实例语义。
        if sentinel_sid:
            self.sentinel_sid = str(sentinel_sid)
        elif self.fingerprint_seed:
            self.sentinel_sid = _seed_uuid(self.fingerprint_seed, "sentinel_sid")
        else:
            self.sentinel_sid = str(uuid.uuid4())
        # 密码注册 iframe 与顶层 Auth 页是两个独立 Sentinel SDK 实例。
        if self.fingerprint_seed:
            self.sentinel_iframe_sid = _seed_uuid(self.fingerprint_seed, "sentinel_iframe_sid")
        else:
            self.sentinel_iframe_sid = str(uuid.uuid4())
        if self.fingerprint_seed:
            self.react_listening_key = "_reactListening" + _seed_uuid(self.fingerprint_seed, "react_listening_key").replace("-", "")[:12]
            self.react_container_key = "__reactContainer$" + _seed_uuid(self.fingerprint_seed, "react_container_key").replace("-", "")[:11]
        else:
            self.react_listening_key = "_reactListening" + uuid.uuid4().hex[:12]
            self.react_container_key = "__reactContainer$" + uuid.uuid4().hex[:11]
        self.react_resources_key = "__reactResources$" + self.react_container_key.split("$", 1)[1]

        # 创建 curl_cffi 会话
        self.session = Session(impersonate=IMPERSONATE)

        # 设置代理
        if transport_proxy:
            self.session.proxies = {
                "http": transport_proxy,
                "https": transport_proxy,
            }

        # 设置超时
        self.session.timeout = REQUEST_TIMEOUT

        # 会话级熔断：收到 403/429 后停止继续打后续接口，避免异常状态下扩大误伤。
        self.blocked_until = 0.0
        self.blocked_reason = ""

        # 先用当前代理检测出口 IP 地理信息，再为本会话挑一份稳定浏览器画像。
        # 这样 Accept-Language / navigator.language / timezone 可自动跟随出口地区。
        self.exit_geo = self._detect_exit_geo() if detect_exit_geo else {}
        self._enforce_proxy_quality()
        if browser_profile:
            self.browser_profile = dict(browser_profile)
        else:
            self.browser_profile = dict(_seeded_browser_profile(self.fingerprint_seed, self.exit_geo))
        self.browser_profile["react_listening_key"] = self.react_listening_key
        self.browser_profile["react_container_key"] = self.react_container_key
        self.browser_profile["react_resources_key"] = self.react_resources_key
        issues = validate_browser_profile(self.browser_profile)
        if issues:
            logger.warning("[Vân tay] profile trình duyệt không khớp: %s", "; ".join(issues))

        # 让 HTTP Cookie、OAuth 参数 ext-oai-did、Sentinel 里的 id 三者一致。
        # 浏览器里 oai-did 通常会作为一方 Cookie 存在；协议层主动补齐可减少同一会话内
        # “头部/参数/JS 指纹有设备 ID，但 Cookie Jar 为空”的不一致。
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            self.session.cookies.set("oai-did", self.device_id, domain=domain, path="/")
        # 参考真实前端会话：语言不仅体现在 Accept-Language/oai-language，也写入
        # 同一个 Cookie Jar，避免代理为 JP 但 Cookie 仍泄漏默认地区。
        locale = self.navigator_language()
        for domain in ("chatgpt.com", "auth.openai.com"):
            self.session.cookies.set("oai-locale", locale, domain=domain, path="/")

        # Cloudflare 状态只能来自真实响应 Set-Cookie；这里仅记录变化，不主动伪造/覆盖。
        self._cf_cookie_seen = self.cf_cookie_snapshot()

    def cf_cookie_snapshot(self) -> dict:
        """trả vềhiện tại CookieJar Cloudflare liên quan khoá Cookie trích cần ，tiện tại xác nhậncùng IP/cùng phiênnối tiếp tính 。"""
        out = {}
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                if name in _CF_COOKIE_NAMES:
                    out[f"{getattr(cookie, 'domain', '')}:{name}"] = len(str(getattr(cookie, "value", "") or ""))
        except Exception:
            pass
        return out

    def close(self) -> None:
        """Close the HTTP session and any proxy-pool relay owned by this session."""
        try:
            self.session.close()
        finally:
            relay, self._proxy_pool_relay = self._proxy_pool_relay, None
            if relay is not None:
                relay.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @staticmethod
    def _short_value(value: object, limit: int = 80) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."

    def fingerprint_summary(self) -> dict:
        """trả vềphù hợp khớp nhật ký/rơi kho trình duyệtchỉ vân trích cần ，không mở rộng mở qua dài số nhóm trường。"""
        profile = getattr(self, "browser_profile", {}) or {}
        geo = profile.get("geo") or self.exit_geo or {}
        summary = {
            "device_id": self.device_id,
            "proxy": self.proxy or "",
            "proxy_mode": "direct" if not self.proxy else "proxy",
            "browser_family": profile.get("browser_family") or "chrome",
            "browser_os": profile.get("browser_os") or "macOS",
            "user_agent": profile.get("user_agent") or USER_AGENT,
            "accept_language": profile.get("accept_language") or ACCEPT_LANGUAGE,
            "navigator_language": profile.get("navigator_language") or "zh-CN",
            "navigator_languages": list(profile.get("navigator_languages") or []),
            "timezone_iana": profile.get("timezone_iana") or "",
            "timezone_offset_minutes": int(profile.get("timezone_offset_minutes", 0) or 0),
            "timezone_name": profile.get("timezone_name") or "",
            "screen_width": int(profile.get("screen_width", 0) or 0),
            "screen_height": int(profile.get("screen_height", 0) or 0),
            "device_pixel_ratio": profile.get("device_pixel_ratio") or 0,
            "hardware_concurrency": profile.get("hardware_concurrency") or 0,
            "device_memory": profile.get("device_memory") or 0,
            "js_heap_size_limit": profile.get("js_heap_size_limit") or 0,
            "sec_ch_ua": profile.get("sec_ch_ua") or "",
            "sec_ch_ua_platform": profile.get("sec_ch_ua_platform") or "",
            "sec_ch_ua_platform_version": profile.get("sec_ch_ua_platform_version") or "",
            "sec_ch_ua_mobile": profile.get("sec_ch_ua_mobile") or "",
            "sec_ch_ua_arch": profile.get("sec_ch_ua_arch") or "",
            "sec_ch_ua_bitness": profile.get("sec_ch_ua_bitness") or "",
            "sec_ch_ua_model": profile.get("sec_ch_ua_model") or "",
            "sec_ch_ua_full_version_list": profile.get("sec_ch_ua_full_version_list") or "",
            "react_listening_key": profile.get("react_listening_key") or "",
            "react_container_key": profile.get("react_container_key") or "",
            "react_resources_key": profile.get("react_resources_key") or "",
            "sentinel_sid": self.sentinel_sid,
            "oai_session_id": self.oai_session_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "datadog_trace_id": self.datadog_trace_id,
            "datadog_parent_id": self.datadog_parent_id,
            "geo_country": geo.get("country") or "",
            "geo_city": geo.get("city") or "",
            "geo_timezone": geo.get("timezone") or "",
            "geo_org": geo.get("org") or "",
        }
        return summary

    def fingerprint_summary_text(self) -> str:
        """trích cần nén thành đơn dòng ，phía tiện nhật kýxuất。"""
        p = self.fingerprint_summary()
        parts = [
            f"device_id={self._short_value(p.get('device_id'), 12)}",
            f"proxy={self._short_value(p.get('proxy') or 'direct', 36)}",
            f"ua={self._short_value(p.get('user_agent'), 72)}",
            f"lang={p.get('accept_language')}",
            f"tz={p.get('timezone_iana')}({p.get('timezone_offset_minutes')})",
            f"screen={p.get('screen_width')}x{p.get('screen_height')}@{p.get('device_pixel_ratio')}",
            f"cpu={p.get('hardware_concurrency')}",
            f"mem={p.get('device_memory')}",
            f"geo={p.get('geo_country') or '?'}:{p.get('geo_city') or '?'}",
        ]
        return " ".join(parts)

    def _observe_cf_cookie_changes(self, url: str) -> None:
        current = self.cf_cookie_snapshot()
        if current != getattr(self, "_cf_cookie_seen", {}):
            logger.info("[CF] cập nhật trạng thái Cookie url=%s keys=%s", url, sorted(current.keys()))
            self._cf_cookie_seen = current

    def _enforce_proxy_quality(self) -> None:
        """gốctheo GeoIP org/ASN thô phán proxychất lượng ，mặc địnhtừ chối tuyệt nhà cloud/DC egress。"""
        try:
            from config import browser as _browser_cfg
            reject = bool(getattr(_browser_cfg, "REJECT_CLOUD_PROXY", True))
            keywords = list(getattr(_browser_cfg, "CLOUD_PROXY_ORG_KEYWORDS", []) or [])
        except Exception:
            return
        if not reject or not self.exit_geo:
            return
        org = str(self.exit_geo.get("org") or "").lower()
        if not org:
            return
        hit = next((kw for kw in keywords if kw and str(kw).lower() in org), "")
        if hit:
            raise RuntimeError(
                f"proxyegressgiốngnhà cloud/DC，đã từ chối tiếp tụcđăng ký："
                f"ip={self.exit_geo.get('ip') or '?'} country={self.exit_geo.get('country') or '?'} "
                f"org={self.exit_geo.get('org') or '?'} hit={hit}. "
                f"nếu chắc làproxy dân cư，có thể đặt REJECT_CLOUD_PROXY=False。"
            )

    def _cookie_header_for_domain(self, domain: str) -> str:
        """xuấthiện tạiphiênchochỉ định miền tên thấy được Cookie，cho Node VM document.cookie dùng。"""
        pairs = []
        wanted = domain.lower().lstrip(".")
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                value = getattr(cookie, "value", "")
                cdom = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
                if not name:
                    continue
                if cdom and not (wanted == cdom or wanted.endswith("." + cdom) or cdom.endswith("." + wanted)):
                    continue
                pairs.append(f"{name}={value}")
        except Exception:
            pass
        return "; ".join(pairs)

    def auth_cookie_header(self) -> str:
        return self._cookie_header_for_domain("auth.openai.com") or f"oai-did={self.device_id}"

    def chatgpt_cookie_header(self) -> str:
        return self._cookie_header_for_domain("chatgpt.com") or f"oai-did={self.device_id}"

    def _detect_exit_geo(self) -> dict:
        """thông qua hiện tạiproxydetectegress IP địa lý tin tin ；thất bạitrả vềtrống dict và về lùi đến mặc địnhđịa vùng profile。"""
        try:
            from config import browser as _browser_cfg
            if not getattr(_browser_cfg, "AUTO_BROWSER_LOCALE_FROM_IP", True):
                return {}
            endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
            timeout = float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
        except Exception:
            return {}

        cache_key = self.proxy or "__direct__"
        with _GEO_CACHE_LOCK:
            cached = _GEO_CACHE.get(cache_key)
            if cached is not None:
                return dict(cached)

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        for url in endpoints:
            try:
                resp = self.session.get(url, headers=headers, timeout=timeout)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                geo = self._normalize_geo_response(data)
                if geo.get("country") or geo.get("timezone"):
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[cache_key] = dict(geo)
                    logger.info(
                        "[Vân tay] geo IP egress: ip=%s country=%s city=%s timezone=%s",
                        geo.get("ip") or "?", geo.get("country") or "?",
                        geo.get("city") or "?", geo.get("timezone") or "?",
                    )
                    return geo
            except Exception as exc:
                logger.debug(f"[Vân tay] detect geo IP egress thất bại endpoint={url}: {type(exc).__name__}: {exc}")
                continue
        with _GEO_CACHE_LOCK:
            _GEO_CACHE[cache_key] = {}
        return {}

    @staticmethod
    def _normalize_country_code(value: object) -> str:
        text = str(value or "").strip().upper().replace("_", " ")
        if len(text) == 2 and text.isalpha():
            return text
        return _COUNTRY_NAME_TO_CODE.get(text, text if len(text) == 2 else "")

    @staticmethod
    def _normalize_geo_response(data: dict) -> dict:
        """kiêm dung ipinfo / ipapi / ipwho.is v.v.thường thấy JSON trường。"""
        if not isinstance(data, dict):
            return {}
        timezone = data.get("timezone")
        if isinstance(timezone, dict):
            timezone = timezone.get("id") or timezone.get("name")
        # ipwho.is 的 country="Japan"、country_code="JP"；旧逻辑优先 country
        # 会得到伪代码 JAPAN，随后语言画像错误回落 en-US。始终优先 ISO 字段。
        raw_country = data.get("country_code") or data.get("countryCode")
        if not raw_country:
            country_obj = data.get("country")
            if isinstance(country_obj, dict):
                raw_country = country_obj.get("code") or country_obj.get("iso_code") or country_obj.get("name")
            else:
                raw_country = country_obj
        return {
            "ip": data.get("ip") or data.get("query"),
            "country": BrowserSession._normalize_country_code(raw_country),
            "region": data.get("region") or data.get("regionName"),
            "city": data.get("city"),
            "timezone": timezone or "",
            "org": data.get("org") or data.get("isp") or data.get("connection", {}).get("org"),
        }

    def _get_common_headers(self) -> dict:
        """lấythông dùng requestđầu ，ưu trước dùngnày BrowserSession ổn định profile。"""
        profile = getattr(self, "browser_profile", {}) or {}
        headers = {
            "User-Agent": str(profile.get("user_agent") or USER_AGENT),
            "accept-language": str(profile.get("accept_language") or ACCEPT_LANGUAGE),
        }

        # Safari 不发送 Chromium Client Hints；Chrome/Chromium 画像才补 sec-ch-*。
        send_client_hints = bool(profile.get("send_client_hints", bool(SEC_CH_UA)))
        if send_client_hints:
            if profile.get("sec_ch_ua") or SEC_CH_UA:
                headers["sec-ch-ua"] = str(profile.get("sec_ch_ua") or SEC_CH_UA)
            if profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE:
                headers["sec-ch-ua-mobile"] = str(profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE)
            if profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM:
                headers["sec-ch-ua-platform"] = str(profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM)
            if SEND_HIGH_ENTROPY_CLIENT_HINTS:
                headers.update({
                    "sec-ch-ua-full-version-list": str(profile.get("sec_ch_ua_full_version_list") or SEC_CH_UA_FULL_VERSION_LIST),
                    "sec-ch-ua-platform-version": str(profile.get("sec_ch_ua_platform_version") or SEC_CH_UA_PLATFORM_VERSION),
                    "sec-ch-ua-arch": str(profile.get("sec_ch_ua_arch") or SEC_CH_UA_ARCH),
                    "sec-ch-ua-bitness": str(profile.get("sec_ch_ua_bitness") or SEC_CH_UA_BITNESS),
                    "sec-ch-ua-model": str(profile.get("sec_ch_ua_model") or SEC_CH_UA_MODEL),
                })
        return headers

    def navigator_language(self) -> str:
        """hiện tạiphiênprofiletrong navigator.language。"""
        return str((getattr(self, "browser_profile", {}) or {}).get("navigator_language") or "zh-CN")

    @staticmethod
    def _sec_fetch_site_for(target_origin: str, referer: str) -> str:
        """theo Referer thô lược mô-đun mô phỏng trình duyệt Sec-Fetch-Site。"""
        ref = (referer or "").lower()
        target = target_origin.lower().rstrip("/")
        if ref.startswith(target):
            return "same-origin"
        if ref.startswith("https://chatgpt.com") or ref.startswith("https://auth.openai.com") or ref.startswith("https://sentinel.openai.com"):
            return "cross-site"
        return "none"

    def get_datadog_headers(self) -> dict:
        """lấyhiện tạiphiênổn định Datadog/RUM liên quan liên đầu 。"""
        return {
            "x-datadog-origin": self.datadog_origin,
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": self.datadog_trace_id,
            "x-datadog-parent-id": self.datadog_parent_id,
        }

    def get_trace_context_headers(self) -> dict:
        """bổ sung Auth Web bắt gói trong W3C traceparent / Datadog tracestate。"""
        trace_hex = format(int(self.datadog_trace_id), "032x")[-32:]
        parent_hex = format(int(self.datadog_parent_id), "016x")[-16:]
        return {
            "traceparent": f"00-{trace_hex}-{parent_hex}-01",
            "tracestate": f"dd=s:1;o:{self.datadog_origin}",
        }

    def _attach_auth_rum_headers(self, headers: dict) -> dict:
        """Auth Web JSON nhận cổng đầu ：HAR chỉ ra hiện RUM/trace/access-flow，không mang oai-client-*。"""
        # 浏览器每个 fetch 都创建新的 span，而不是整个登录链复用同一 trace。
        self.datadog_trace_id = str(random.getrandbits(64) or 1)
        self.datadog_parent_id = str(random.getrandbits(64) or 1)
        headers.update(self.get_trace_context_headers())
        headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
        headers["x-openai-document-navigation-id"] = self.document_navigation_id
        headers.update(self.get_datadog_headers())
        return headers

    def rotate_document_navigation_id(self) -> str:
        self.document_navigation_id = str(uuid.uuid4())
        return self.document_navigation_id

    def js_timezone_offset_min(self) -> int:
        """trả về JS Date.getTimezoneOffset() ngôn nghĩa ：UTC-local，đông tám vùng là -480。"""
        profile = getattr(self, "browser_profile", {}) or {}
        return -int(profile.get("timezone_offset_minutes", 0) or 0)

    def _attach_datadog_headers(self, headers: dict) -> dict:
        """là frontend API requestbổ sung Datadog đầu ，hạ thấp không chẩn đoán ngắt đầu silent-drop khái tỷ lệ 。"""
        headers.update(self.get_datadog_headers())
        return headers

    def _attach_oai_context_headers(self, headers: dict) -> dict:
        """bổ sungcùngđặt dự ngữ cảnhđầu ，và oai-did Cookie / OAuth ext-oai-did giữ giữ một khiến 。"""
        headers["oai-client-build-number"] = str(getattr(self, "client_build_number", OAI_CLIENT_BUILD_NUMBER))
        headers["oai-client-version"] = str(getattr(self, "client_version", OAI_CLIENT_VERSION))
        headers["oai-device-id"] = self.device_id
        headers["oai-language"] = self.navigator_language()
        headers["oai-session-id"] = self.oai_session_id
        return headers

    def observe_chatgpt_document(self, response) -> None:
        """từnày thật thật trang đăng nhập HTML cùng bước ChatGPT frontend build phần tử số theo 。"""
        try:
            final_url = str(getattr(response, "url", "") or "")
            if urlparse(final_url).hostname != "chatgpt.com":
                return
            html = str(getattr(response, "text", "") or "")
            build = re.search(r'\bdata-build=["\']([^"\']+)', html[:200000])
            seq = re.search(r'\bdata-seq=["\']([^"\']+)', html[:200000])
            if build:
                self.client_version = build.group(1)
                self.browser_profile["build_id"] = self.client_version
            if seq:
                self.client_build_number = seq.group(1)
            if build or seq:
                logger.info(
                    "[Vân tay] đã đồng bộ phiên bản frontend từ trang đăng nhập ChatGPT：build=%s seq=%s",
                    self.client_version, self.client_build_number,
                )
        except Exception as exc:
            logger.debug("[Vân tay] parse build trang đăng nhập ChatGPT thất bại：%s", exc)

    def _attach_frontend_api_headers(self, headers: dict) -> dict:
        """frontend API thống nhấtđầu ：BrowserProfile + oai ngữ cảnh + Datadog。"""
        self._attach_oai_context_headers(headers)
        self._attach_datadog_headers(headers)
        return headers

    def get_nextauth_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """NextAuth `/api/auth/*` đầu ；HAR không mang mang oai-client-*。"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
        })
        return headers

    def get_chatgpt_headers(self, referer: str = "https://chatgpt.com/login") -> dict:
        """
lấy chatgpt.com miền tên requestđầu 。
dùng chobước1-3。
"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
        })
        return self._attach_frontend_api_headers(headers)

    def get_auth_headers(self, referer: str = "https://auth.openai.com/create-account/password") -> dict:
        """
lấy auth.openai.com miền tên requestđầu 。
dùng chobước7、10、12。
"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "application/json",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
            "origin": "https://auth.openai.com",
        })
        return self._attach_auth_rum_headers(headers)

    def get_auth_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True, target_origin: str = "https://auth.openai.com") -> dict:
        """
lấy auth.openai.com dẫn điều hướng requestđầu （dùng choGETtrangrequest）。
dùng chobước4、5、8。
"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": self._sec_fetch_site_for(target_origin, referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if referer:
            headers["referer"] = referer
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        # document 导航由浏览器网络栈发出，不携带 fetch/XHR 使用的
        # x-datadog-* 自定义头；跨站 OAuth 导航尤其需要保持原生头集合。
        return headers

    def get_chatgpt_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True) -> dict:
        """lấy chatgpt.com trangdẫn điều hướng requestđầu ，dùng chokhởi động trướctrang đăng nhập / về đến nên dùng trang 。"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": self._sec_fetch_site_for("https://chatgpt.com", referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if referer:
            headers["referer"] = referer
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers

    def get_sentinel_headers(self) -> dict:
        """
lấy sentinel.openai.com requestđầu 。
dùng chobước6、9、11。
"""
        from config import SENTINEL_SV
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://sentinel.openai.com",
            "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "priority": "u=1, i",
        })
        # 成功浏览器样本的 Sentinel iframe fetch 不带 oai-client-* 或
        # x-datadog-*，只保留标准 CORS 请求头。
        return headers

    def get_sentinel_frame_headers(self, user_initiated: bool = False) -> dict:
        """Sentinel SDK iframe cùng trạm văn hồ sơ dẫn điều hướng đầu 。"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "referer": "https://auth.openai.com/",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "iframe",
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers


    @staticmethod
    def _chatgpt_target_route(path: str) -> str:
        """thật thật URL path về một thành HAR trong x-openai-target-route hình trạng thái 。"""
        if path.startswith("/backend-api/accounts/check/"):
            return "/backend-api/accounts/check/{version}"
        if path.startswith("/backend-anon/accounts/check/"):
            return "/backend-anon/accounts/check/{version}"
        if path.startswith("/backend-api/conversation/") and path != "/backend-api/conversation/init":
            return "/backend-api/conversation/{conversation_id}"
        if path.startswith("/backend-anon/conversation/") and path != "/backend-anon/conversation/init":
            return "/backend-anon/conversation/{conversation_id}"
        return path

    def _attach_openai_target_headers_for_url(self, url: str, headers: dict | None) -> dict | None:
        """
tự độngbổ sung HAR chatgpt.com frontend API target chẩn đoán ngắt đầu 。

NextAuth `/api/auth/*` và auth.openai.com JSON nhận cổng tại bắt gói không mang này một số đầu ，
này trong chỉ với chatgpt.com backend/ces frontendnhận cổng bổ sung，tránhcác điều chỉnh dùng điểm thủ côngduy trì bảo vệ 。
"""
        if headers is None:
            return headers
        try:
            parsed = urlparse(str(url))
        except Exception:
            return headers
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if host != "chatgpt.com":
            return headers
        if not (path.startswith("/backend-api/") or path.startswith("/backend-anon/") or path.startswith("/ces/")):
            return headers
        # 不覆盖调用方显式指定的值，便于后续特殊接口单独调整。
        headers.setdefault("x-openai-target-path", path)
        headers.setdefault("x-openai-target-route", self._chatgpt_target_route(path))
        return headers

    def _raise_if_circuit_open(self) -> None:
        if self.blocked_until and time.time() < self.blocked_until:
            remain = max(0, int(self.blocked_until - time.time()))
            raise RuntimeError(f"BrowserSession đang ngắt mạch 熔断冷却 (còn {remain}s): {self.blocked_reason}")

    def reset_circuit_breaker(self) -> None:
        """dọnmột Khởi động trước tuỳ chọnsản sinh localngắt mạchtrạng thái。

một một số best-effort bootstrap nhận cổng trả về 403 khi，không thay bảng sau đóchínhxác thựcnhận cổng
không có thể dùng ；điều chỉnh dùng phía xonglỗicách rời saucó thể tường minhkhôi phụcnày phiêntiếp tụcthực thi。
"""
        self.blocked_until = 0.0
        self.blocked_reason = ""

    @staticmethod
    def _parse_retry_after(value: str | None) -> int:
        if not value:
            return 0
        text = str(value).strip()
        if text.isdigit():
            return max(0, int(text))
        return 0

    def _observe_response_for_circuit_breaker(self, resp, url: str):
        status = int(getattr(resp, "status_code", 0) or 0)
        self._observe_cf_cookie_changes(url)
        if status not in (403, 429):
            return resp
        retry_after = self._parse_retry_after(getattr(resp, "headers", {}).get("retry-after") if getattr(resp, "headers", None) else None)
        cool_down = retry_after if retry_after > 0 else (300 if status == 429 else 900)
        self.blocked_until = max(self.blocked_until, time.time() + min(cool_down, 3600))
        self.blocked_reason = f"HTTP {status} from {url}"
        logger.warning("[Ngắt mạch] phiên hiện tại nhận HTTP %s，vào cooldown %ss，dừng request tiếp：%s", status, min(cool_down, 3600), url)
        return resp

    def get(self, url: str, headers: dict = None, **kwargs):
        """gửi GET request"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.get(url, headers=headers, **kwargs)
        return self._observe_response_for_circuit_breaker(resp, url)

    def post(self, url: str, headers: dict = None, **kwargs):
        """gửi POST request"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.post(url, headers=headers, **kwargs)
        return self._observe_response_for_circuit_breaker(resp, url)
