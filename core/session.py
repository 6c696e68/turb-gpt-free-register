# -*- coding: utf-8 -*-
"""
Gói bọc curl_cffi Session
Quản lý thống nhất Cookie, header yêu cầu và vân tay TLS
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
    Trình quản lý phiên HTTP mô phỏng trình duyệt Chrome.
    Dùng chức năng impersonate của curl_cffi để vượt qua phát hiện dấu vân tay TLS của Cloudflare.
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
        Khởi tạo phiên.

        Args:
            proxy: Địa chỉ proxy, ví dụ "socks5h://user:pass@host:port".
                   Không truyền thì lấy ngẫu nhiên một cái từ config.PROXY_POOL.
                   Truyền tường minh "" nghĩa là tắt proxy.
            detect_exit_geo: Có dò IP đầu ra và tự chọn hồ sơ ngôn ngữ/múi giờ hay không.
                             Request ngắn như tra cứu gói có thể tắt để tránh chờ mạng thêm.
        """
        # proxy=None  → lấy ngẫu nhiên từ pool (hành vi mặc định), và theo cấu hình upstream pool proxy quyết định có chain hay không
        # proxy=""    → tắt proxy (kết nối trực tiếp)
        # proxy="..." → dùng proxy chỉ định, không áp dụng upstream pool proxy
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

        # Tạo/tái sử dụng ID thiết bị (oai-did), tái sử dụng trong toàn chu kỳ nhiệm vụ.
        if device_id:
            self.device_id = str(device_id)
        elif self.fingerprint_seed:
            self.device_id = _seed_uuid(self.fingerprint_seed, "device_id")
        else:
            self.device_id = str(uuid.uuid4())

        # Tạo auth_session_logging_id
        if auth_session_logging_id:
            self.auth_session_logging_id = str(auth_session_logging_id)
        elif self.fingerprint_seed:
            self.auth_session_logging_id = _seed_uuid(self.fingerprint_seed, "auth_session_logging_id")
        else:
            self.auth_session_logging_id = str(uuid.uuid4())

        # Auth Web tái sử dụng ID này trong cùng một document; chỉ luân chuyển khi thực sự điều hướng trang.
        self.document_navigation_id = str(uuid.uuid4())

        # ID phiên frontend ChatGPT: giữ ổn định trong chuỗi CES / Statsig / API.
        if oai_session_id:
            self.oai_session_id = str(oai_session_id)
        elif self.fingerprint_seed:
            self.oai_session_id = _seed_uuid(self.fingerprint_seed, "oai_session_id")
        else:
            self.oai_session_id = str(uuid.uuid4())

        # ID liên kết Datadog/RUM: mỗi BrowserSession tạo độc lập, cấm tái dùng cross-account.
        # Môi trường runtime của cùng một tài khoản cố gắng giữ cố định, tránh trôi dấu vân tay khi thao tác nhiều lần cùng tài khoản.
        if self.fingerprint_seed:
            self.datadog_trace_id = str(_seed_int(self.fingerprint_seed, "datadog_trace_id"))
            self.datadog_parent_id = str(_seed_int(self.fingerprint_seed, "datadog_parent_id"))
        else:
            self.datadog_trace_id = str(random.getrandbits(63))
            self.datadog_parent_id = str(random.getrandbits(63))
        self.datadog_origin = "rum"
        # Trước hết dùng giá trị mặc định cấu hình, sau khi tải trang đăng nhập ChatGPT thật thì từ data-build/data-seq
        # Đồng bộ động, tránh tiếp tục gửi header phiên bản frontend đã hết hạn trong quá trình rolling release.
        self.client_build_number = str(OAI_CLIENT_BUILD_NUMBER)
        self.client_version = str(OAI_CLIENT_VERSION)

        # sid nội bộ Sentinel SDK: SDK thật sẽ tạo riêng một UUID, không cùng giá trị với oai-did.
        # p ban đầu của Python và token cuối của Node Runner đều tái sử dụng sid này, giữ ngữ nghĩa cùng một instance SDK.
        if sentinel_sid:
            self.sentinel_sid = str(sentinel_sid)
        elif self.fingerprint_seed:
            self.sentinel_sid = _seed_uuid(self.fingerprint_seed, "sentinel_sid")
        else:
            self.sentinel_sid = str(uuid.uuid4())
        # iframe đăng ký mật khẩu và trang Auth cấp cao nhất là hai phiên bản Sentinel SDK độc lập.
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

        # Tạo phiên curl_cffi
        self.session = Session(impersonate=IMPERSONATE)

        # Thiết lập proxy
        if transport_proxy:
            self.session.proxies = {
                "http": transport_proxy,
                "https": transport_proxy,
            }

        # Thiết lập timeout
        self.session.timeout = REQUEST_TIMEOUT

        # Cầu chì cấp phiên: sau khi nhận 403/429 thì dừng gọi các API tiếp theo, tránh mở rộng thiệt hại nhầm trong trạng thái bất thường.
        self.blocked_until = 0.0
        self.blocked_reason = ""

        # Trước tiên dùng proxy hiện tại kiểm tra thông tin địa lý IP ra, rồi chọn một hồ sơ trình duyệt ổn định cho phiên này.
        # Như vậy Accept-Language / navigator.language / timezone có thể tự theo vùng xuất proxy.
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

        # Làm cho HTTP Cookie, tham số OAuth ext-oai-did, và id trong Sentinel ba thứ nhất quán.
        # Trong trình duyệt oai-did thường tồn tại như first-party Cookie; lớp protocol chủ động bổ sung có thể giảm trong cùng phiên
        # Sự không nhất quán “header/tham số/dấu vân tay JS có device ID, nhưng Cookie Jar trống”.
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            self.session.cookies.set("oai-did", self.device_id, domain=domain, path="/")
        # Tham chiếu phiên frontend thật: ngôn ngữ không chỉ ở Accept-Language/oai-language, mà còn ghi vào
        # Cùng một Cookie Jar, tránh proxy là JP nhưng Cookie vẫn rò rỉ vùng mặc định.
        locale = self.navigator_language()
        for domain in ("chatgpt.com", "auth.openai.com"):
            self.session.cookies.set("oai-locale", locale, domain=domain, path="/")

        # Trạng thái Cloudflare chỉ có thể đến từ Set-Cookie response thật; ở đây chỉ ghi nhận thay đổi, không chủ động giả mạo/ghi đè.
        self._cf_cookie_seen = self.cf_cookie_snapshot()

    def cf_cookie_snapshot(self) -> dict:
        """Trả tóm tắt Cookie Cloudflare trong CookieJar hiện tại, tiện xác nhận liên tục cùng IP/cùng session."""
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
        """Trả về tóm tắt vân tay trình duyệt phù hợp log/lưu DB, không bung các trường mảng quá dài."""
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
        """Nén tóm tắt thành một dòng, tiện xuất nhật ký."""
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
        """Đánh giá thô chất lượng proxy theo GeoIP org/ASN, mặc định từ chối cổng ra cloud vendor/DC."""
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
                f"IP egress của proxy nghi là nhà cloud/DC, đã từ chối tiếp tục đăng ký: "
                f"ip={self.exit_geo.get('ip') or '?'} country={self.exit_geo.get('country') or '?'} "
                f"org={self.exit_geo.get('org') or '?'} hit={hit}. "
                f"Nếu chắc là proxy dân cư, có thể đặt REJECT_CLOUD_PROXY=False."
            )

    def _cookie_header_for_domain(self, domain: str) -> str:
        """Xuất Cookie của phiên hiện tại hiển thị cho miền chỉ định, dùng cho Node VM document.cookie."""
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
        """Qua proxy hiện tại phát hiện thông tin địa lý IP đầu ra; thất bại trả về dict rỗng và fallback về hồ sơ khu vực mặc định."""
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
        """Tương thích các trường JSON phổ biến như ipinfo / ipapi / ipwho.is."""
        if not isinstance(data, dict):
            return {}
        timezone = data.get("timezone")
        if isinstance(timezone, dict):
            timezone = timezone.get("id") or timezone.get("name")
        # country="Japan", country_code="JP" của ipwho.is; logic cũ ưu tiên country
        # Sẽ ra mã giả JAPAN, rồi hồ sơ ngôn ngữ fallback sai về en-US. Luôn ưu tiên trường ISO.
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
        """Lấy header yêu cầu chung, ưu tiên dùng hồ sơ ổn định của BrowserSession này."""
        profile = getattr(self, "browser_profile", {}) or {}
        headers = {
            "User-Agent": str(profile.get("user_agent") or USER_AGENT),
            "accept-language": str(profile.get("accept_language") or ACCEPT_LANGUAGE),
        }

        # Safari không gửi Chromium Client Hints; chỉ hồ sơ Chrome/Chromium mới bổ sung sec-ch-*.
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
        """navigator.language trong hồ sơ phiên hiện tại."""
        return str((getattr(self, "browser_profile", {}) or {}).get("navigator_language") or "zh-CN")

    @staticmethod
    def _sec_fetch_site_for(target_origin: str, referer: str) -> str:
        """Mô phỏng thô Sec-Fetch-Site của trình duyệt theo Referer."""
        ref = (referer or "").lower()
        target = target_origin.lower().rstrip("/")
        if ref.startswith(target):
            return "same-origin"
        if ref.startswith("https://chatgpt.com") or ref.startswith("https://auth.openai.com") or ref.startswith("https://sentinel.openai.com"):
            return "cross-site"
        return "none"

    def get_datadog_headers(self) -> dict:
        """Lấy header liên kết Datadog/RUM ổn định của phiên hiện tại."""
        return {
            "x-datadog-origin": self.datadog_origin,
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": self.datadog_trace_id,
            "x-datadog-parent-id": self.datadog_parent_id,
        }

    def get_trace_context_headers(self) -> dict:
        """Bổ sung W3C traceparent / Datadog tracestate trong gói bắt Auth Web."""
        trace_hex = format(int(self.datadog_trace_id), "032x")[-32:]
        parent_hex = format(int(self.datadog_parent_id), "016x")[-16:]
        return {
            "traceparent": f"00-{trace_hex}-{parent_hex}-01",
            "tracestate": f"dd=s:1;o:{self.datadog_origin}",
        }

    def _attach_auth_rum_headers(self, headers: dict) -> dict:
        """Header giao diện Auth Web JSON: trong HAR chỉ xuất hiện RUM/trace/access-flow, không kèm oai-client-*."""
        # Mỗi fetch của trình duyệt đều tạo span mới, thay vì cả chuỗi đăng nhập tái dùng cùng một trace.
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
        """Trả về ngữ nghĩa JS Date.getTimezoneOffset(): UTC-local, múi giờ Đông 8 là -480."""
        profile = getattr(self, "browser_profile", {}) or {}
        return -int(profile.get("timezone_offset_minutes", 0) or 0)

    def _attach_datadog_headers(self, headers: dict) -> dict:
        """Bổ sung header Datadog cho các yêu cầu API frontend, giảm xác suất silent-drop khi thiếu header chẩn đoán."""
        headers.update(self.get_datadog_headers())
        return headers

    def _attach_oai_context_headers(self, headers: dict) -> dict:
        """Bổ sung header ngữ cảnh cùng thiết bị, giữ nhất quán với Cookie oai-did / OAuth ext-oai-did."""
        headers["oai-client-build-number"] = str(getattr(self, "client_build_number", OAI_CLIENT_BUILD_NUMBER))
        headers["oai-client-version"] = str(getattr(self, "client_version", OAI_CLIENT_VERSION))
        headers["oai-device-id"] = self.device_id
        headers["oai-language"] = self.navigator_language()
        headers["oai-session-id"] = self.oai_session_id
        return headers

    def observe_chatgpt_document(self, response) -> None:
        """Đồng bộ metadata build frontend ChatGPT từ HTML trang đăng nhập thực tế lần này."""
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
        """Header thống nhất API frontend: BrowserProfile + ngữ cảnh oai + Datadog."""
        self._attach_oai_context_headers(headers)
        self._attach_datadog_headers(headers)
        return headers

    def get_nextauth_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """Header NextAuth `/api/auth/*`; không mang oai-client-* trong HAR."""
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
        Lấy header yêu cầu cho miền chatgpt.com.
        Dùng cho bước 1-3.
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
        Lấy header request domain auth.openai.com.
        Dùng cho bước 7, 10, 12.
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
        Lấy header request điều hướng auth.openai.com (dùng cho request GET trang).
        Dùng cho bước 4, 5, 8.
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
        # Điều hướng document do network stack trình duyệt phát, không mang header mà fetch/XHR dùng
        # Header tùy chỉnh x-datadog-*; điều hướng OAuth cross-site đặc biệt cần giữ bộ header gốc.
        return headers

    def get_chatgpt_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True) -> dict:
        """Lấy header điều hướng trang chatgpt.com, dùng để làm nóng trang đăng nhập / quay lại trang ứng dụng."""
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
        Lấy header request của sentinel.openai.com.
        Dùng cho bước 6, 9, 11.
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
        # Fetch iframe Sentinel của mẫu trình duyệt thành công không mang oai-client-* hoặc
        # x-datadog-*, chỉ giữ các header CORS chuẩn.
        return headers

    def get_sentinel_frame_headers(self, user_initiated: bool = False) -> dict:
        """Header điều hướng tài liệu same-origin của iframe Sentinel SDK."""
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
        """Chuẩn hóa path URL thật thành dạng x-openai-target-route trong HAR."""
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
        Tự động bổ sung header chẩn đoán target cho API frontend chatgpt.com trong HAR.

        Các giao diện NextAuth `/api/auth/*` và JSON auth.openai.com trong gói bắt không mang các header này,
        ở đây chỉ bổ sung cho các giao diện frontend backend/ces của chatgpt.com, tránh phải duy trì thủ công tại từng điểm gọi.
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
        # Không ghi đè giá trị do bên gọi chỉ định rõ, thuận tiện điều chỉnh riêng các interface đặc biệt sau này.
        headers.setdefault("x-openai-target-path", path)
        headers.setdefault("x-openai-target-route", self._chatgpt_target_route(path))
        return headers

    def _raise_if_circuit_open(self) -> None:
        if self.blocked_until and time.time() < self.blocked_until:
            remain = max(0, int(self.blocked_until - time.time()))
            raise RuntimeError(f"当前 BrowserSession 已熔断冷却（剩余 {remain}s): {self.blocked_reason}")

    def reset_circuit_breaker(self) -> None:
        """Xóa một lần trạng thái cầu chì cục bộ do preheat tùy chọn tạo ra.

        Khi một số API bootstrap best-effort trả 403, không có nghĩa các API xác thực chính thức sau đó
        không dùng được; sau khi bên gọi đã cô lập lỗi có thể khôi phục tường minh phiên này để tiếp tục.
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
        """发送 GET 请求"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.get(url, headers=headers, **kwargs)
        return self._observe_response_for_circuit_breaker(resp, url)

    def post(self, url: str, headers: dict = None, **kwargs):
        """发送 POST 请求"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.post(url, headers=headers, **kwargs)
        return self._observe_response_for_circuit_breaker(resp, url)
