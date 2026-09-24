# -*- coding: utf-8 -*-
"""
Cấu hình fingerprint trình duyệt và HTTP client.

Giữ một "hồ sơ môi trường trình duyệt" dùng chung ba lớp:
1. header TLS / HTTP của curl_cffi;
2. Python sinh p ban đầu của Sentinel;
3. Node VM chạy sdk.js.

Nguyên tắc: ổn định trong một BrowserSession, phân tán tự nhiên giữa các session; header giao thức và JS
navigator/screen/timezone/client hints không được mâu thuẫn nhau.
"""
from __future__ import annotations

from config.env_loader import apply_env_overrides

import random
import re
from datetime import datetime
from zoneinfo import ZoneInfo


def _latest_chrome_major(default: str = "146") -> str:
    """Tương thích import module cũ; phải khớp phiên bản TLS impersonate thực của curl_cffi."""
    return default


CHROME_MAJOR = "146"
CHROME_FULL_VERSION = "146.0.0.0"

SAFARI_VERSION = ""
SAFARI_WEBKIT_VERSION = "537.36"
MAC_OS_UA_VERSION = "10_15_7"

# ---------- curl_cffi giả lập trình duyệt ----------
# curl_cffi 0.15 cao nhất tích hợp là chrome146. UA, Client Hints, JS navigator
# phải đồng bộ 146; không được ghép fingerprint lệch phiên bản TLS=146, HTTP/JS=149.
IMPERSONATE = "chrome146"

# ---------- Hồ sơ Chrome desktop ----------
BROWSER_FAMILY = "chrome"
BROWSER_OS = "macOS"
# Field liên quan OS phải khớp cả ba: UA / Client Hints / JS navigator.
NAVIGATOR_PLATFORM = "MacIntel"
NAVIGATOR_VENDOR = "Google Inc."
USER_AGENT_DATA_PLATFORM = "macOS"
USER_AGENT = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X {MAC_OS_UA_VERSION}) "
    f"AppleWebKit/{SAFARI_WEBKIT_VERSION} (KHTML, like Gecko) "
    f"Chrome/{CHROME_FULL_VERSION} Safari/{SAFARI_WEBKIT_VERSION}"
)

SEC_CH_UA = '"Google Chrome";v="146", "Chromium";v="146", "Not)A;Brand";v="24"'
SEC_CH_UA_FULL_VERSION_LIST = '"Google Chrome";v="146.0.0.0", "Chromium";v="146.0.0.0", "Not)A;Brand";v="24.0.0.0"'
SEC_CH_UA_PLATFORM = '"macOS"'
SEC_CH_UA_PLATFORM_VERSION = '"15.7.0"'
SEC_CH_UA_MOBILE = "?0"
SEC_CH_UA_ARCH = '"arm"'
SEC_CH_UA_BITNESS = '"64"'
SEC_CH_UA_MODEL = '""'
SEND_CLIENT_HINTS = True
SEND_HIGH_ENTROPY_CLIENT_HINTS = False

# ---------- Ngôn ngữ / múi giờ ----------
BROWSER_LOCALE_PROFILE = "jp"
AUTO_BROWSER_LOCALE_FROM_IP = True
IP_GEO_TIMEOUT = 6.0
IP_GEO_ENDPOINTS = [
    "https://ipinfo.io/json",
    "https://ipapi.co/json",
    "https://ipwho.is/",
]

# Chẩn đoán chất lượng đầu ra proxy: mặc định không chặn, chỉ từ chối ASN cloud/DC khi bật tay.
# Người dùng có thể cố ý dùng đầu ra cloud cố định để tái hiện bắt gói, nên mặc định False.
REJECT_CLOUD_PROXY = False
CLOUD_PROXY_ORG_KEYWORDS = [
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
    "digitalocean", "linode", "akamai", "ovh", "hetzner", "oracle",
    "tencent", "alibaba", "aliyun", "huawei cloud", "vultr", "contabo",
    "data center", "datacenter", "hosting", "host", "server", "cloud",
]

# ---------- Chế độ tiết kiệm data trình duyệt Roxy/Cloak ----------
# Mặc định tắt. Bật thì chỉ chặn ảnh/media tuỳ chọn và URL thống kê/bên thứ ba liệt kê dưới;
# không chặn document, script lõi, stylesheet, xhr/fetch, websocket cần cho đăng nhập;
# Playwright cho qua URL có từ khoá mã OTP/challenge.
# Chỉ áp Roxy/Cloak, trình duyệt local mới cần tiết kiệm băng thông; Browser Use/Skyvern cloud
# không cài interceptor tiết kiệm data. Selenium/CDP chỉ chặn theo hậu tố URL; captcha lỗi thì tắt.
BROWSER_DATA_SAVER_MODE: bool = False
# Sau khi đăng ký đã có accessToken, chặn vỏ ứng dụng/telemetry ChatGPT không còn cần.
# Chỉ có hiệu lực giai đoạn sau đăng ký Roxy/Cloak, không ảnh hưởng email, mã OTP và trang đăng nhập.
BROWSER_DATA_SAVER_DEEP_MODE: bool = True
# Mỗi dòng một Playwright resource_type. Có thể image/media/font/manifest/texttrack;
# mặc định chỉ chặn image, media; cũng cấu hình được stylesheet/font. Roxy còn tắt tải ảnh qua tham số khởi động Chromium.
# Layout hoặc captcha lỗi thì tắt chế độ.
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES: list[str] = ["image", "media"]
# Chặn thêm cấp URL glob. Dưới đây là tài nguyên thống kê RUM/quảng cáo xác nhận không tham gia
# luồng chính đăng ký email/mật khẩu; Google GSI chỉ cho đăng nhập Google, mặc định chặn khi không dùng Google.
# Đừng coi CDN chunk ChatGPT/auth.openai là ứng viên: chunk chỉ vài hàm được gọi
# vẫn có thể phụ trách route, đổi form hoặc lazy-load; phải A/B một biến rồi mới thêm rule.
# Đừng thêm API lõi chatgpt/openai hoặc URL sentinel vào đây.
# `**` khớp path bất kỳ trong URL; Playwright/Selenium của Roxy/Cloak đọc bộ rule này.
BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS: list[str] = [
    "**://auth.openai.com/awe/api/v2/rum**",
    "**://chatgpt.com/awe/api/v2/rum**",
    "**://chatgpt.com/ces/statsc/flush**",
    "**://connect.facebook.net/**",
    "**://analytics.tiktok.com/**",
    "**://snap.licdn.com/**",
    "**://bat.bing.com/**",
    "**://accounts.google.com/gsi/client**",
]

# ---------- Log chi tiết lưu lượng trình duyệt Roxy/Cloak ----------
# Mặc định tắt; bật thì cuối mỗi lần đăng ký in URL, loại, trạng thái và kích thước tài nguyên, sắp theo tổng byte request giảm dần.
# Giá trị query URL được che; không lưu body request/response hay header đầy đủ.
BROWSER_TRAFFIC_DETAIL_LOG: bool = False
BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES: int = 2000

# ---------- Coverage JS chính xác trình duyệt Roxy/Cloak ----------
# Bật thì qua Chrome DevTools Protocol Profiler ghi hàm/vùng code JavaScript
# thực sự chạy trong phiên. Chỉ lưu tên hàm, số lần gọi và offset, không đọc tham số, giá trị trả về
# hay source; Browser Use/Skyvern cloud không bật listener này; mặc định tắt, tránh overhead cho đăng ký bình thường.
BROWSER_JS_COVERAGE_LOG: bool = False
BROWSER_JS_COVERAGE_MAX_ENTRIES: int = 1000
COUNTRY_LOCALE_PROFILE_MAP = {
    "JP": "jp", "CN": "cn", "HK": "hk", "TW": "tw", "US": "us", "CA": "us",
    "SG": "sg", "GB": "gb", "AU": "gb", "DE": "de", "FR": "fr", "NL": "nl",
    "VN": "vn",
}

# Quốc gia đầu ra chưa có hồ sơ đầy đủ riêng thì ít nhất tự khớp ngôn ngữ trình duyệt. Múi giờ vẫn lấy thẳng
# giá trị API địa lý IP; đổi quốc gia proxy sẽ không rơi về ja-JP/Asia-Tokyo cố định.
COUNTRY_LANGUAGE_TAG_MAP = {
    "TH": "th-TH", "ID": "id-ID", "MY": "ms-MY", "PH": "en-PH",
    "KR": "ko-KR", "IN": "en-IN", "BR": "pt-BR", "MX": "es-MX",
    "ES": "es-ES", "IT": "it-IT", "PT": "pt-PT", "PL": "pl-PL",
    "RU": "ru-RU", "TR": "tr-TR", "AE": "ar-AE", "SA": "ar-SA",
    "ZA": "en-ZA", "NZ": "en-NZ", "IE": "en-IE", "AT": "de-AT",
    "CH": "de-CH", "BE": "nl-BE", "SE": "sv-SE", "NO": "nb-NO",
    "DK": "da-DK", "FI": "fi-FI", "CZ": "cs-CZ", "RO": "ro-RO",
    "HU": "hu-HU", "GR": "el-GR", "IL": "he-IL", "UA": "uk-UA",
}

BROWSER_LOCALE_PROFILES = {
    "jp": {"navigator_language": "ja-JP", "navigator_languages": ["ja-JP"], "accept_language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Tokyo", "timezone_offset_minutes": 9 * 60, "timezone_name": "Japan Standard Time"},
    "cn": {"navigator_language": "zh-CN", "navigator_languages": ["zh-CN"], "accept_language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Shanghai", "timezone_offset_minutes": 8 * 60, "timezone_name": "China Standard Time"},
    "us": {"navigator_language": "en-US", "navigator_languages": ["en-US"], "accept_language": "en-US,en;q=0.9", "timezone_iana": "America/Los_Angeles", "timezone_offset_minutes": -7 * 60, "timezone_name": "Pacific Daylight Time"},
    "sg": {"navigator_language": "en-SG", "navigator_languages": ["en-SG"], "accept_language": "en-SG,en-US;q=0.9,en;q=0.8", "timezone_iana": "Asia/Singapore", "timezone_offset_minutes": 8 * 60, "timezone_name": "Singapore Standard Time"},
    "hk": {"navigator_language": "zh-HK", "navigator_languages": ["zh-HK"], "accept_language": "zh-HK,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6", "timezone_iana": "Asia/Hong_Kong", "timezone_offset_minutes": 8 * 60, "timezone_name": "Hong Kong Standard Time"},
    "tw": {"navigator_language": "zh-TW", "navigator_languages": ["zh-TW"], "accept_language": "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Taipei", "timezone_offset_minutes": 8 * 60, "timezone_name": "Taipei Standard Time"},
    "gb": {"navigator_language": "en-GB", "navigator_languages": ["en-GB"], "accept_language": "en-GB,en-US;q=0.9,en;q=0.8", "timezone_iana": "Europe/London", "timezone_offset_minutes": 1 * 60, "timezone_name": "British Summer Time"},
    "de": {"navigator_language": "de-DE", "navigator_languages": ["de-DE"], "accept_language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Berlin", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "fr": {"navigator_language": "fr-FR", "navigator_languages": ["fr-FR"], "accept_language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Paris", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "nl": {"navigator_language": "nl-NL", "navigator_languages": ["nl-NL"], "accept_language": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Amsterdam", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "vn": {"navigator_language": "vi-VN", "navigator_languages": ["vi-VN", "vi", "en-US", "en"], "accept_language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Ho_Chi_Minh", "timezone_offset_minutes": 7 * 60, "timezone_name": "Indochina Time"},
}

TIMEZONE_NAME_BY_IANA = {
    "Asia/Tokyo": "Japan Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Hong_Kong": "Hong Kong Standard Time",
    "Asia/Taipei": "Taipei Standard Time",
    "America/Los_Angeles": "Pacific Daylight Time",
    "America/New_York": "Eastern Daylight Time",
    "America/Chicago": "Central Daylight Time",
    "America/Denver": "Mountain Daylight Time",
    "Europe/London": "British Summer Time",
    "Europe/Berlin": "Central European Summer Time",
    "Europe/Paris": "Central European Summer Time",
    "Europe/Amsterdam": "Central European Summer Time",
    "Asia/Ho_Chi_Minh": "Indochina Time",
    "Asia/Bangkok": "Indochina Time",
}


def _offset_minutes_for_timezone(tz_name: str, default: int) -> int:
    try:
        offset = datetime.now(ZoneInfo(tz_name)).utcoffset()
        if offset is not None:
            return int(offset.total_seconds() // 60)
    except Exception:
        pass
    return int(default)


def _locale_profile_key_from_geo(geo: dict | None) -> str:
    if not geo or not AUTO_BROWSER_LOCALE_FROM_IP:
        return BROWSER_LOCALE_PROFILE
    country = str(geo.get("country") or geo.get("country_code") or "").upper()
    return COUNTRY_LOCALE_PROFILE_MAP.get(country, BROWSER_LOCALE_PROFILE)


def _build_locale_from_geo(geo: dict | None) -> dict:
    key = _locale_profile_key_from_geo(geo)
    resolved_profile = key
    locale = dict(BROWSER_LOCALE_PROFILES.get(key, BROWSER_LOCALE_PROFILES[BROWSER_LOCALE_PROFILE]))
    if geo and AUTO_BROWSER_LOCALE_FROM_IP:
        country = str(geo.get("country") or geo.get("country_code") or "").upper()
        # Hồ sơ riêng phủ các quốc gia thường gặp; quốc gia đã biết còn lại sinh field ngôn ngữ động. Nếu API địa lý
        # trả quốc gia không rõ, dùng en-US trung tính, không lộ hồ sơ tiếng Nhật mặc định của máy.
        if country not in COUNTRY_LOCALE_PROFILE_MAP:
            language_tag = COUNTRY_LANGUAGE_TAG_MAP.get(country, "en-US")
            resolved_profile = f"geo:{country.lower() or 'unknown'}"
            base_language = language_tag.split("-", 1)[0]
            languages = [language_tag]
            if base_language != language_tag:
                languages.append(base_language)
            if base_language != "en":
                languages.extend(["en-US", "en"])
                accept_language = f"{language_tag},{base_language};q=0.9,en-US;q=0.8,en;q=0.7"
            else:
                languages.append("en")
                accept_language = f"{language_tag},en;q=0.9"
            locale.update({
                "navigator_language": language_tag,
                "navigator_languages": list(dict.fromkeys(languages)),
                "accept_language": accept_language,
            })
        tz = str(geo.get("timezone") or "").strip()
        if tz:
            locale["timezone_iana"] = tz
            locale["timezone_offset_minutes"] = _offset_minutes_for_timezone(tz, int(locale["timezone_offset_minutes"]))
            locale["timezone_name"] = TIMEZONE_NAME_BY_IANA.get(tz, locale.get("timezone_name", ""))
    locale["locale_profile"] = resolved_profile
    return locale


_LOCALE = BROWSER_LOCALE_PROFILES.get(BROWSER_LOCALE_PROFILE, BROWSER_LOCALE_PROFILES["jp"])
NAVIGATOR_LANGUAGE = _LOCALE["navigator_language"]
NAVIGATOR_LANGUAGES = list(_LOCALE["navigator_languages"])
ACCEPT_LANGUAGE = _LOCALE["accept_language"]
TIMEZONE_IANA = _LOCALE["timezone_iana"]
TIMEZONE_OFFSET_MINUTES = int(_LOCALE["timezone_offset_minutes"])
TIMEZONE_NAME = _LOCALE["timezone_name"]

# ---------- Môi trường Sentinel / JS VM ----------
SCREEN_WIDTH = 1680
SCREEN_HEIGHT = 1050
HARDWARE_CONCURRENCY = 6
JS_HEAP_SIZE_LIMIT = 4395630592
DEVICE_MEMORY = 8

# Các list này phải khớp createBrowserContext trong sentinel/sentinel-runner.js.
NAVIGATOR_PROTO_SAMPLES = [
    "createAuctionNonce−function createAuctionNonce() { [native code] }",
    "clearOriginJoinedAdInterestGroups−function clearOriginJoinedAdInterestGroups() { [native code] }",
    "updateAdInterestGroups−function updateAdInterestGroups() { [native code] }",
    "canLoadAdAuctionFencedFrame−function canLoadAdAuctionFencedFrame() { [native code] }",
    "gpu−[object GPU]",
    "getBattery−function getBattery() { [native code] }",
    "getGamepads−function getGamepads() { [native code] }",
    "javaEnabled−function javaEnabled() { [native code] }",
    "sendBeacon−function sendBeacon() { [native code] }",
    "vibrate−function vibrate() { [native code] }",
    "login−[object NavigatorLogin]",
]
DOCUMENT_KEY_SAMPLES = [
    "currentScript", "scripts", "cookie", "URL", "documentURI", "referrer",
    "title", "characterSet", "charset", "compatMode", "contentType", "readyState",
    "visibilityState", "hidden", "hasFocus", "documentElement", "body",
    "addEventListener", "removeEventListener", "querySelector", "querySelectorAll",
    "getElementById", "getElementsByTagName", "createElement",
]
WINDOW_KEY_SAMPLES = [
    "window", "self", "top", "parent", "frames", "navigator", "screen", "location",
    "localStorage", "sessionStorage", "history", "innerWidth", "innerHeight",
    "outerWidth", "outerHeight", "devicePixelRatio", "chrome", "performance", "crypto",
    "TextEncoder", "URL", "URLSearchParams", "AbortController",
    "locationbar", "scrollX", "scrollY", "ondevicemotion",
    "requestAnimationFrame", "queueMicrotask", "onfocus", "onblur", "onpageshow",
]

SCRIPT_SRC_SAMPLES = [
    "https://accounts.google.com/gsi/client",
    "https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload",
    "https://sentinel.openai.com/sentinel/20260810913b/sdk.js",
]

WINDOW_FEATURE_FLAGS = {
    "ai": 0,
    "InstallTrigger": 0,
    "cache": 0,
    "data": 0,
    "solana": 0,
    "dump": 0,
    # Mẫu HAR p[24] là 0; mặc định không lộ, bật bằng công tắc hồ sơ khi cần.
    "requestIdleCallback": 0,
}

# ---------- Timeout HTTP ----------
REQUEST_TIMEOUT = 30

# Hồ sơ tham chiếu HAR: giải mã p[0]/p[2]/p[16] từ Default-all-domains-1784468371563.json.
HAR_CAPTURE_BASE_PROFILE = {"screen_width": 1680, "screen_height": 1050, "hardware_concurrency": 6, "device_memory": 8, "js_heap_size_limit": 4395630592, "device_pixel_ratio": 2}

# Pool hồ sơ desktop Chrome macOS thường gặp. Giữ nguyên trong một session; phân tán ngẫu nhiên giữa session.
# HAR_CAPTURE_BASE_PROFILE chỉ là một ứng viên, không cố định toàn cục.
BROWSER_PROFILE_POOL = [
    HAR_CAPTURE_BASE_PROFILE,
    {"screen_width": 1440, "screen_height": 900,  "hardware_concurrency": 8,  "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1512, "screen_height": 982,  "hardware_concurrency": 8,  "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1680, "screen_height": 1050, "hardware_concurrency": 8,  "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1728, "screen_height": 1117, "hardware_concurrency": 10, "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1800, "screen_height": 1169, "hardware_concurrency": 10, "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 2056, "screen_height": 1329, "hardware_concurrency": 12, "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
]


def build_browser_environment(geo: dict | None = None, base_profile: dict | None = None) -> dict:
    """Dựng hồ sơ môi trường trình duyệt đầy đủ, nguồn dữ liệu duy nhất cho mọi field fingerprint."""
    locale = _build_locale_from_geo(geo)
    profile = dict(base_profile or random.choice(BROWSER_PROFILE_POOL))
    profile.update({
        "locale_profile": locale.get("locale_profile", BROWSER_LOCALE_PROFILE),
        "geo": dict(geo or {}),
        "timezone_iana": locale["timezone_iana"],
        "timezone_offset_minutes": int(locale["timezone_offset_minutes"]),
        "timezone_name": locale["timezone_name"],
        "navigator_language": locale["navigator_language"],
        "navigator_languages": list(locale["navigator_languages"]),
        "accept_language": locale["accept_language"],
        "browser_family": BROWSER_FAMILY,
        "browser_os": BROWSER_OS,
        "navigator_platform": NAVIGATOR_PLATFORM,
        "navigator_vendor": NAVIGATOR_VENDOR,
        "user_agent_data_platform": USER_AGENT_DATA_PLATFORM,
        "safari_version": SAFARI_VERSION,
        "safari_webkit_version": SAFARI_WEBKIT_VERSION,
        "chrome_major": CHROME_MAJOR,
        "chrome_full_version": CHROME_FULL_VERSION,
        "user_agent": USER_AGENT,
        "send_client_hints": SEND_CLIENT_HINTS,
        "sec_ch_ua": SEC_CH_UA,
        "sec_ch_ua_platform": SEC_CH_UA_PLATFORM,
        "sec_ch_ua_platform_version": SEC_CH_UA_PLATFORM_VERSION,
        "sec_ch_ua_arch": SEC_CH_UA_ARCH,
        "sec_ch_ua_bitness": SEC_CH_UA_BITNESS,
        "sec_ch_ua_model": SEC_CH_UA_MODEL,
        "sec_ch_ua_full_version_list": SEC_CH_UA_FULL_VERSION_LIST,
        "sec_ch_ua_mobile": SEC_CH_UA_MOBILE,
        "navigator_proto_samples": list(NAVIGATOR_PROTO_SAMPLES),
        "document_key_samples": list(DOCUMENT_KEY_SAMPLES),
        "window_key_samples": list(WINDOW_KEY_SAMPLES),
        "script_src_samples": list(SCRIPT_SRC_SAMPLES),
        "window_feature_flags": dict(WINDOW_FEATURE_FLAGS),
        "build_id": __import__("config.openai_protocol", fromlist=["OPENAI_BUILD_ID"]).OPENAI_BUILD_ID,
    })
    # Fingerprint Sentinel VM và HTTP phải dùng cùng bộ hồ sơ screen/window/viewport/GPU.
    screen_width = int(profile.get("screen_width", 1680))
    screen_height = int(profile.get("screen_height", 1050))
    profile.setdefault("screen_avail_width", screen_width)
    profile.setdefault("screen_avail_height", max(0, screen_height - 25))
    profile.setdefault("color_depth", 24)
    profile.setdefault("outer_width", int(profile["screen_avail_width"]))
    profile.setdefault("outer_height", int(profile["screen_avail_height"]))
    profile.setdefault("viewport_width", int(profile["outer_width"]))
    profile.setdefault("viewport_height", max(0, int(profile["outer_height"]) - 87))
    cores = int(profile.get("hardware_concurrency", 8))
    chip = "Apple M2 Max" if cores >= 12 else "Apple M2 Pro" if cores >= 10 else "Apple M2"
    profile.setdefault("webgl_vendor", "Google Inc. (Apple)")
    profile.setdefault(
        "webgl_renderer",
        f"ANGLE (Apple, ANGLE Metal Renderer: {chip}, Unspecified Version)",
    )
    return profile


def pick_browser_profile(geo: dict | None = None) -> dict:
    """Chọn ngẫu nhiên một hồ sơ desktop ổn định cho một BrowserSession; kích thước HAR chỉ là một ứng viên."""
    return build_browser_environment(geo)


def validate_browser_profile(profile: dict) -> list[str]:
    """Trả các điểm mâu thuẫn trong hồ sơ, chủ yếu cho log/tự kiểm."""
    issues: list[str] = []
    ua = str(profile.get("user_agent") or "")
    family = str(profile.get("browser_family") or BROWSER_FAMILY)
    if family == "safari":
        if "Version/" not in ua or "Safari/" not in ua or "Chrome/" in ua or "Chromium/" in ua:
            issues.append("Safari UA không khớp")
        if profile.get("send_client_hints"):
            issues.append("Safari không được gửi Chromium Client Hints")
    elif f"Chrome/{profile.get('chrome_full_version')}" not in ua:
        issues.append("UA không khớp chrome_full_version")
    if profile.get("browser_os") == "macOS":
        if "Macintosh; Intel Mac OS X" not in ua:
            issues.append("Hồ sơ macOS nhưng UA không phải Macintosh")
        if str(profile.get("navigator_platform") or "") != "MacIntel":
            issues.append("Hồ sơ macOS nhưng navigator.platform không phải MacIntel")
        if "macOS" not in str(profile.get("sec_ch_ua_platform") or ""):
            issues.append("Hồ sơ macOS nhưng sec-ch-ua-platform không phải macOS")
    if not profile.get("navigator_language"):
        issues.append("navigator_language trống")
    languages = profile.get("navigator_languages") or []
    if profile.get("navigator_language") and profile.get("navigator_language") not in languages:
        issues.append("navigator.language không nằm trong navigator.languages")
    # Hồ sơ quyết định có lộ requestIdleCallback không.
    return issues

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'BROWSER_LOCALE_PROFILE': 'str', 'AUTO_BROWSER_LOCALE_FROM_IP': 'bool', 'IP_GEO_TIMEOUT': 'float', 'REJECT_CLOUD_PROXY': 'bool', 'BROWSER_DATA_SAVER_MODE': 'bool', 'BROWSER_DATA_SAVER_DEEP_MODE': 'bool', 'BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES': 'list_str_multiline', 'BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS': 'list_str_multiline', 'BROWSER_TRAFFIC_DETAIL_LOG': 'bool', 'BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES': 'int', 'BROWSER_JS_COVERAGE_LOG': 'bool', 'BROWSER_JS_COVERAGE_MAX_ENTRIES': 'int'})
