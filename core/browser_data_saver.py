# -*- coding: utf-8 -*-
"""浏览器注册流程的省流量资源拦截。

省流量模式只拦截 Roxy/Cloak 本地指纹浏览器中的可选页面资源和配置中明确指定的
URL，默认不拦截 document/核心 script/stylesheet/xhr/fetch/websocket，避免影响登录、
验证码和 session 写入。Playwright 可以按资源类型和 URL glob 精确拦截；Selenium/Roxy
通过 Chrome CDP 的 URL glob 拦截常见扩展名资源及配置的 URL。Browser Use/Skyvern
云端浏览器不安装本模块的拦截器。
"""
from __future__ import annotations

import logging
import threading
from collections import Counter
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

from config import browser as _cfg

logger = logging.getLogger(__name__)


# Enum Request.resource_type của Playwright. Ở đây giữ các loại thường dùng, giá trị lạ sẽ không khiến
# Quy trình đăng ký thất bại; người dùng có thể điền nhiều giá trị trong cấu hình, mỗi dòng một cái.
_RESOURCE_TYPE_ALIASES = {
    "images": "image",
    "img": "image",
    "videos": "media",
    "video": "media",
    "audio": "media",
    "fonts": "font",
    "tracks": "texttrack",
    "track": "texttrack",
}
_KNOWN_RESOURCE_TYPES = {
    "document",
    "stylesheet",
    "image",
    "media",
    "font",
    "script",
    "texttrack",
    "xhr",
    "fetch",
    "eventsource",
    "websocket",
    "manifest",
    "other",
}

# Selenium/CDP không expose bộ lọc resourceType qua Network.setBlockedURLs, chỉ có thể theo
# Lọc URL glob. Vì vậy chỉ liệt kê các hậu tố tài nguyên tĩnh phổ biến, không chặn cả domain third-party.
_URL_EXTENSIONS_BY_TYPE = {
    "image": (
        ".apng", ".avif", ".bmp", ".gif", ".ico", ".jfif", ".jpeg", ".jpg",
        ".png", ".svg", ".webp",
    ),
    "media": (
        ".3gp", ".avi", ".flac", ".m4a", ".m4v", ".mkv", ".mov", ".mp3",
        ".mp4", ".mpeg", ".ogg", ".wav", ".webm",
    ),
    "font": (".eot", ".otf", ".ttf", ".woff", ".woff2"),
    "manifest": (".webmanifest", "/manifest.json"),
    "texttrack": (".vtt", ".srt"),
    # Các loại dưới đây không phải giá trị mặc định, nhưng cho phép cấu hình nâng cao dùng; trước khi bật nên xác nhận trang không phụ thuộc chúng.
    "stylesheet": (".css",),
    "script": (".js", ".mjs"),
}

# Kiểm soát rủi ro đăng nhập/thách thức xác minh có thể đánh dấu ảnh captcha, tài nguyên challenge là image. Định tuyến Playwright
# Có thể cho phép ngoại lệ các resource này theo URL; blacklist URL của Selenium/CDP không có quy tắc ngoại lệ, chỉ có thể dựa vào
# Loại tài nguyên này thường không dùng hậu tố tĩnh phổ biến, gặp bất thường captcha nên tắt chế độ để kiểm tra.
_CHALLENGE_KEYWORDS = (
    "captcha", "challenge", "arkose", "hcaptcha", "recaptcha", "turnstile",
    "verification", "verify",
)


def _as_items(value: Any, *, lower: bool = True) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.replace(",", "\n").splitlines()
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = [value]
    result = [str(item or "").strip() for item in raw if str(item or "").strip()]
    return [item.lower() for item in result] if lower else result


def configured_resource_types() -> list[str]:
    """Đọc và chuẩn hóa loại chặn tiết kiệm lưu lượng; loại không hợp lệ sẽ bị bỏ qua."""
    raw = getattr(_cfg, "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", ("image", "media"))
    result: list[str] = []
    for item in _as_items(raw, lower=True):
        item = _RESOURCE_TYPE_ALIASES.get(item, item)
        if item in _KNOWN_RESOURCE_TYPES and item not in result:
            result.append(item)
    return result


def configured_url_patterns() -> list[str]:
    """Đọc và chuẩn hóa quy tắc URL glob bổ sung; bỏ mục rỗng, khử trùng, giữ thứ tự cấu hình."""
    raw = getattr(_cfg, "BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", ())
    result: list[str] = []
    # URL path có thể phân biệt hoa thường, không thể chuyển thống nhất sang chữ thường như resource_type.
    for item in _as_items(raw, lower=False):
        if item not in result:
            result.append(item)
    return result


def _is_challenge_url(url: str) -> bool:
    lower = str(url or "").lower()
    return any(keyword in lower for keyword in _CHALLENGE_KEYWORDS)


def _infer_resource_type(url: str) -> str:
    """Khi sự kiện CDP của Selenium thiếu type, suy luận thận trọng theo hậu tố URL."""
    try:
        path = urlsplit(str(url or "")).path.lower()
    except Exception:
        path = str(url or "").lower().split("?", 1)[0].split("#", 1)[0]
    for resource_type, extensions in _URL_EXTENSIONS_BY_TYPE.items():
        if any(path.endswith(extension) for extension in extensions):
            return resource_type
    return "other"


class BrowserDataSaver:
    """Cài đặt bộ chặn tài nguyên tùy chọn cho một phiên trình duyệt."""

    def __init__(self, *, label: str = "Browser"):
        self.label = str(label or "Browser")
        self.enabled = bool(getattr(_cfg, "BROWSER_DATA_SAVER_MODE", False))
        self.resource_types = configured_resource_types() if self.enabled else []
        self.url_patterns = configured_url_patterns() if self.enabled else []
        self.blocked_count = 0
        self.blocked_by_type: Counter[str] = Counter()
        self.blocked_by_url_pattern: Counter[str] = Counter()
        self._lock = threading.RLock()
        self._context: Any | None = None
        self._driver: Any | None = None
        self._route_handler: Any | None = None
        self._blocked_playwright_requests: set[int] = set()
        self._selenium_patterns: list[str] = []
        self._installed = False
        self._stopped = False
        self.method = "disabled"

    def _matching_url_pattern(self, url: str) -> str | None:
        """Trả về URL glob khớp đầu tiên; khớp quy tắc phân biệt hoa thường theo nguyên văn URL."""
        text = str(url or "")
        if not text:
            return None
        for pattern in self.url_patterns:
            try:
                if fnmatchcase(text, pattern):
                    return pattern
            except Exception:
                continue
        return None

    def _should_block(self, resource_type: str, url: str) -> bool:
        if not self.enabled or self._stopped:
            return False
        resource_type = _RESOURCE_TYPE_ALIASES.get(str(resource_type or "").lower(), str(resource_type or "").lower())
        matched_url_pattern = self._matching_url_pattern(url)
        if resource_type not in self.resource_types and matched_url_pattern is None:
            return False
        # Tài nguyên thách thức xác minh được cho qua ưu tiên; ảnh/media trang thường vẫn bị chặn.
        if _is_challenge_url(url):
            return False
        return True

    def _record_blocked(
        self,
        resource_type: str,
        *,
        request: Any | None = None,
        url_pattern: str | None = None,
    ) -> None:
        normalized = _RESOURCE_TYPE_ALIASES.get(str(resource_type or "other").lower(), str(resource_type or "other").lower())
        with self._lock:
            self.blocked_count += 1
            self.blocked_by_type[normalized or "other"] += 1
            if url_pattern:
                self.blocked_by_url_pattern[str(url_pattern)] += 1
            if request is not None:
                self._blocked_playwright_requests.add(id(request))

    def was_playwright_blocked(self, request: Any) -> bool:
        """Để bộ đếm lưu lượng Playwright loại trừ các byte tải lên giả do route.abort() tạo ra."""
        with self._lock:
            key = id(request)
            if key not in self._blocked_playwright_requests:
                return False
            self._blocked_playwright_requests.remove(key)
            return True

    def install_playwright(self, context: Any) -> "BrowserDataSaver":
        """Chặn yêu cầu trên BrowserContext theo resource_type."""
        if not self.enabled:
            return self
        if not self.resource_types and not self.url_patterns:
            logger.info("[%s] chế độ tiết lưu lượng đã bật nhưng chưa cấu hình loại tài nguyên chặn được hoặc rule URL", self.label)
            return self
        try:
            def _handle_route(route: Any) -> None:
                try:
                    request = route.request
                    resource_type = getattr(request, "resource_type", "")
                    url = getattr(request, "url", "")
                    if self._should_block(resource_type, url):
                        self._record_blocked(
                            resource_type,
                            request=request,
                            url_pattern=self._matching_url_pattern(url),
                        )
                        try:
                            route.abort("blockedbyclient")
                        except TypeError:
                            # Tương thích chữ ký Playwright route.abort() cực cũ.
                            route.abort()
                        return
                    route.continue_()
                except Exception as exc:
                    # Interceptor không được chặn quy trình đăng ký chính; khi xử lý ngoại lệ cố gắng cho request đi qua.
                    logger.debug("[%s] xử lý route tiết lưu lượng thất bại, thử cho qua：%s", self.label, exc)
                    try:
                        route.continue_()
                    except Exception:
                        pass

            context.route("**/*", _handle_route)
            self._context = context
            self._route_handler = _handle_route
            self._installed = True
            self.method = "playwright.context.route"
            logger.info(
                "[%s] chế độ tiết lưu lượng đã bật：loại tài nguyên chặn=%s，rule URL=%s（URL liên quan mã OTP/challenge được cho qua）",
                self.label,
                ",".join(self.resource_types) or "-",
                len(self.url_patterns),
            )
        except Exception as exc:
            logger.warning("[%s] cài chặn tiết lưu lượng Playwright thất bại, tiếp tục không chặn：%s: %s", self.label, type(exc).__name__, exc)
        return self

    def install_selenium(self, driver: Any) -> "BrowserDataSaver":
        """Cài đặt chặn hậu tố URL và URL glob qua Chrome CDP Network.setBlockedURLs."""
        if not self.enabled:
            return self
        patterns: list[str] = []
        for resource_type in self.resource_types:
            for extension in _URL_EXTENSIONS_BY_TYPE.get(resource_type, ()):
                # Bỏ scheme/host, khớp URL tài nguyên cùng loại có query/hash.
                patterns.append(f"*{extension}*")
        # URL matcher của CDP dùng * làm wildcard; chuyển ** trong quy tắc Playwright
        # Thu hẹp thành một * duy nhất, là có thể tương thích khớp CDP cho URL xuyên đường dẫn.
        patterns.extend(pattern.replace("**", "*") for pattern in self.url_patterns)
        # Loại trùng và giữ thứ tự cấu hình/phần mở rộng, thuận tiện cho log và kiểm thử ổn định.
        patterns = list(dict.fromkeys(patterns))
        if not patterns:
            logger.info("[%s] chế độ tiết lưu lượng đã bật nhưng Selenium không có rule URL dùng được", self.label)
            return self
        try:
            # Trong một số trường hợp bộ đếm lưu lượng không khởi tạo thành công, vẫn cần bật riêng miền Network.
            try:
                driver.execute_cdp_cmd("Network.enable", {})
            except Exception:
                pass
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": patterns})
            self._driver = driver
            self._selenium_patterns = patterns
            self._installed = True
            self.method = "selenium.cdp.Network.setBlockedURLs"
            logger.info(
                "[%s] chế độ tiết lưu lượng đã bật：chặn loại tài nguyên theo URL=%s，rule loại=%s mục，rule URL=%s mục（rule URL Selenium không hỗ trợ ngoại lệ challenge）",
                self.label,
                ",".join(self.resource_types) or "-",
                sum(len(_URL_EXTENSIONS_BY_TYPE.get(resource_type, ())) for resource_type in self.resource_types),
                len(self.url_patterns),
            )
        except Exception as exc:
            logger.warning("[%s] cài chặn tiết lưu lượng Selenium thất bại, tiếp tục không chặn：%s: %s", self.label, type(exc).__name__, exc)
        return self

    def enable_post_auth_deep_mode(self, driver: Any) -> bool:
        """Sau khi đăng ký xong, thắt chặt quy tắc, chặn các request shell ứng dụng và telemetry không còn cần thiết."""
        if not self.enabled or not bool(getattr(_cfg, "BROWSER_DATA_SAVER_DEEP_MODE", True)):
            return False
        patterns = [
            "*://chatgpt.com/_next/*", "*://www.chatgpt.com/_next/*",
            "*://chatgpt.com/cdn/assets/*", "*://www.chatgpt.com/cdn/assets/*",
            "*://chatgpt.com/unauth-mweb/*", "*://www.chatgpt.com/unauth-mweb/*",
            "*://oaistatic.com/*", "*://*.oaistatic.com/*",
            "*://chatgpt.com/ces/*", "*://www.chatgpt.com/ces/*",
            "*://auth.openai.com/awe/api/v2/rum*", "*://chatgpt.com/awe/api/v2/rum*",
        ]
        patterns = list(dict.fromkeys(self._selenium_patterns + patterns))
        try:
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": patterns})
            self._selenium_patterns = patterns
            logger.info("[%s] đã bật tiết lưu lượng sâu sau đăng ký：rule shell app/telemetry=%s mục", self.label, len(patterns))
            return True
        except Exception as exc:
            logger.warning("[%s] cài tiết lưu lượng sâu sau đăng ký thất bại, tiếp tục online：%s", self.label, str(exc)[:180])
            return False

    def observe_cdp_event(self, method: str, params: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        """Để bộ đếm lưu lượng Selenium nhận diện sự kiện chặn của CDP inspector.

        Trả về True nghĩa là đây là request bị quy tắc lưu lượng này chặn; bộ đếm nên bỏ qua ước lượng header của nó,
        vì request thực tế không được gửi ra mạng.
        """
        if not self.enabled or method != "Network.loadingFailed":
            return False
        if str(params.get("blockedReason") or "").lower() != "inspector":
            return False
        request = request or {}
        url = str(request.get("url") or "")
        resource_type = str(request.get("resourceType") or "").strip().lower() or _infer_resource_type(url)
        resource_type = _RESOURCE_TYPE_ALIASES.get(resource_type, resource_type)
        if self._selenium_patterns:
            if not url or not any(fnmatchcase(url, pattern) for pattern in self._selenium_patterns):
                return False
        # Giữ tương thích sự kiện loại tài nguyên khi chưa gọi install_selenium(); sau khi cài đặt thành công bình thường
        # Luôn có quy tắc URL, đi nhánh chính xác ở trên.
        elif resource_type not in self.resource_types:
            return False
        self._record_blocked(resource_type, url_pattern=self._matching_url_pattern(url))
        return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "data_saver_enabled": bool(self.enabled),
                "data_saver_method": self.method,
                "data_saver_blocked_resource_types": list(self.resource_types),
                "data_saver_blocked_url_patterns": list(self.url_patterns),
                "data_saver_blocked_count": int(self.blocked_count),
                "data_saver_blocked_by_type": dict(sorted(self.blocked_by_type.items())),
                "data_saver_blocked_by_url_pattern": dict(sorted(self.blocked_by_url_pattern.items())),
            }

    def stop(self) -> None:
        """Gỡ bỏ định tuyến Playwright; quy tắc URL CDP kết thúc cùng phiên trình duyệt."""
        if self._stopped:
            return
        self._stopped = True
        if self._context is not None and self._route_handler is not None:
            try:
                self._context.unroute("**/*", self._route_handler)
            except Exception:
                pass
        self._route_handler = None
        self._context = None
        self._driver = None
        self._blocked_playwright_requests.clear()


__all__ = ["BrowserDataSaver", "configured_resource_types", "configured_url_patterns"]
