# -*- coding: utf-8 -*-
"""Client Browser Use Cloud: dựng kết nối CDP và quản lý vòng đời Playwright."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from config import browser_use as _cfg

logger = logging.getLogger(__name__)


@dataclass
class BrowserUseSession:
    connect_url: str
    api_key_present: bool
    proxy_country_code: str = ""
    profile_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class BrowserUseClient:
    """Client tối giản: mặc định dùng websocket connect_over_cdp chính thức."""

    def __init__(self, api_key: str | None = None):
        self.api_key = (api_key if api_key is not None else getattr(_cfg, "BROWSER_USE_API_KEY", "") or "").strip()

    def require_api_key(self) -> str:
        if not self.api_key:
            raise RuntimeError(
                "BROWSER_USE_API_KEY đang trống. Hãy tạo API Key trên Browser Use Cloud, "
                "và điền trong config/browser_use.py hoặc trang cấu hình WebUI."
            )
        return self.api_key

    def build_connect_url(self) -> BrowserUseSession:
        api_key = self.require_api_key()
        base = str(getattr(_cfg, "BROWSER_USE_CDP_BASE", "wss://connect.browser-use.com") or "wss://connect.browser-use.com").rstrip("?&")
        query: dict[str, str] = {"apiKey": api_key}

        proxy_country = str(getattr(_cfg, "BROWSER_USE_PROXY_COUNTRY_CODE", "") or "").strip().lower()
        use_proxy = bool(getattr(_cfg, "BROWSER_USE_USE_PROXY", True))
        if use_proxy and proxy_country:
            query["proxyCountryCode"] = proxy_country

        profile_id = str(getattr(_cfg, "BROWSER_USE_PROFILE_ID", "") or "").strip()
        if profile_id:
            query["profileId"] = profile_id

        session_timeout = int(getattr(_cfg, "BROWSER_USE_SESSION_TIMEOUT", 240) or 240)
        if session_timeout > 0:
            # timeout của Browser Use Cloud connect URL là keepAlive/thời gian sống phiên, đơn vị phút.
            # Server sẽ validate giới hạn trên; vượt sẽ trả HTTP 422 ở giai đoạn kết nối CDP. Ở đây kẹp thống nhất về 1~240 phút.
            query["timeout"] = str(max(1, min(240, session_timeout)))

        extra = dict(getattr(_cfg, "BROWSER_USE_EXTRA_QUERY", {}) or {})
        for key, value in extra.items():
            if value is None:
                continue
            text = str(value).strip()
            if text:
                query[str(key)] = text

        connect_url = f"{base}?{urlencode(query)}"
        # Không in đầy đủ apiKey trong log
        safe_query = dict(query)
        if "apiKey" in safe_query:
            safe_query["apiKey"] = safe_query["apiKey"][:6] + "***"
        logger.info(
            "[BrowserUse] CDP connect params: base=%s proxyCountry=%s profileId=%s use_proxy=%s timeout=%s",
            base,
            proxy_country or "-",
            profile_id or "-",
            use_proxy,
            query.get("timeout") or "-",
        )
        logger.debug("[BrowserUse] CDP safe query=%s", safe_query)
        return BrowserUseSession(
            connect_url=connect_url,
            api_key_present=True,
            proxy_country_code=proxy_country,
            profile_id=profile_id,
            raw={"query": safe_query, "base": base},
        )

    def open_session(self) -> BrowserUseSession:
        mode = str(getattr(_cfg, "BROWSER_USE_CONNECT_MODE", "cdp_url") or "cdp_url").strip().lower()
        if mode not in ("cdp_url", "cdp", "websocket", "ws", "sdk"):
            raise RuntimeError(f"Không hỗ trợ BROWSER_USE_CONNECT_MODE={mode!r}, Hiện hỗ trợ cdp_url")
        # Hiện tại cách kết nối công khai ổn định nhất chính thức của Browser Use là CDP websocket.
        # Nếu API sdk/rest create-session ổn định về sau, có thể mở rộng tại đây.
        return self.build_connect_url()
