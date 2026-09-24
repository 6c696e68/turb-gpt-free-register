# -*- coding: utf-8 -*-
"""Cấu hình trình duyệt cloud Skyvern."""
from config.env_loader import env_str, apply_env_overrides

# Skyvern API Key (tạo ở Skyvern Cloud Dashboard; ưu tiên đọc .env / biến môi trường)
SKYVERN_API_KEY: str = env_str("SKYVERN_API_KEY", "")

# Gốc Skyvern API. Cloud mặc định: https://api.skyvern.com
SKYVERN_API_BASE: str = "https://api.skyvern.com"

# Tham số tạo Browser Session
SKYVERN_BROWSER_SESSION_TIMEOUT: int = 60  # phút
SKYVERN_BROWSER_PROFILE_ID: str = ""
SKYVERN_PROXY_LOCATION: str = ""  # Tuỳ chọn: jp tự thành RESIDENTIAL_JP; để trống thì không truyền
SKYVERN_GENERATE_BROWSER_PROFILE: bool = False
SKYVERN_AD_BLOCKER: bool = True
SKYVERN_BROWSER_TYPE: str = "stealth-chromium"

# Timeout Playwright / trang; để trống thì luồng thực tế vẫn dùng timeout mặc định trong cấu hình Browser Use
SKYVERN_KEEP_BROWSER_OPEN: bool = False

# Khi đăng ký tay Skyvern ít bị khoá, tự động mặc định bám "thao tác tay":
# - không đi fast mode của Browser Use;
# - không ghi đè thêm UA/ngôn ngữ/múi giờ/Client Hints;
# - giữ gõ từng ký tự chậm, dừng trước click, dừng sau submit.
SKYVERN_HUMAN_MODE: bool = True

# Trang đăng ký mở đầu
SKYVERN_START_URL: str = "https://chatgpt.com/auth/login"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'SKYVERN_API_KEY': 'str',
    'SKYVERN_API_BASE': 'str',
    'SKYVERN_BROWSER_SESSION_TIMEOUT': 'int',
    'SKYVERN_BROWSER_PROFILE_ID': 'str',
    'SKYVERN_PROXY_LOCATION': 'str',
    'SKYVERN_GENERATE_BROWSER_PROFILE': 'bool',
    'SKYVERN_AD_BLOCKER': 'bool',
    'SKYVERN_BROWSER_TYPE': 'str',
    'SKYVERN_KEEP_BROWSER_OPEN': 'bool',
    'SKYVERN_HUMAN_MODE': 'bool',
    'SKYVERN_START_URL': 'str',
})
