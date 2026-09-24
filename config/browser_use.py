# -*- coding: utf-8 -*-
"""
Cấu hình Browser Use Cloud.

Tài liệu:
- https://docs.browser-use.com/cloud/browser/stealth
- https://docs.browser-use.com/cloud/browser/playwright-puppeteer-selenium

Cách dùng:
  1. Trong config/roxybrowser.py đặt REGISTRATION_DRIVER = "browser_use"
  2. Điền BROWSER_USE_API_KEY trong .env (cũng ghi được qua field khoá WebUI)
  3. Nên tắt Codex trước: ENABLE_CODEX_AUTO = False
"""
from config.env_loader import env_str, apply_env_overrides

# Browser Use API Key (tạo ở Cloud Dashboard; ưu tiên đọc .env / biến môi trường)
BROWSER_USE_API_KEY: str = env_str("BROWSER_USE_API_KEY", "")

# Cách kết nối:
#   "cdp_url" = dùng thẳng CDP websocket chính thức (nên dùng, đơn giản nhất)
#   "sdk"     = gọi REST tạo session trước (dự phòng; mặc định vẫn cdp_url)
BROWSER_USE_CONNECT_MODE: str = "cdp_url"

# Template địa chỉ kết nối CDP. {api_key}/{proxy_country_code}/{profile_id} được thay hoặc nối query khi cần.
BROWSER_USE_CDP_BASE: str = "wss://connect.browser-use.com"

# Gốc REST API tuỳ chọn (dùng sau nếu chuyển sang create/stop session tường minh)
BROWSER_USE_API_BASE: str = "https://api.browser-use.com/api/v2"

# Mã quốc gia proxy, 2 chữ thường, ví dụ jp / us / sg / de; để trống thì dùng đầu ra mặc định Browser Use
BROWSER_USE_PROXY_COUNTRY_CODE: str = "jp"

# Có dùng proxy tích hợp Browser Use không. False thì cố không ép cloud proxy (vẫn phụ thuộc mặc định server)
BROWSER_USE_USE_PROXY: bool = True

# Tuỳ chọn: cố định profileId Browser Use để tái dùng cookies/localStorage.
# Đăng ký hàng loạt cá nhân nên để trống, mỗi phiên mới sạch hơn.
BROWSER_USE_PROFILE_ID: str = ""

# Timeout Playwright / trang
BROWSER_USE_TIMEOUT: int = 90
BROWSER_USE_NAVIGATION_TIMEOUT: int = 90

# keepAlive / thời gian sống phiên trình duyệt cloud Browser Use (phút).
# Truyền làm tham số timeout của connect URL, để trình duyệt remote còn sống khi chờ OTP, SMS, callback.
# Timeout Browser Use hiện tính bằng phút, trần chính thức thường 240; code clamp về 1~240.
BROWSER_USE_SESSION_TIMEOUT: int = 240

# Chế độ nhanh: giảm human_delay thêm và chờ dài trong luồng Browser Use; mặc định bật.
BROWSER_USE_FAST_MODE: bool = True

# Log thời gian pha: in thời gian connect/goto/email/otp/phone/callback, để tìm chỗ chậm.
BROWSER_USE_LOG_TIMING: bool = True

# Thời gian xử lý tối đa trang hồ sơ; quá hạn không kẹt nữa, thử đọc accessToken từ /api/auth/session.
BROWSER_USE_PROFILE_TIMEOUT: int = 28
SKYVERN_PROFILE_TIMEOUT: int = 45

# Thời gian chờ tối đa đọc accessToken sau khi trang hồ sơ xong/timeout; không lấy được thì tác vụ thất bại.
BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT: int = 18
SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT: int = 35

# Sau tác vụ có chủ động ngắt CDP không
BROWSER_USE_KEEP_BROWSER_OPEN: bool = False

# Tham số query CDP thêm, gộp vào connect URL; field trùng tên ghi đè BROWSER_USE_SESSION_TIMEOUT phía trên.
# Ví dụ: {"timeout": "120"}  # đơn vị phút
BROWSER_USE_EXTRA_QUERY: dict = {}

# Trang đăng ký mở đầu
BROWSER_USE_START_URL: str = "https://chatgpt.com/auth/login"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'BROWSER_USE_API_KEY': 'str', 'BROWSER_USE_PROXY_COUNTRY_CODE': 'str', 'BROWSER_USE_USE_PROXY': 'bool', 'BROWSER_USE_PROFILE_ID': 'str', 'BROWSER_USE_CDP_BASE': 'str', 'BROWSER_USE_TIMEOUT': 'int', 'BROWSER_USE_SESSION_TIMEOUT': 'int', 'BROWSER_USE_FAST_MODE': 'bool', 'BROWSER_USE_LOG_TIMING': 'bool', 'BROWSER_USE_PROFILE_TIMEOUT': 'int', 'SKYVERN_PROFILE_TIMEOUT': 'int', 'BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT': 'int', 'SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT': 'int', 'BROWSER_USE_KEEP_BROWSER_OPEN': 'bool', 'BROWSER_USE_START_URL': 'str'})
