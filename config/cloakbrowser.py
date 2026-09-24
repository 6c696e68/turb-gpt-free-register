# -*- coding: utf-8 -*-
"""Cấu hình đăng ký tự động CloakBrowser."""
from config.env_loader import apply_env_overrides

# Headless: False=hiện cửa sổ, True=headless.
CLOAK_HEADLESS: bool = True

# Có bật hành vi humanize CloakBrowser không.
CLOAK_HUMANIZE: bool = True

# Tự khớp múi giờ/ngôn ngữ/WebRTC IP theo IP đầu ra hiện tại.
CLOAK_GEOIP: bool = True

# Chỉ định ngôn ngữ/múi giờ Cloak; để trống thì khi CLOAK_GEOIP=True suy theo IP đầu ra.
# Ví dụ: CLOAK_LOCALE="ja-JP", CLOAK_TIMEZONE="Asia/Tokyo".
CLOAK_LOCALE: str = ""
CLOAK_TIMEZONE: str = ""

# Có truyền proxy của project / proxy rút từ kho sang CloakBrowser không.
CLOAK_USE_PROXY: bool = True

# Pro license; để trống dùng binary miễn phí.
CLOAK_LICENSE_KEY: str = ""

# Fingerprint seed cố định; để trống thì mỗi lần launch sinh fingerprint mới.
CLOAK_FINGERPRINT_SEED: str = ""

# Thư mục user bền; để trống thì context tạm. Muốn cố định hồ sơ/cache tài khoản, điền ví dụ "./cloak-profiles/default".
CLOAK_USER_DATA_DIR: str = ""

# Tham số Chromium thêm, ví dụ ["--fingerprint=12345"]. CLOAK_FINGERPRINT_SEED được nối tự động.
CLOAK_EXTRA_ARGS: list = []

# Timeout dùng chung với luồng Selenium Roxy gốc.
CLOAK_SELENIUM_TIMEOUT: int = 90

# Khi debug giữ trình duyệt, không tự đóng.
CLOAK_KEEP_BROWSER_OPEN: bool = False

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'CLOAK_HEADLESS': 'bool', 'CLOAK_HUMANIZE': 'bool', 'CLOAK_GEOIP': 'bool', 'CLOAK_LOCALE': 'str', 'CLOAK_TIMEZONE': 'str', 'CLOAK_USE_PROXY': 'bool', 'CLOAK_LICENSE_KEY': 'str', 'CLOAK_FINGERPRINT_SEED': 'str', 'CLOAK_USER_DATA_DIR': 'str', 'CLOAK_SELENIUM_TIMEOUT': 'int', 'CLOAK_KEEP_BROWSER_OPEN': 'bool'})
