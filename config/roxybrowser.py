# -*- coding: utf-8 -*-
"""
Cấu hình đăng ký tự động bằng trình duyệt fingerprint RoxyBrowser.

Tài liệu chính thức:
- API host mặc định: http://127.0.0.1:50000
- Mọi API phải có header token
- Kết hợp được Selenium / Puppeteer / Playwright
"""
from config.env_loader import env_str, apply_env_overrides


# Driver đăng ký:
#   "protocol"     = đăng ký thuần giao thức curl_cffi gốc (dễ bị khoá, không nên)
#   "roxy"         = RoxyBrowser fingerprint + Selenium
#   "cloak"        = CloakBrowser + lớp thích ứng Playwright/Selenium
#   "browser_use"  = Browser Use Cloud stealth Chromium + Playwright
#   "skyvern"      = Skyvern Browser Sessions + Playwright
REGISTRATION_DRIVER: str = "roxy"

# API local RoxyBrowser
ROXY_API_BASE: str = "http://127.0.0.1:50100"
ROXY_API_TOKEN: str = env_str("ROXY_API_TOKEN", "")

# Roxy profile/môi trường ID; để trống thì dùng ROXY_PROFILE_CREATE_* tạo môi trường tạm trước (nếu API hỗ trợ)
ROXY_PROFILE_ID: str = ""

# Roxy workspace ID. API tạo Profile bắt buộc workspaceId.
# Xem trên trang workspace/team Roxy hoặc trong phản hồi API.
ROXY_WORKSPACE_ID: str = "90143"

# Roxy project ID. /browser/workspace trả project_details.projectId; gửi kèm khi tạo Profile.
ROXY_PROJECT_ID: str = "97471"

# Path API danh sách team/workspace. Bản khác thì sửa trên WebUI; client cũng tự thử vài path thường gặp.
ROXY_WORKSPACE_LIST_PATH: str = "/browser/workspace"
ROXY_WORKSPACE_LIST_METHOD: str = "GET"

# Template path API. Bản khác thì chỉ sửa ở đây.
# {profile_id} được thay bằng ROXY_PROFILE_ID.
ROXY_OPEN_PATH: str = "/browser/open"
ROXY_CLOSE_PATH: str = "/browser/close"
ROXY_CREATE_PATH: str = "/browser/create"

# Method API: open/close thường là GET; bản của bạn bắt POST thì sửa trên WebUI/cấu hình.
ROXY_OPEN_METHOD: str = "POST"
ROXY_CLOSE_METHOD: str = "POST"
ROXY_CREATE_METHOD: str = "POST"

# Có mở trình duyệt headless không:
#   False = hiện cửa sổ Roxy (dễ quan sát/debug)
#   True  = headless, không hiện cửa sổ (nếu bản Roxy hỗ trợ headless)
ROXY_OPEN_HEADLESS: bool = False

# Tham số thêm khi mở trình duyệt; gộp vào body /browser/open, ưu tiên hơn mặc định.
ROXY_OPEN_EXTRA_PARAMS: dict = {}

# Hành vi Selenium
ROXY_SELENIUM_TIMEOUT: int = 90
ROXY_KEEP_BROWSER_OPEN: bool = False

# Cache tài nguyên tĩnh local xuyên Profile Roxy (chỉ cache JS/CSS/font/image, auth/API luôn ra mạng).
# Bật config.browser.BROWSER_DATA_SAVER_MODE thì tự bật, không cần sửa công tắc này riêng.
ROXY_LOCAL_ASSET_CACHE_ENABLED: bool = False
ROXY_LOCAL_ASSET_CACHE_MODE: str = "auto"
ROXY_LOCAL_ASSET_CACHE_DIR: str = "./cache/roxy-assets"
ROXY_LOCAL_ASSET_CACHE_MAX_AGE: int = 86400
ROXY_LOCAL_ASSET_CACHE_MAX_ITEM_BYTES: int = 25 * 1024 * 1024

# Thử lại lỗi transient Roxy API. create mặc định không thử lại, tránh timeout rồi tạo môi trường mồ côi; open/close/delete có thử lại.
ROXY_API_RETRIES: int = 3
ROXY_API_RETRY_DELAY: int = 2
ROXY_CREATE_RETRIES: int = 3
ROXY_CREATE_RETRY_DELAY: int = 3

# Khi đăng ký đa luồng, khoảng khởi đầu chung của mọi worker cho /browser/create (giây).
# Roxy có thể trả "đang tạo" khi môi trường trước chưa tạo xong; mặc định lệch 1.5 giây.
ROXY_CREATE_INTERVAL: float = 1.5

# Vòng đời môi trường:
#   True  = một tài khoản một profile: mỗi tài khoản buộc tạo Profile mới, dùng xong đóng và xoá, không tái dùng ROXY_PROFILE_ID
#   False = được tái dùng ROXY_PROFILE_ID hoặc chỉ đóng không xoá
ROXY_ONE_PROFILE_PER_ACCOUNT: bool = True

# Sau một tài khoản một profile có xoá Profile không. Nên giữ True.
ROXY_DELETE_PROFILE_AFTER_RUN: bool = True

# Path/method API xoá môi trường; bản Roxy khác thì chỉ sửa ở đây.
ROXY_DELETE_PATH: str = "/browser/delete"
ROXY_DELETE_METHOD: str = "POST"

# Fingerprint OS ngẫu nhiên khi tạo môi trường Roxy; bật thì mỗi /browser/create chọn ngẫu nhiên Windows / macOS,
# tránh fingerprint macOS cố định.
ROXY_RANDOM_OS_ON_CREATE: bool = True
ROXY_RANDOM_OS_CHOICES: str = "Windows,macOS"

# Tên ngẫu nhiên khi tạo môi trường Roxy; bật thì ghi đè name cố định trong ROXY_PROFILE_CREATE_PAYLOAD.
ROXY_RANDOM_PROFILE_NAME_ON_CREATE: bool = True
ROXY_PROFILE_NAME_PREFIX: str = "rb"

# Fingerprint OS mặc định khi tạo môi trường Roxy. Chỉ dùng khi ROXY_RANDOM_OS_ON_CREATE=False.
# Enum os chính thức Roxy: Windows / macOS / Linux / IOS / Android.
ROXY_DEFAULT_OS: str = "macOS"
# Để trống thì dùng phiên bản mặc định/cao nhất của OS Roxy; muốn cố định thì điền 15.3.2, 14.7, v.v.
ROXY_DEFAULT_OS_VERSION: str = ""

# Khi tạo môi trường Roxy có dùng PROXY_POOL trong config/proxy.py không:
#   False = không chủ động đặt proxy cho môi trường Roxy
#   True  = mỗi lần tạo môi trường rút ngẫu nhiên một proxy từ PROXY_POOL ghi vào proxyInfo
ROXY_CREATE_USE_PROXY_POOL: bool = False

# Kênh kiểm tra proxy Roxy; để trống thì không truyền checkChannel.
ROXY_PROXY_CHECK_CHANNEL: str = "IPRust.io"

# Payload tối thiểu tạo môi trường khi không có ROXY_PROFILE_ID; chỉnh field theo bản Roxy.
# ROXY_RANDOM_PROFILE_NAME_ON_CREATE mặc định bật, nên name ở đây chỉ là giá trị dự phòng.
ROXY_PROFILE_CREATE_PAYLOAD: dict = {
    "name": "gpt-free-register",
    "os": "macOS",
}


# Số giây tối đa chờ callback uỷ quyền Codex trên Roxy
ROXY_CODEX_CALLBACK_TIMEOUT: int = 180

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'REGISTRATION_DRIVER': 'str', 'ROXY_API_BASE': 'str', 'ROXY_API_TOKEN': 'str', 'ROXY_PROFILE_ID': 'str', 'ROXY_WORKSPACE_ID': 'str', 'ROXY_PROJECT_ID': 'str', 'ROXY_WORKSPACE_LIST_PATH': 'str', 'ROXY_OPEN_PATH': 'str', 'ROXY_OPEN_HEADLESS': 'bool', 'ROXY_CLOSE_PATH': 'str', 'ROXY_KEEP_BROWSER_OPEN': 'bool', 'ROXY_API_RETRIES': 'int', 'ROXY_API_RETRY_DELAY': 'int', 'ROXY_CREATE_RETRIES': 'int', 'ROXY_CREATE_RETRY_DELAY': 'int', 'ROXY_LOCAL_ASSET_CACHE_ENABLED': 'bool', 'ROXY_LOCAL_ASSET_CACHE_MODE': 'str', 'ROXY_LOCAL_ASSET_CACHE_DIR': 'str', 'ROXY_LOCAL_ASSET_CACHE_MAX_AGE': 'int', 'ROXY_LOCAL_ASSET_CACHE_MAX_ITEM_BYTES': 'int', 'ROXY_ONE_PROFILE_PER_ACCOUNT': 'bool', 'ROXY_DELETE_PROFILE_AFTER_RUN': 'bool', 'ROXY_RANDOM_OS_ON_CREATE': 'bool', 'ROXY_RANDOM_OS_CHOICES': 'str', 'ROXY_RANDOM_PROFILE_NAME_ON_CREATE': 'bool', 'ROXY_PROFILE_NAME_PREFIX': 'str', 'ROXY_CREATE_USE_PROXY_POOL': 'bool', 'ROXY_PROXY_CHECK_CHANNEL': 'str', 'ROXY_DELETE_PATH': 'str', 'ROXY_CODEX_CALLBACK_TIMEOUT': 'int', 'ROXY_CREATE_INTERVAL': 'float'})
