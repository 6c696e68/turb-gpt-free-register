# -*- coding: utf-8 -*-
"""
Cấu hình tự chạy uỷ quyền Codex OAuth sau đăng ký thành công.
ENABLE_CODEX = False thì bỏ hẳn bước này.

Nguồn tham số: source CLIProxyAPI internal/auth/codex/openai_auth.go + pkce.go,
đối chiếu từng dòng https://github.com/router-for-me/CLIProxyAPI.
"""
from config.env_loader import env_str, apply_env_overrides


# Có bật uỷ quyền Codex OAuth không (False = bỏ qua, không ảnh hưởng kết quả đăng ký)
ENABLE_CODEX: bool = False

# Client ID Codex OAuth (cố định, từ CLIProxyAPI openai_auth.go:27 ClientID)
CODEX_CLIENT_ID: str = "app_EMoamEEZ73f0CkXaXp7hrann"

# Endpoint uỷ quyền (openai_auth.go:25 AuthURL)
CODEX_AUTH_URL: str = "https://auth.openai.com/oauth/authorize"

# Endpoint đổi token (openai_auth.go:26 TokenURL)
CODEX_TOKEN_URL: str = "https://auth.openai.com/oauth/token"

# Địa chỉ callback (openai_auth.go:28 RedirectURI)
# Lưu ý: local không thật sự mở server này, chỉ chặn redirect và lấy code từ Location.
CODEX_REDIRECT_URI: str = "http://localhost:1455/auth/callback"

# OAuth scopes (scope trong openai_auth.go:75 GenerateAuthURL)
CODEX_SCOPE: str = "openid email profile offline_access"

# Tên thư mục xuất (chỉ tên, lúc chạy nối vào gốc project; cùng kiểu OUTLOOK_ACCOUNTS_FILE)
CODEX_OUTPUT_DIRNAME: str = "codex_accounts"

# Timeout request (giây)
CODEX_REQUEST_TIMEOUT: int = 30


# ============================================================
# Cách uỷ quyền Codex (đổi 2026-06-15)
#
# Cách cũ "tái dùng session đã đăng nhập lúc đăng ký" kẹt /choose-an-account;
# cách mới dùng session sạch đăng nhập từ đầu, đi đường kiểm soát rủi ro chuẩn OpenAI
# (OTP email → xác minh SMS → chọn workspace → lấy code),
# xác minh điện thoại nhờ nền tảng nhận OTP GrizzlySMS tự nhận mã.
# ============================================================

# Sau đăng ký thành công có tự chạy uỷ quyền Codex không (True=tự động, False=bỏ qua)
ENABLE_CODEX_AUTO: bool = False

# Driver uỷ quyền Codex OAuth:
#   "protocol" = uỷ quyền giao thức curl_cffi gốc
#   "roxy"     = RoxyBrowser fingerprint làm trang uỷ quyền/xác minh điện thoại/bắt callback
#   "cloak"       = CloakBrowser làm trang uỷ quyền/xác minh điện thoại/bắt callback
#   "browser_use" = Browser Use Cloud làm trang uỷ quyền/xác minh điện thoại/bắt callback
#   "same_as_registration" = theo REGISTRATION_DRIVER
CODEX_OAUTH_DRIVER: str = "roxy"




# ============================================================
# CPA management API (URL uỷ quyền Codex do CPA tạo, local chỉ chạy đăng nhập và nộp callback)
# ============================================================

# Nguồn URL uỷ quyền:
#   "cpa"   = tạo qua CPA management API /v0/management/codex-auth-url (nên dùng)
#   "sub2"  = tạo qua API quản trị sub2, và tải callback lên sub2
#   "local" = logic PKCE local giữ trong module này (tương thích cách cũ)
CODEX_AUTH_URL_SOURCE: str = "cpa"

# Trang hoặc địa chỉ dịch vụ quản trị CPA, ví dụ http://localhost:8317/admin/oauth
# Request thực tế lấy origin, rồi gọi:
#   GET  /v0/management/codex-auth-url
#   POST /v0/management/oauth-callback
CPA_MANAGEMENT_URL: str = "http://127.0.0.1:8317/management.html"#/oauth"

# Khoá quản trị CPA, đồng thời làm Authorization: Bearer và X-Management-Key
CPA_MANAGEMENT_KEY: str = env_str("CPA_MANAGEMENT_KEY", "")

# Timeout request CPA management API (giây)
CPA_REQUEST_TIMEOUT: int = 30

# Số lần thử / khoảng cơ bản khi nộp OAuth callback cho CPA.
# Gặp 409 Timeout waiting for OAuth callback, timeout mạng hoặc 5xx thì thử lại cùng callback URL.
CPA_CALLBACK_SUBMIT_RETRIES: int = 5
CPA_CALLBACK_SUBMIT_RETRY_DELAY: int = 6

# Khi CPA không trả auth json đầy đủ, có vẫn ghi một credential đã nộp callback trong codex_accounts/ local không
CPA_SAVE_CALLBACK_RECEIPT: bool = True

# ============================================================
# Nền tảng nhận OTP SMS (xác minh SMS)
# SMS_PROVIDER:
#   "grizzly" = GrizzlySMS, tài liệu https://api.grizzlysms.com
#   "smsbower"= SMSBower, tài liệu https://smsbower.app/cn/api?page=client
#   "l"       = dịch vụ lấy số L local, xem L_API.md
#   "h"       = dịch vụ lấy số H local, xem H_API.md
# ============================================================

SMS_PROVIDER: str = "l"

# Gốc API nhận OTP SMS (GET handler)
SMS_API_BASE: str = "https://api.grizzlysms.com/stubs/handler_api.php"

# Khoá API nhận OTP SMS (lấy ở admin GrizzlySMS → Cài đặt)
# Để trống thì bước xác minh điện thoại của uỷ quyền Codex thất bại; không cần uỷ quyền Codex tự động thì ENABLE_CODEX_AUTO=False.
SMS_API_KEY: str = env_str("SMS_API_KEY", "")

# Cấu hình API SMSBower riêng (dùng khi SMS_PROVIDER="smsbower")
SMSBOWER_API_BASE: str = "https://smsbower.page/stubs/handler_api.php"
SMSBOWER_API_KEY: str = env_str("SMSBOWER_API_KEY", "")
SMSBOWER_USE_V2: bool = False
SMSBOWER_PROVIDER_IDS: str = ""
SMSBOWER_EXCEPT_PROVIDER_IDS: str = ""
SMSBOWER_PHONE_EXCEPTION: str = ""
SMSBOWER_MIN_PRICE: str = ""

# Mã dịch vụ: OpenAI (ChatGPT) = "dr"
SMS_SERVICE: str = "dr"

# Mã quốc gia: Bồ Đào Nha = "117" / Mỹ = "187"
SMS_COUNTRY: str = "10"

# Giá cao nhất chấp nhận cho một số (trống=không giới hạn). Truyền thẳng maxPrice của getNumber.
SMS_MAX_PRICE: str = ""

# Số lần đổi số tối đa khi một số không nhận SMS hoặc bị từ chối
SMS_MAX_RETRIES: int = 10

# Số giây tối đa một số chờ SMS (quá hạn thì huỷ số đó và đổi số)
SMS_CODE_WAIT: int = 120

# Khoảng poll nền tảng nhận OTP để xem SMS (giây)
SMS_POLL_INTERVAL: int = 5

# Timeout request HTTP nền tảng nhận OTP (giây)
SMS_REQUEST_TIMEOUT: int = 30


# ============================================================
# Dịch vụ lấy số H (dùng khi SMS_PROVIDER="h")
# ============================================================

# Gốc H API, ví dụ admin local: http://localhost:8788
H_API_BASE: str = "http://localhost:8788"

# Mã uỷ quyền admin H, tương ứng Authorization: Bearer <ADMIN_AUTH_CODE> trong H_API.md
H_ADMIN_AUTH_CODE: str = env_str("H_ADMIN_AUTH_CODE", "")

# Nếu số H trả về không có mã quốc gia, thêm tiền tố ở đây; để trống thì dùng thẳng item.phone.
H_PHONE_PREFIX: str = ""

# Cách lấy số H:
#   "reusable" = ưu tiên tái dùng số, gọi /api/admin/h/take-reusable-phone (mặc định)
#   "new"      = mỗi lần lấy số mới, gọi /api/admin/h/take-phone
H_PHONE_ACQUIRE_MODE: str = "reusable"


# ============================================================
# Dịch vụ lấy số L (dùng khi SMS_PROVIDER="l")
# ============================================================

# Gốc L API, ví dụ admin local: http://localhost:8788
L_API_BASE: str = "http://localhost:8788"

# Mã uỷ quyền admin L, tương ứng Authorization: Bearer <ADMIN_AUTH_CODE> trong L_API.md
L_ADMIN_AUTH_CODE: str = env_str("L_ADMIN_AUTH_CODE", "")

# Nếu số L trả về không có mã quốc gia, thêm tiền tố ở đây; số local Mỹ 10 số điền "1".
# Để trống thì dùng thẳng item.phone.
L_PHONE_PREFIX: str = ""

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_CODEX_AUTO': 'bool', 'CODEX_OAUTH_DRIVER': 'str', 'CODEX_AUTH_URL_SOURCE': 'str', 'CPA_MANAGEMENT_URL': 'str', 'CPA_MANAGEMENT_KEY': 'str', 'CPA_REQUEST_TIMEOUT': 'int', 'CPA_CALLBACK_SUBMIT_RETRIES': 'int', 'CPA_CALLBACK_SUBMIT_RETRY_DELAY': 'int', 'CPA_SAVE_CALLBACK_RECEIPT': 'bool', 'SMS_PROVIDER': 'str', 'SMS_COUNTRY': 'str', 'SMS_SERVICE': 'str', 'SMS_MAX_PRICE': 'str', 'SMS_MAX_RETRIES': 'int', 'SMS_CODE_WAIT': 'int', 'SMS_POLL_INTERVAL': 'int', 'SMS_REQUEST_TIMEOUT': 'int', 'SMS_API_KEY': 'str', 'SMSBOWER_API_BASE': 'str', 'SMSBOWER_API_KEY': 'str', 'SMSBOWER_USE_V2': 'bool', 'SMSBOWER_PROVIDER_IDS': 'str', 'SMSBOWER_EXCEPT_PROVIDER_IDS': 'str', 'SMSBOWER_PHONE_EXCEPTION': 'str', 'SMSBOWER_MIN_PRICE': 'str', 'H_API_BASE': 'str', 'H_ADMIN_AUTH_CODE': 'str', 'H_PHONE_PREFIX': 'str', 'H_PHONE_ACQUIRE_MODE': 'str', 'L_API_BASE': 'str', 'L_ADMIN_AUTH_CODE': 'str', 'L_PHONE_PREFIX': 'str'})
