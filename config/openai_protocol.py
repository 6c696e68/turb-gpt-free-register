# -*- coding: utf-8 -*-
"""
Tham số cố định giao thức OAuth OpenAI / ChatGPT

Từ bắt gói: client_id của OpenAI là giá trị cố định.
SENTINEL_SV là phiên bản sdk.js, đổi theo bản OpenAI cập nhật.
Khi cập nhật, xem bản hiện tại tại https://sentinel.openai.com/sentinel/<version>/sdk.js.
"""
from config.env_loader import apply_env_overrides

# OAuth client ID (cố định)
OPENAI_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"

# OAuth scopes
OPENAI_SCOPE = (
    "openid email profile offline_access "
    "model.request model.read "
    "organization.read organization.write"
)

# OAuth audience
OPENAI_AUDIENCE = "https://api.openai.com/v1"

# Callback OAuth (phía chatgpt.com)
OPENAI_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"

# Phiên bản Sentinel SDK (ảnh hưởng URL iframe sentinel và header referer)
SENTINEL_SV = "20260810913b"

# Định danh build trang ChatGPT (dùng giả lập Sentinel p[6] / documentElement data-build)
OPENAI_BUILD_ID = "prod-d4e40d432de549a66bf9feb61d43c262b258386f"

# Header báo cáo CES / API frontend ChatGPT, từ bắt gói 2026-07-19.
OAI_CLIENT_BUILD_NUMBER = "10762726"
OAI_CLIENT_VERSION = OPENAI_BUILD_ID

# Phiên bản Statsig / Analytics SDK, dùng khi giao thức thuần bổ sung chuỗi cùng dạng frontend.
STATSIG_CLIENT_KEY = "client-nb0qtYlZuy2tCMN5s5ncnuIBCJncjRViT0IzFm7GqST"
STATSIG_SDK_VERSION = "3.33.1"
STATSIG_SDK_TYPE = "javascript-client"
AB_CLIENT_KEY = "client-tN5GMyzpIPKXd3KNv7ANIfiqjRSvNNTTWbZdbdabF58"
AB_SDK_VERSION = "3.32.7"

# Mẫu Roxy thành công 2026-09-14: email-otp/validate mang cả Sentinel và SO.
SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE = True

# Có bổ sung chuỗi warmup bootstrap màn đầu ChatGPT Web trong HAR không.
CHATGPT_ANON_BOOTSTRAP_ENABLED = True
CHATGPT_AUTH_BOOTSTRAP_ENABLED = True
# True thì warmup thất bại cắt luồng chính; mặc định False, chỉ ghi log rồi tiếp tục.
CHATGPT_BOOTSTRAP_STRICT = False

# Cấu hình thử lại khi đăng ký giao thức gặp lỗi mạng tạm: kết nối proxy, TLS, timeout, reset.
# Tổng số lần gồm request đầu; khoảng backoff lần lượt delay, delay*2, delay*4…
OPENAI_PROXY_RETRY_MAX_ATTEMPTS = 3
OPENAI_PROXY_RETRY_DELAY = 1.0
# Preflight trang đăng nhập dùng timeout ngắn riêng. Cổng proxy kết nối được không có nghĩa TLS upstream sống,
# tránh node chết chiếm worker đăng ký theo timeout toàn cục 30 giây.
OPENAI_PREFLIGHT_TIMEOUT = 12.0


apply_env_overrides(globals(), {
    "OPENAI_PROXY_RETRY_MAX_ATTEMPTS": "int",
    "OPENAI_PROXY_RETRY_DELAY": "float",
    "OPENAI_PREFLIGHT_TIMEOUT": "float",
})
