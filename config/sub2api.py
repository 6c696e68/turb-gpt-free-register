# -*- coding: utf-8 -*-
"""Cấu hình nối sub2api."""
from config.env_loader import apply_env_overrides

# Sau khi tạo Codex Agent Token thành công, có tự đồng bộ sang sub2api không.
SUB2API_AUTO_EXPORT: bool = True

# Chế độ đồng bộ:
# api  = gọi thẳng API sub2api để tải lên
# file = chỉ nối/cập nhật sub2api.json local
# both = tải API thành công/thất bại không ảnh hưởng đồng bộ file local
SUB2API_SYNC_MODE: str = "api"

# Gốc API sub2api; tải Agent Token và Codex OAuth đều dùng địa chỉ này.
SUB2API_API_BASE: str = ""

# Tương thích cấu hình cũ: Agent Token tải thẳng lên URL đầy đủ.
SUB2API_API_URL: str = ""

# API Key management sub2api; trống thì không gửi header xác thực.
SUB2API_API_KEY: str = ""

# Tên cấu hình cũ: SUB2API_API_TOKEN.
SUB2API_API_TOKEN: str = ""

# Header xác thực management sub2api: x-api-key: <your-admin-api-key>.
SUB2API_API_AUTH_HEADER: str = "x-api-key"

# x-api-key không cần tiền tố Bearer.
SUB2API_API_AUTH_PREFIX: str = ""

# Timeout tải lên (giây).
SUB2API_API_TIMEOUT: int = 20

# Đường dẫn xuất file cấu hình sub2api local; path tương đối tính từ gốc project.
SUB2API_OUTPUT_PATH: str = "sub2api.json"

# Khoá proxy tuỳ chọn; ghi account.proxy_key, và khởi tạo proxies[0].proxy_key khi proxies trong sub2api.json trống.
SUB2API_PROXY_KEY: str = ""


# ============================================================
# Nối uỷ quyền Codex OAuth với sub2
# Dùng khi config.codex.CODEX_AUTH_URL_SOURCE="sub2":
#   1) lấy link uỷ quyền Codex từ sub2
#   2) sau khi luồng trình duyệt/giao thức có localhost callback thì gửi lại sub2
# ============================================================

# Tương thích cấu hình cũ: gốc API quản trị Codex sub2; trống thì dùng SUB2API_API_BASE.
SUB2_CODEX_API_BASE: str = ""

# Path API lấy link uỷ quyền Codex.
# API sub2api hiện tại: POST /api/v1/admin/openai/generate-auth-url
SUB2_CODEX_AUTH_URL_PATH: str = "/api/v1/admin/openai/generate-auth-url"

# Path API tải/nộp OAuth callback và tạo tài khoản.
# API tạo tài khoản sub2api hiện tại: POST /api/v1/admin/openai/create-from-oauth
SUB2_CODEX_CALLBACK_PATH: str = "/api/v1/admin/openai/create-from-oauth"

# Tương thích cấu hình cũ: token xác thực API Codex sub2; trống thì dùng lại SUB2API_API_KEY / SUB2API_API_TOKEN.
SUB2_CODEX_API_TOKEN: str = ""

# Tên/tiền tố header xác thực; trống thì dùng lại SUB2API_API_AUTH_HEADER / SUB2API_API_AUTH_PREFIX.
SUB2_CODEX_AUTH_HEADER: str = ""
SUB2_CODEX_AUTH_PREFIX: str = ""

# Payload tải callback:
# create_from_oauth => sub2api tạo tài khoản gốc: {"session_id","code","state","redirect_uri","name","concurrency","priority"}
# exchange_code     => chỉ đổi token, không tạo tài khoản (tương thích logic cũ)
SUB2_CODEX_CALLBACK_PAYLOAD_MODE: str = "create_from_oauth"

apply_env_overrides(globals(), {
    'SUB2API_AUTO_EXPORT': 'bool',
    'SUB2API_SYNC_MODE': 'str',
    'SUB2API_API_BASE': 'str',
    'SUB2API_API_URL': 'str',
    'SUB2API_API_KEY': 'str',
    'SUB2API_API_TOKEN': 'str',
    'SUB2API_API_AUTH_HEADER': 'str',
    'SUB2API_API_AUTH_PREFIX': 'str',
    'SUB2API_API_TIMEOUT': 'int',
    'SUB2API_OUTPUT_PATH': 'str',
    'SUB2API_PROXY_KEY': 'str',
    'SUB2_CODEX_API_BASE': 'str',
    'SUB2_CODEX_AUTH_URL_PATH': 'str',
    'SUB2_CODEX_CALLBACK_PATH': 'str',
    'SUB2_CODEX_API_TOKEN': 'str',
    'SUB2_CODEX_AUTH_HEADER': 'str',
    'SUB2_CODEX_AUTH_PREFIX': 'str',
    'SUB2_CODEX_CALLBACK_PAYLOAD_MODE': 'str',
})
